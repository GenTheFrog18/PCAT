from __future__ import annotations

import hashlib
import gzip
import json
import mimetypes
import re
import shutil
import subprocess
import struct
import zipfile
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path

from .models import ArtifactRecord, to_plain


@dataclass(frozen=True)
class Signature:
    name: str
    ext: str
    magic: bytes
    eof: bytes | None = None
    max_size: int = 10 * 1024 * 1024


SIGNATURES = [
    Signature("png", ".png", b"\x89PNG\r\n\x1a\n", b"IEND\xaeB`\x82"),
    Signature("jpg", ".jpg", b"\xff\xd8\xff", b"\xff\xd9"),
    Signature("gif", ".gif", b"GIF89a", b"\x3b"),
    Signature("gif", ".gif", b"GIF87a", b"\x3b"),
    Signature("pdf", ".pdf", b"%PDF", b"%%EOF", max_size=20 * 1024 * 1024),
    Signature("zip", ".zip", b"PK\x03\x04", max_size=50 * 1024 * 1024),
    Signature("gzip", ".gz", b"\x1f\x8b", max_size=5 * 1024 * 1024),
    Signature("rar", ".rar", b"Rar!\x1a\x07\x00"),
    Signature("7z", ".7z", b"7z\xbc\xaf\x27\x1c"),
    Signature("elf", ".elf", b"\x7fELF"),
    Signature("bmp", ".bmp", b"BM"),
    Signature("sqlite", ".sqlite", b"SQLite format 3\x00"),
]


def find_magic(data: bytes, source: str) -> list[ArtifactRecord]:
    findings = []
    counters: dict[str, int] = {}
    for sig in SIGNATURES:
        start = 0
        while True:
            offset = data.find(sig.magic, start)
            if offset == -1:
                break
            counters[sig.name] = counters.get(sig.name, 0) + 1
            artifact_id = f"{source}:{sig.name}:{offset}"
            record = ArtifactRecord(
                artifact_id=artifact_id,
                kind=sig.name,
                source=source,
                offset=offset,
                source_type="raw" if source == "raw-file" else "packet_payload",
                declared_type=sig.name,
                filename=f"{sig.name}_{counters[sig.name]:03d}{sig.ext}",
                tags=["magic-byte"],
            )
            validate_artifact_record(record, data, sig)
            score_artifact(record)
            findings.append(record)
            start = offset + 1
    return findings


def detect_artifacts(raw_path: Path, payloads: list[tuple[str, bytes]] | None = None, include_raw: bool = True) -> list[ArtifactRecord]:
    results: list[ArtifactRecord] = []
    if include_raw:
        results.extend(find_magic(raw_path.read_bytes(), "raw-file"))
    for source, payload in payloads or []:
        results.extend(find_magic(payload, source))
    return results


def signature_for_kind(kind: str) -> Signature | None:
    for sig in SIGNATURES:
        if sig.name == kind:
            return sig
    return None


def carve_blob(data: bytes, offset: int, sig: Signature) -> bytes:
    if sig.name == "zip":
        end = zip_end_offset(data, offset, sig.max_size)
        if end:
            return data[offset:end]
        return data[offset : offset + sig.max_size]
    if sig.eof:
        end = data.find(sig.eof, offset + len(sig.magic))
        if end != -1:
            return data[offset : min(end + len(sig.eof), offset + sig.max_size)]
    return data[offset : offset + sig.max_size]


def zip_end_offset(data: bytes, offset: int, max_size: int) -> int | None:
    limit = min(len(data), offset + max_size)
    window = data[offset:limit]
    eocd_sig = b"PK\x05\x06"
    eocd = window.rfind(eocd_sig)
    if eocd == -1 or eocd + 22 > len(window):
        return None
    try:
        comment_len = struct.unpack_from("<H", window, eocd + 20)[0]
    except struct.error:
        return None
    end = eocd + 22 + comment_len
    if end > len(window):
        return None
    return offset + end


def safe_source(source: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", source)


def file_type(path: Path) -> str:
    system_file = shutil.which("file")
    if system_file:
        try:
            result = subprocess.run(
                [system_file, "-b", str(path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
                timeout=5,
            )
            if result.stdout.strip():
                return result.stdout.strip()
        except Exception:
            pass
    guessed, _ = mimetypes.guess_type(str(path))
    return guessed or "unknown"


def extract_artifacts(
    raw_path: Path,
    artifacts: list[ArtifactRecord],
    out_dir: Path,
    payload_map: dict[str, bytes] | None = None,
    limit: int | None = None,
) -> list[ArtifactRecord]:
    out_dir.mkdir(parents=True, exist_ok=True)
    payload_map = payload_map or {}
    raw_data = raw_path.read_bytes()
    counters: dict[str, int] = {}
    saved: list[ArtifactRecord] = []
    selected = sorted(artifacts, key=lambda item: item.score, reverse=True)
    if limit is not None:
        selected = selected[: max(0, limit)]
    for artifact in selected:
        sig = signature_for_kind(artifact.kind)
        if not sig:
            continue
        source_data = raw_data if artifact.source == "raw-file" else payload_map.get(artifact.source)
        if not source_data:
            continue
        validate_artifact_record(artifact, source_data, sig)
        if artifact.validation == "invalid":
            continue
        counters[artifact.kind] = counters.get(artifact.kind, 0) + 1
        blob = carve_blob(source_data, artifact.offset, sig)
        filename = f"{artifact.kind}_{counters[artifact.kind]:03d}_{safe_source(artifact.source)}_off{artifact.offset}{sig.ext}"
        output_path = out_dir / filename
        output_path.write_bytes(blob)
        artifact.path = str(output_path)
        artifact.filename = filename
        artifact.size = len(blob)
        artifact.sha256 = hashlib.sha256(blob).hexdigest()
        validate_blob(artifact, blob)
        detected_type = file_type(output_path)
        artifact.validated_type = detected_type
        if detected_type not in artifact.tags:
            artifact.tags.append(detected_type)
        artifact.extraction_status = "extracted"
        score_artifact(artifact)
        saved.append(artifact)
    return saved


def write_artifact_manifest(artifacts: list[ArtifactRecord], artifacts_dir: Path) -> Path:
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = artifacts_dir / "manifest.json"
    for artifact in artifacts:
        artifact.manifest_path = str(manifest_path)
    manifest_path.write_text(json.dumps(to_plain(artifacts), indent=2), encoding="utf-8")
    return manifest_path


def validate_artifact_record(artifact: ArtifactRecord, data: bytes, sig: Signature | None = None) -> ArtifactRecord:
    sig = sig or signature_for_kind(artifact.kind)
    if not sig:
        return artifact
    blob = carve_blob(data, artifact.offset, sig)
    return validate_blob(artifact, blob)


def validate_blob(artifact: ArtifactRecord, blob: bytes) -> ArtifactRecord:
    tags = set(artifact.tags)
    state = "signature_only"
    try:
        if artifact.kind == "zip":
            with zipfile.ZipFile(BytesIO(blob)) as zf:
                names = zf.namelist()
                artifact.members = names[:200]
                if names:
                    tags.add(f"entries:{len(names)}")
                encrypted = any(info.flag_bits & 0x1 for info in zf.infolist())
                if encrypted:
                    artifact.encrypted = True
                    tags.add("encrypted")
                lower_names = {name.lower() for name in names}
                if any(name.endswith((".xlsm", ".docm", ".pptm")) for name in lower_names):
                    tags.add("macro-office-extension")
                if any(name.endswith("vbaproject.bin") for name in lower_names):
                    tags.add("office-macro")
                state = "validated"
        elif artifact.kind == "png":
            state = "validated" if blob.startswith(b"\x89PNG\r\n\x1a\n") and b"IEND\xaeB`\x82" in blob else "invalid"
        elif artifact.kind == "jpg":
            state = "validated" if blob.startswith(b"\xff\xd8\xff") and blob.rstrip().endswith(b"\xff\xd9") else "invalid"
        elif artifact.kind == "gif":
            state = "validated" if blob.startswith((b"GIF89a", b"GIF87a")) and b"\x3b" in blob[6:] else "invalid"
        elif artifact.kind == "pdf":
            state = "validated" if blob.startswith(b"%PDF") and b"%%EOF" in blob else "invalid"
        elif artifact.kind == "gzip":
            with gzip.GzipFile(fileobj=BytesIO(blob)) as handle:
                handle.read(1)
            state = "validated"
        elif artifact.kind == "bmp":
            state = "validated" if valid_bmp(blob) else "invalid"
        elif artifact.kind == "sqlite":
            state = "validated" if blob.startswith(b"SQLite format 3\x00") else "invalid"
        elif artifact.kind == "elf":
            state = "validated" if blob.startswith(b"\x7fELF") else "invalid"
        elif artifact.kind in {"rar", "7z"}:
            state = "signature_only"
    except Exception:
        state = "invalid"
    artifact.validation = state
    if state not in tags:
        tags.add(state)
    artifact.tags = sorted(tags)
    return artifact


def valid_bmp(blob: bytes) -> bool:
    if len(blob) < 54 or not blob.startswith(b"BM"):
        return False
    try:
        size = struct.unpack_from("<I", blob, 2)[0]
        pixel_offset = struct.unpack_from("<I", blob, 10)[0]
    except struct.error:
        return False
    return 54 <= pixel_offset <= size <= len(blob)


def score_artifact(artifact: ArtifactRecord) -> ArtifactRecord:
    score = 0
    reasons: list[str] = []
    high_value = {"zip", "pdf", "elf", "sqlite", "rar", "7z"}
    media_value = {"png", "jpg", "gif"}
    noisy = {"gzip"}
    if artifact.kind in high_value:
        score += 50
        reasons.append("high-value file type")
    elif artifact.kind in media_value:
        score += 30
        reasons.append("media/image artifact")
    elif artifact.kind in noisy:
        score -= 20
        reasons.append("common/noisy signature")
    if artifact.source != "raw-file":
        score += 40
        reasons.append("found inside packet payload")
    else:
        score -= 5
        reasons.append("raw PCAP hit, possible false positive")
    if artifact.validation == "validated":
        score += 25
        reasons.append("validated artifact structure")
    elif artifact.validation == "invalid":
        score -= 55
        reasons.append("invalid or incomplete artifact structure")
    elif artifact.validation == "signature_only":
        score -= 10
        reasons.append("signature-only hit")
    if artifact.kind == "zip":
        score += 20
        reasons.append("ZIP often contains bundled artifacts")
    if "encrypted" in artifact.tags:
        score += 10
        reasons.append("encrypted archive")
    if "office-macro" in artifact.tags or "macro-office-extension" in artifact.tags:
        score += 20
        reasons.append("macro-enabled Office artifact")
    if artifact.kind in {"elf", "sqlite"}:
        score += 20
        reasons.append("unusual in normal browsing traffic")
    artifact.score = max(0, min(100, score))
    artifact.reasons = reasons
    return artifact
