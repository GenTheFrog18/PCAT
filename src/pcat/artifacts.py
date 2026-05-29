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


@dataclass(frozen=True)
class CarveResult:
    blob: bytes
    complete: bool | None
    truncated: bool | None


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
    Signature("pe", ".exe", b"MZ", max_size=50 * 1024 * 1024),
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
                source_scope=source_scope_for(source),
                declared_type=sig.name,
                filename=f"{sig.name}_{counters[sig.name]:03d}{sig.ext}",
                tags=["magic-byte"],
            )
            validate_artifact_record(record, data, sig)
            score_artifact(record)
            findings.append(record)
            start = offset + 1
    return dedupe_artifacts(findings)


def detect_artifacts(raw_path: Path, payloads: list[tuple[str, bytes]] | None = None, include_raw: bool = True) -> list[ArtifactRecord]:
    results: list[ArtifactRecord] = []
    if include_raw:
        results.extend(
            artifact
            for artifact in find_magic(raw_path.read_bytes(), "raw-file")
            if not is_input_container_artifact(raw_path, artifact)
        )
    for source, payload in payloads or []:
        results.extend(find_magic(payload, source))
    return dedupe_artifacts(results)


def is_input_container_artifact(raw_path: Path, artifact: ArtifactRecord) -> bool:
    return (
        artifact.source == "raw-file"
        and artifact.kind == "gzip"
        and artifact.offset == 0
        and raw_path.name.lower().endswith(".pcap.gz")
    )


def signature_for_kind(kind: str) -> Signature | None:
    for sig in SIGNATURES:
        if sig.name == kind:
            return sig
    return None


def carve_blob(data: bytes, offset: int, sig: Signature) -> bytes:
    return carve_blob_with_metadata(data, offset, sig).blob


def carve_blob_with_metadata(data: bytes, offset: int, sig: Signature) -> CarveResult:
    limit = min(len(data), offset + sig.max_size)
    if sig.name == "zip":
        end = zip_end_offset(data, offset, sig.max_size)
        if end:
            return CarveResult(data[offset:end], True, False)
        return CarveResult(data[offset:limit], False, True)
    if sig.name == "pe":
        end = pe_end_offset(data, offset, sig.max_size)
        if end:
            return CarveResult(data[offset:end], True, False)
        return CarveResult(data[offset:limit], False, True)
    if sig.eof:
        end = data.find(sig.eof, offset + len(sig.magic))
        if end != -1:
            final = min(end + len(sig.eof), limit)
            return CarveResult(data[offset:final], True, False)
        return CarveResult(data[offset:limit], False, True)
    return CarveResult(data[offset:limit], None, None)


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


def pe_end_offset(data: bytes, offset: int, max_size: int) -> int | None:
    limit = min(len(data), offset + max_size)
    if offset + 0x40 > limit or data[offset : offset + 2] != b"MZ":
        return None
    try:
        pe_offset = offset + struct.unpack_from("<I", data, offset + 0x3C)[0]
        if pe_offset < offset + 0x40 or pe_offset + 24 > limit:
            return None
        if data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
            return None
        section_count = struct.unpack_from("<H", data, pe_offset + 6)[0]
        optional_header_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
        section_table = pe_offset + 24 + optional_header_size
        section_table_end = section_table + section_count * 40
        if section_count <= 0 or section_count > 96 or section_table_end > limit:
            return None
        end = section_table_end
        for index in range(section_count):
            entry = section_table + index * 40
            raw_size = struct.unpack_from("<I", data, entry + 16)[0]
            raw_ptr = struct.unpack_from("<I", data, entry + 20)[0]
            if raw_size and raw_ptr:
                end = max(end, offset + raw_ptr + raw_size)
        if end <= offset or end > limit:
            return None
        return end
    except struct.error:
        return None


def safe_source(source: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", source)


def source_scope_for(source: str) -> str:
    return "raw_capture" if source == "raw-file" else "packet_payload"


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
    ranked = sorted(artifacts, key=lambda item: item.score, reverse=True)
    for artifact in ranked:
        if artifact_is_extractable(artifact):
            continue
        mark_unextractable_artifact(artifact)
    selected = [item for item in ranked if artifact_is_extractable(item)]
    if limit is not None:
        selected = selected[: max(0, limit)]
    for artifact in selected:
        sig = signature_for_kind(artifact.kind)
        if not sig:
            continue
        source_data = raw_data if artifact.source == "raw-file" else payload_map.get(artifact.source)
        if not source_data:
            artifact.extraction_status = "skipped_missing_source"
            artifact.skip_reason = "missing_source"
            continue
        validate_artifact_record(artifact, source_data, sig)
        if artifact.validation == "invalid":
            artifact.extraction_status = "skipped_invalid"
            artifact.skip_reason = "validation_failed"
            continue
        if artifact.validation == "truncated" or artifact.complete_file_valid is False:
            artifact.extraction_status = "skipped_incomplete"
            artifact.skip_reason = "incomplete_or_truncated"
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


def artifact_is_extractable(artifact: ArtifactRecord) -> bool:
    return (
        artifact.certainty != "rejected"
        and artifact.validation != "truncated"
        and artifact.complete_file_valid is not False
    )


def mark_unextractable_artifact(artifact: ArtifactRecord) -> None:
    if artifact.certainty == "rejected" or artifact.validation == "invalid":
        artifact.extraction_status = "skipped_invalid"
        artifact.skip_reason = "validation_failed"
    elif artifact.validation == "truncated" or artifact.complete_file_valid is False:
        artifact.extraction_status = "skipped_incomplete"
        artifact.skip_reason = "incomplete_or_truncated"


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
        update_certainty(artifact)
        return artifact
    result = carve_blob_with_metadata(data, artifact.offset, sig)
    artifact.magic_header_valid = data[artifact.offset : artifact.offset + len(sig.magic)] == sig.magic
    artifact.source_scope = artifact.source_scope or source_scope_for(artifact.source)
    artifact.truncated = result.truncated
    if result.complete is not None:
        artifact.complete_file_valid = result.complete
    return validate_blob(artifact, result.blob)


def validate_blob(artifact: ArtifactRecord, blob: bytes) -> ArtifactRecord:
    tags = set(artifact.tags)
    state = "signature_only"
    artifact.magic_header_valid = artifact.magic_header_valid or blob_starts_with_magic(artifact.kind, blob)
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
                artifact.structure_valid = True
                artifact.complete_file_valid = True
                artifact.truncated = False
        elif artifact.kind == "png":
            state = complete_or_truncated_state(blob.startswith(b"\x89PNG\r\n\x1a\n"), b"IEND\xaeB`\x82" in blob)
        elif artifact.kind == "jpg":
            state = complete_or_truncated_state(blob.startswith(b"\xff\xd8\xff"), blob.rstrip().endswith(b"\xff\xd9"))
        elif artifact.kind == "gif":
            state = complete_or_truncated_state(blob.startswith((b"GIF89a", b"GIF87a")), b"\x3b" in blob[6:])
        elif artifact.kind == "pdf":
            state = complete_or_truncated_state(blob.startswith(b"%PDF"), b"%%EOF" in blob)
        elif artifact.kind == "gzip":
            state = validate_gzip_blob(blob)
        elif artifact.kind == "bmp":
            state = validate_bmp_blob(blob)
        elif artifact.kind == "sqlite":
            state = "signature_only" if blob.startswith(b"SQLite format 3\x00") else "invalid"
            artifact.structure_valid = blob.startswith(b"SQLite format 3\x00")
            artifact.complete_file_valid = None if artifact.structure_valid else False
        elif artifact.kind == "elf":
            state = "signature_only" if len(blob) >= 16 and blob.startswith(b"\x7fELF") else "invalid"
            artifact.structure_valid = state == "signature_only"
            artifact.complete_file_valid = None if artifact.structure_valid else False
        elif artifact.kind == "pe":
            state = validate_pe_blob(blob)
        elif artifact.kind in {"rar", "7z"}:
            state = "signature_only"
            artifact.structure_valid = None
            artifact.complete_file_valid = None
    except Exception:
        state = "truncated" if artifact.truncated else "invalid"
    apply_validation_state(artifact, state)
    artifact.validation = state
    update_certainty(artifact)
    if state not in tags:
        tags.add(state)
    if artifact.truncated and "truncated" not in tags:
        tags.add("truncated")
    artifact.tags = sorted(tags)
    return artifact


def blob_starts_with_magic(kind: str, blob: bytes) -> bool:
    sig = signature_for_kind(kind)
    return bool(sig and blob.startswith(sig.magic))


def complete_or_truncated_state(has_header: bool, complete: bool) -> str:
    if not has_header:
        return "invalid"
    return "validated" if complete else "truncated"


def validate_gzip_blob(blob: bytes) -> str:
    if len(blob) < 10 or not blob.startswith(b"\x1f\x8b") or blob[2] != 8:
        return "invalid"
    try:
        with gzip.GzipFile(fileobj=BytesIO(blob)) as handle:
            handle.read()
        return "validated"
    except Exception:
        return "truncated"


def validate_bmp_blob(blob: bytes) -> str:
    if len(blob) < 54 or not blob.startswith(b"BM"):
        return "invalid"
    try:
        size = struct.unpack_from("<I", blob, 2)[0]
        pixel_offset = struct.unpack_from("<I", blob, 10)[0]
    except struct.error:
        return "invalid"
    if not 54 <= pixel_offset <= size:
        return "invalid"
    if size > len(blob):
        return "truncated"
    return "validated"


def validate_pe_blob(blob: bytes) -> str:
    if len(blob) < 0x40 or not blob.startswith(b"MZ"):
        return "invalid"
    end = pe_end_offset(blob, 0, len(blob))
    if not end:
        try:
            pe_offset = struct.unpack_from("<I", blob, 0x3C)[0]
        except struct.error:
            return "invalid"
        if pe_offset + 4 > len(blob):
            return "truncated"
        return "invalid"
    return "validated" if end <= len(blob) else "truncated"


def apply_validation_state(artifact: ArtifactRecord, state: str) -> None:
    if state == "validated":
        artifact.structure_valid = True
        artifact.complete_file_valid = True
        artifact.truncated = False
    elif state == "invalid":
        artifact.structure_valid = False
        artifact.complete_file_valid = False
        artifact.truncated = False if artifact.truncated is None else artifact.truncated
    elif state == "truncated":
        artifact.structure_valid = True if artifact.magic_header_valid else None
        artifact.complete_file_valid = False
        artifact.truncated = True
    elif state == "signature_only":
        artifact.structure_valid = None if artifact.structure_valid is None else artifact.structure_valid
        artifact.complete_file_valid = None if artifact.complete_file_valid is None else artifact.complete_file_valid


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
    update_certainty(artifact)
    score = 0
    reasons: list[str] = []
    high_value = {"zip", "pdf", "elf", "pe", "sqlite", "rar", "7z"}
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
    source_scope = artifact.source_scope or source_scope_for(artifact.source)
    artifact.source_scope = source_scope
    if source_scope == "packet_payload":
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
    elif artifact.validation == "truncated":
        score -= 35
        reasons.append("incomplete or truncated artifact candidate")
    elif artifact.validation == "signature_only":
        score -= 10
        reasons.append("signature-only hit")
    if artifact.complete_file_valid is False:
        score -= 15
        reasons.append("complete file was not validated")
    if artifact.truncated:
        reasons.append("truncated source data")
    if artifact.kind == "zip":
        score += 20
        reasons.append("ZIP often contains bundled artifacts")
    if "encrypted" in artifact.tags:
        score += 10
        reasons.append("encrypted archive")
    if "office-macro" in artifact.tags or "macro-office-extension" in artifact.tags:
        score += 20
        reasons.append("macro-enabled Office artifact")
    if artifact.kind in {"elf", "pe", "sqlite"}:
        score += 20
        reasons.append("unusual in normal browsing traffic")
    if artifact.certainty == "confirmed":
        reasons.append("confirmed artifact")
    elif artifact.certainty == "candidate":
        reasons.append("artifact candidate")
    elif artifact.certainty == "rejected":
        score = min(score, 10)
        reasons.append("rejected candidate; extraction skipped")
    if artifact.certainty != "confirmed":
        cap = 60
        if source_scope == "raw_capture":
            cap = 35
        if artifact.validation == "truncated" or artifact.complete_file_valid is False:
            cap = min(cap, 45)
        if artifact.kind == "gzip":
            cap = min(cap, 35)
        score = min(score, cap)
    if artifact.kind in media_value:
        score = min(score, 45)
        reasons.append("ordinary media artifact capped below critical without stronger context")
    artifact.score = max(0, min(100, score))
    artifact.reasons = reasons
    return artifact


def certainty_from_validation(validation: str) -> str:
    if validation == "validated":
        return "confirmed"
    if validation == "invalid":
        return "rejected"
    return "candidate"


def update_certainty(artifact: ArtifactRecord) -> ArtifactRecord:
    artifact.certainty = certainty_from_validation(artifact.validation)
    return artifact


def dedupe_artifacts(artifacts: list[ArtifactRecord]) -> list[ArtifactRecord]:
    deduped: list[ArtifactRecord] = []
    by_key: dict[tuple[str, str, int], ArtifactRecord] = {}
    for artifact in sorted(artifacts, key=lambda item: (item.source, item.kind, item.offset, -item.score)):
        key = (artifact.source, artifact.kind, artifact.offset)
        existing = by_key.get(key)
        if existing:
            artifact.duplicate_of = existing.artifact_id
            continue
        by_key[key] = artifact
        deduped.append(artifact)
    return deduped
