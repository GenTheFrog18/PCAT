from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from pathlib import Path

from .errors import InputFileError, MissingDependencyError, ReportWriteError


ARCHIVE_SUFFIXES = {
    ".zip",
    ".7z",
    ".rar",
    ".tar",
    ".tgz",
    ".tbz",
    ".tbz2",
    ".txz",
    ".tar.gz",
    ".tar.bz2",
    ".tar.xz",
}
CAPTURE_SUFFIXES = {".pcap", ".pcapng", ".cap", ".pcap.gz"}


def validate_input(path: str | Path) -> Path:
    p = Path(path)
    if not p.is_file():
        raise InputFileError(f"Input file not found: {p}")
    return p


def classify_input_file(path: Path) -> str:
    suffix = normalized_suffix(path)
    try:
        with path.open("rb") as handle:
            header = handle.read(512)
    except OSError:
        return "unknown"
    if looks_like_html(header):
        return "html"
    if header.startswith(b"PK\x03\x04") or header.startswith(b"PK\x05\x06") or header.startswith(b"PK\x07\x08"):
        return "archive"
    if header.startswith(b"7z\xbc\xaf\x27\x1c") or header.startswith(b"Rar!\x1a\x07"):
        return "archive"
    if len(header) >= 262 and header[257:262] == b"ustar":
        return "archive"
    if header.startswith(b"\x1f\x8b"):
        return "gzip"
    if header.startswith(
        (
            b"\xd4\xc3\xb2\xa1",
            b"\xa1\xb2\xc3\xd4",
            b"\x4d\x3c\xb2\xa1",
            b"\xa1\xb2\x3c\x4d",
            b"\x0a\x0d\x0d\x0a",
        )
    ):
        return "capture"
    if suffix in ARCHIVE_SUFFIXES:
        return "archive"
    if suffix in {".gz", ".pcap.gz"}:
        return "gzip"
    if suffix in CAPTURE_SUFFIXES:
        return "capture"
    return "unknown"


def input_parse_guidance(path: Path, tshark_error: str) -> str:
    kind = classify_input_file(path)
    base = tshark_error.strip() or "tshark failed to parse the input file."
    if kind == "archive":
        return (
            f"{base}\n"
            "This looks like an archive, not a capture file. Extract the archive first, then run PCAT on the contained capture. "
            "PCAT does not recursively unpack archives in V2.1."
        )
    if kind == "html":
        return (
            f"{base}\n"
            "This looks like an HTML page or failed download placeholder, not a capture file. "
            "Download the raw .pcap/.pcapng/.cap file and retry."
        )
    if kind == "gzip":
        return (
            f"{base}\n"
            "This looks gzip-compressed. If it is a .pcap.gz and your tshark build cannot read it directly, "
            "decompress it first, then run PCAT on the decompressed capture."
        )
    return (
        f"{base}\n"
        "PCAT accepts files that tshark/Wireshark can parse, including .pcap, .pcapng, .cap, .pcap.gz, and capture files with unusual extensions. "
        "Open the file with tshark -r or Wireshark to verify it is a valid capture."
    )


def normalized_suffix(path: Path) -> str:
    suffixes = [item.lower() for item in path.suffixes]
    if len(suffixes) >= 2:
        combined = "".join(suffixes[-2:])
        if combined in ARCHIVE_SUFFIXES or combined in CAPTURE_SUFFIXES:
            return combined
    return suffixes[-1] if suffixes else ""


def looks_like_html(data: bytes) -> bool:
    text = data.lstrip().lower()
    return text.startswith((b"<!doctype html", b"<html", b"<head", b"<body")) or b"<html" in text[:200]


def require_tshark() -> str:
    tshark = shutil.which("tshark")
    if not tshark:
        raise MissingDependencyError(
            "tshark is required for PCAT. Install Wireshark/tshark first "
            "(for example: sudo apt install tshark)."
        )
    return tshark


def tool_version(command: str) -> str:
    path = shutil.which(command)
    if not path:
        return "not found"
    try:
        version_args = ["i"] if command in {"7z", "7za", "7zr"} else ["--version"]
        result = subprocess.run(
            [path, *version_args],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
            timeout=5,
        )
        for line in result.stdout.splitlines():
            if line.strip():
                return line.strip()
        return "available"
    except Exception:
        return "available"


def default_output_dir(input_path: Path) -> Path:
    return Path(f"{input_path.name}-pcat") / input_path.stem


def prepare_output_dir(path: Path, force: bool) -> Path:
    if path.exists() and not path.is_dir():
        raise ReportWriteError(f"Output path exists and is not a folder: {path}")
    if path.exists() and not force:
        raise ReportWriteError(f"Output folder already exists: {path}. Use --force to overwrite PCAT-generated files.")
    path.mkdir(parents=True, exist_ok=True)
    return path


def format_shell_command(parts: list[object] | tuple[object, ...]) -> str:
    return " ".join(shlex.quote(str(part)) for part in parts if part is not None and str(part) != "")


def is_tty() -> bool:
    try:
        return os.isatty(1)
    except Exception:
        return False
