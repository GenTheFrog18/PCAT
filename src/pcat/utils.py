from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from .errors import InputFileError, MissingDependencyError


SUPPORTED_EXTENSIONS = {".pcap", ".pcapng"}


def validate_input(path: str | Path) -> Path:
    p = Path(path)
    if not p.is_file():
        raise InputFileError(f"Input file not found: {p}")
    if p.suffix.lower() not in SUPPORTED_EXTENSIONS:
        raise InputFileError("Input must be a .pcap or .pcapng file.")
    return p


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
        raise InputFileError(f"Output path exists and is not a folder: {path}")
    if path.exists() and not force:
        raise InputFileError(f"Output folder already exists: {path}. Use --force to overwrite PCAT-generated files.")
    path.mkdir(parents=True, exist_ok=True)
    return path


def is_tty() -> bool:
    try:
        return os.isatty(1)
    except Exception:
        return False
