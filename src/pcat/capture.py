from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
from pathlib import Path

from .models import CaptureRecord, ReportMessage, ToolRun
from .utils import tool_version


def build_capture_record(path: Path) -> tuple[CaptureRecord, list[ToolRun], list[ReportMessage]]:
    warnings: list[ReportMessage] = []
    tools: list[ToolRun] = []
    record = CaptureRecord(
        path=str(path),
        name=path.name,
        stem=path.stem,
        size_bytes=path.stat().st_size,
        sha256=sha256_file(path),
    )
    capinfos = shutil.which("capinfos")
    if capinfos:
        result = subprocess.run([capinfos, str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        tools.append(ToolRun("capinfos", "ok" if result.returncode == 0 else "failed", tool_version("capinfos"), command=f"capinfos {path}", error=result.stderr.strip()))
        if result.returncode == 0:
            apply_capinfos(record, result.stdout)
        else:
            warnings.append(ReportMessage("capture_metadata", result.stderr.strip() or "capinfos failed", "warning"))
    else:
        tools.append(ToolRun("capinfos", "missing"))
        warnings.append(ReportMessage("capture_metadata", "capinfos not found; capture metadata is limited.", "warning"))
    tshark = shutil.which("tshark")
    if tshark:
        result = subprocess.run(
            [tshark, "-r", str(path), "-q", "-z", "io,phs"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        tools.append(ToolRun("tshark-protocol-hierarchy", "ok" if result.returncode == 0 else "failed", tool_version("tshark"), command=f"tshark -r {path} -q -z io,phs", error=result.stderr.strip()))
        if result.returncode == 0:
            record.protocol_hierarchy = parse_protocol_hierarchy(result.stdout)
        else:
            warnings.append(ReportMessage("protocol_hierarchy", result.stderr.strip() or "tshark protocol hierarchy failed", "warning"))
    else:
        tools.append(ToolRun("tshark", "missing"))
        warnings.append(ReportMessage("protocol_hierarchy", "tshark not found; protocol hierarchy unavailable.", "warning"))
    return record, tools, warnings


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def apply_capinfos(record: CaptureRecord, text: str) -> None:
    for line in text.splitlines():
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if key == "file type":
            record.file_type = value
        elif key == "file encapsulation":
            record.encapsulation = value
        elif key == "number of packets":
            record.packet_count = parse_int(value)
        elif key in {"capture duration", "duration"}:
            record.duration = parse_duration(value)
        elif key in {"earliest packet time", "first packet time"}:
            record.start_time = value
        elif key in {"latest packet time", "last packet time"}:
            record.end_time = value
        elif key == "strict time order":
            record.strict_time_order = value
        elif key == "capture application":
            record.capture_application = value
        elif key == "sha256" and value:
            record.sha256 = value.split()[0]
        elif line.strip().startswith("Interface #"):
            record.interfaces.append(line.strip())


def parse_protocol_hierarchy(text: str) -> dict[str, int]:
    protocols: dict[str, int] = {}
    pattern = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s+frames:(\d+)")
    for line in text.splitlines():
        match = pattern.search(line)
        if match:
            protocols[match.group(1).upper()] = int(match.group(2))
    return dict(sorted(protocols.items(), key=lambda item: item[1], reverse=True))


def parse_int(value: str) -> int:
    digits = re.sub(r"[^0-9]", "", value)
    return int(digits) if digits else 0


def parse_duration(value: str) -> float:
    match = re.search(r"([0-9]+(?:\.[0-9]+)?)", value)
    return float(match.group(1)) if match else 0.0
