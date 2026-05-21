from __future__ import annotations

import argparse
import importlib.util
import json
import re
import shutil
import shlex
import subprocess
import sys
from pathlib import Path

from .analysis import (
    AnalyzeOptions,
    analyze,
    clue_rows,
    decoded_payload_fragments,
    email_clue_rows,
    gather_strings,
    payload_sources,
)
from .artifacts import detect_artifacts, extract_artifacts, score_artifact, write_artifact_manifest
from .evidence import build_report_evidence
from .errors import InvalidArgumentError, PCATError
from .models import to_plain
from .reports import render_terminal, write_reports
from .stringtools import (
    decode_interesting,
    detect_credentials,
    detect_flags,
    find_matches,
    raw_file_strings,
    strings_from_payload_hex,
)
from .tshark_parser import parse_packets
from .utils import default_output_dir, prepare_output_dir, tool_version, validate_input


DEFAULT_FORMATS = {"html", "json", "csv"}


class PCATFormatter(argparse.ArgumentDefaultsHelpFormatter, argparse.RawDescriptionHelpFormatter):
    pass


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    argv = normalize_help_args(argv)
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        if not hasattr(args, "func"):
            parser.print_help()
            return 2
        return args.func(args)
    except SystemExit as exc:
        return int(exc.code or 0)
    except KeyboardInterrupt:
        print("Interrupted by user.", file=sys.stderr)
        return 130
    except BrokenPipeError:
        return 0
    except PCATError as exc:
        if getattr(args, "debug", False):
            raise
        print(f"Error ({exc.exit_code}): {exc}", file=sys.stderr)
        return exc.exit_code
    except Exception as exc:
        if getattr(args, "debug", False):
            raise
        print(f"Error (1): {exc}", file=sys.stderr)
        return 1


def normalize_help_args(argv: list[str]) -> list[str]:
    """Support pcat -h analyze and pcat help analyze."""
    if len(argv) >= 2 and argv[0] in {"-h", "--help"} and not argv[1].startswith("-"):
        return [argv[1], "--help", *argv[2:]]
    if argv and argv[0] == "help":
        if len(argv) == 1:
            return ["--help"]
        return [argv[1], "--help", *argv[2:]]
    return argv


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pcat",
        description="PCAT - PCAP Assistant for Triage",
        formatter_class=PCATFormatter,
        epilog="""Examples:
  pcat analyze -i capture.pcap
  pcat analyze -i capture.pcap --ctf --extract -o pcat/demo
  pcat strings -i capture.pcap --grep flag --ignore-case
  pcat hunt -i capture.pcap

Command help:
  pcat analyze -h
  pcat -h analyze
  pcat help analyze
""",
    )
    parser.add_argument("--version", action="version", version="PCAT 0.2.0")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND", title="commands")

    add_analyze(sub)
    add_summary(sub)
    add_streams(sub)
    add_dns(sub)
    add_http(sub)
    add_evidence(sub)
    add_timeline(sub)
    add_strings(sub)
    add_search(sub)
    add_files(sub)
    add_artifacts(sub)
    add_extract(sub)
    add_suspicious(sub)
    add_hunt(sub)
    add_doctor(sub)
    return parser


def add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("file", nargs="?", metavar="PCAP", help="Input .pcap or .pcapng file. Do not use this together with -i/--input.")
    parser.add_argument("-i", "--input", dest="input_file", metavar="PCAP", help="Input .pcap or .pcapng file. Preferred explicit input style.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show concise progress details")
    parser.add_argument("--quiet", action="store_true", help="Suppress normal terminal chatter")
    parser.add_argument("--json", action="store_true", help="Print command output as JSON")
    parser.add_argument("--debug", action="store_true", help="Show Python tracebacks for debugging")


def add_mode(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-m", "--mode", choices=["triage", "ctf"], default=None, help="Analysis mode. triage is general security analysis; ctf prioritizes flags, secrets, strings, and artifacts.")
    parser.add_argument("--ctf", action="store_true", help="Shortcut for --mode ctf")
    parser.add_argument("--triage", action="store_true", help="Shortcut for --mode triage")


def add_output(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-o", "--out", metavar="DIR", help="Output folder for generated reports/artifacts")
    parser.add_argument("--force", action="store_true", help="Allow writing into an existing output folder")


def add_report_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-f", "--format", dest="formats", metavar="LIST", help="Comma-separated report formats: html,json,csv,md,txt")
    parser.add_argument("--no-terminal", action="store_true", help="Disable terminal report output")


def add_analyze(sub) -> None:
    p = sub.add_parser(
        "analyze",
        help="Run full PCAP triage analysis",
        description="Run the full PCAT pipeline: parse packets, build summaries, find suspicious evidence, rank next steps, and optionally write reports.",
        formatter_class=PCATFormatter,
        epilog="""Examples:
  pcat analyze -i capture.pcap
  pcat analyze -i capture.pcap --ctf --extract -o pcat/demo
  pcat analyze capture.pcap -m triage --top 20 --no-ml
  pcat analyze -i capture.pcap -o pcat/case1 -f html,json,csv,md,txt
""",
    )
    add_common(p)
    add_mode(p)
    add_output(p)
    add_report_flags(p)
    p.add_argument("--top", type=int, default=10, metavar="N", help="Number of top terminal results to display")
    p.add_argument("--min-risk", type=int, default=10, metavar="N", help="Minimum risk score for findings in terminal/report ranking")
    p.add_argument("--extract", action="store_true", help="Extract detected artifacts")
    p.add_argument("--extract-limit", type=int, default=50, metavar="N", help="Maximum artifacts to extract when --extract is used")
    p.add_argument("--include-raw-artifacts", action="store_true", help="Include raw PCAP byte hits when extracting artifacts. Disabled by default to reduce false positives.")
    p.add_argument("--no-ml", action="store_true", help="Disable optional ML anomaly scoring")
    p.add_argument("--ctf-flag", default="", metavar="PATTERN", help='Custom CTF flag format, for example "CTF101{<flag>}"')
    p.add_argument("--redact", action="store_true", help="Redact sensitive-looking values in previews/reports")
    p.add_argument("--no-redact", action="store_true", help="Explicitly keep sensitive-looking values unredacted")
    p.set_defaults(func=cmd_analyze)


def add_summary(sub) -> None:
    p = sub.add_parser(
        "summary",
        help="Show quick capture summary",
        description="Print a fast overview: file size, packet count, duration, protocols, top hosts, and top ports.",
        formatter_class=PCATFormatter,
        epilog="""Examples:
  pcat summary -i capture.pcap
  pcat summary capture.pcap --top 20
""",
    )
    add_common(p)
    p.add_argument("--top", type=int, default=10, metavar="N", help="Number of top summary rows to display")
    p.set_defaults(func=cmd_summary)


def add_streams(sub) -> None:
    p = sub.add_parser(
        "streams",
        help="Show ranked streams/conversations",
        description="List TCP streams/conversations with packet counts, byte counts, and interest score when stream IDs are available.",
        formatter_class=PCATFormatter,
        epilog="""Examples:
  pcat streams -i capture.pcap
  pcat streams capture.pcap --top 25
""",
    )
    add_common(p)
    p.add_argument("--top", type=int, default=10, metavar="N", help="Number of streams to display")
    p.set_defaults(func=cmd_streams)


def add_dns(sub) -> None:
    p = sub.add_parser(
        "dns",
        help="Show DNS-focused view",
        description="Print top DNS queries and DNS records parsed from the capture.",
        formatter_class=PCATFormatter,
        epilog="""Examples:
  pcat dns -i capture.pcap
  pcat dns capture.pcap --top 50
""",
    )
    add_common(p)
    p.add_argument("--top", type=int, default=20, metavar="N", help="Number of DNS rows to display")
    p.set_defaults(func=cmd_dns)


def add_http(sub) -> None:
    p = sub.add_parser(
        "http",
        help="Show HTTP-focused view",
        description="Print plaintext HTTP hosts, requests, responses, paths, status codes, content types, and stream IDs when available.",
        formatter_class=PCATFormatter,
        epilog="""Examples:
  pcat http -i capture.pcap
  pcat http capture.pcap --top 50
""",
    )
    add_common(p)
    p.add_argument("--top", type=int, default=20, metavar="N", help="Number of HTTP rows to display")
    p.set_defaults(func=cmd_http)


def add_evidence(sub) -> None:
    p = sub.add_parser(
        "evidence",
        help="Show structured evidence records",
        description="Print PCAT V2 evidence records with frame/stream anchors, confidence, previews, and handoff filters.",
        formatter_class=PCATFormatter,
        epilog="""Examples:
  pcat evidence -i capture.pcap
  pcat evidence capture.pcap --type http_request --top 50 --json
""",
    )
    add_common(p)
    p.add_argument("--type", metavar="TYPE", help="Only show evidence records of this type")
    p.add_argument("--top", type=int, default=25, metavar="N", help="Number of evidence records to display")
    p.set_defaults(func=cmd_evidence)


def add_timeline(sub) -> None:
    p = sub.add_parser(
        "timeline",
        help="Show chronological findings timeline",
        description="Print timestamped timeline events generated from findings and high-value observations.",
        formatter_class=PCATFormatter,
        epilog="""Examples:
  pcat timeline -i capture.pcap
  pcat timeline capture.pcap --top 100 --json
""",
    )
    add_common(p)
    p.add_argument("--top", type=int, default=50, metavar="N", help="Number of timeline events to display")
    p.set_defaults(func=cmd_timeline)


def add_strings(sub) -> None:
    p = sub.add_parser(
        "strings",
        help="Extract printable strings from raw bytes and packet payloads",
        description="Extract printable ASCII/UTF-8-like strings from the raw PCAP file and parsed packet payloads.",
        formatter_class=PCATFormatter,
        epilog="""Examples:
  pcat strings -i capture.pcap
  pcat strings -i capture.pcap --grep flag --ignore-case
  pcat strings -i capture.pcap --output strings.txt --no-payloads
""",
    )
    add_common(p)
    p.add_argument("--min", type=int, default=5, dest="min_len", metavar="N", help="Minimum printable string length")
    p.add_argument("--grep", metavar="PATTERN", help="Only show strings matching this regex pattern")
    p.add_argument("--ignore-case", action="store_true", help="Use case-insensitive matching with --grep")
    p.add_argument("--output", metavar="FILE", help="Write extracted strings to a text file")
    p.add_argument("--limit", "--top", dest="limit", type=int, default=200, metavar="N", help="Maximum strings to print to terminal")
    p.add_argument("--no-raw", action="store_true", help="Skip raw PCAP byte scanning")
    p.add_argument("--no-payloads", action="store_true", help="Skip parsed packet payload scanning")
    p.set_defaults(func=cmd_strings)


def add_search(sub) -> None:
    p = sub.add_parser(
        "search",
        help="Search extracted strings by keyword or regex",
        description="Search strings extracted from raw PCAP bytes and packet payloads.",
        formatter_class=PCATFormatter,
        epilog="""Examples:
  pcat search -i capture.pcap password
  pcat search -i capture.pcap "flag\\{.*\\}" --regex
  pcat search capture.pcap token --ignore-case --limit 50
""",
    )
    add_common(p)
    p.add_argument("keyword", metavar="KEYWORD", help="Keyword to search for, or regex pattern when --regex is used")
    p.add_argument("--regex", action="store_true", help="Treat KEYWORD as a regular expression")
    p.add_argument("--ignore-case", action="store_true", help="Use case-insensitive matching")
    p.add_argument("--min", type=int, default=5, dest="min_len", metavar="N", help="Minimum printable string length before searching")
    p.add_argument("--limit", "--top", dest="limit", type=int, default=100, metavar="N", help="Maximum matches to print")
    p.add_argument("--no-raw", action="store_true", help="Skip raw PCAP byte scanning")
    p.add_argument("--no-payloads", action="store_true", help="Skip parsed packet payload scanning")
    p.set_defaults(func=cmd_search)


def add_files(sub) -> None:
    p = sub.add_parser(
        "files",
        help="Detect embedded files by magic bytes",
        description="Detect common embedded file signatures such as PNG, JPG, GIF, PDF, ZIP, gzip, RAR, 7z, ELF, BMP, and SQLite.",
        formatter_class=PCATFormatter,
        epilog="""Examples:
  pcat files -i capture.pcap
  pcat files capture.pcap --no-raw
""",
    )
    add_common(p)
    p.add_argument("--no-raw", action="store_true", help="Skip raw PCAP byte scanning")
    p.add_argument("--no-payloads", action="store_true", help="Skip parsed packet payload scanning")
    p.add_argument("--limit", "--top", dest="limit", type=int, default=200, metavar="N", help="Maximum artifact rows to print")
    p.set_defaults(func=cmd_files)


def add_artifacts(sub) -> None:
    p = sub.add_parser(
        "artifacts",
        help="Show artifact manager view",
        description="List detected artifacts with validation, risk score, source, extraction status, and related metadata.",
        formatter_class=PCATFormatter,
        epilog="""Examples:
  pcat artifacts -i capture.pcap
  pcat artifacts capture.pcap --include-raw --top 100 --json
""",
    )
    add_common(p)
    p.add_argument("--include-raw", action="store_true", help="Include raw PCAP byte scanning in addition to packet payload artifacts")
    p.add_argument("--no-payloads", action="store_true", help="Skip parsed packet payload scanning")
    p.add_argument("--limit", "--top", dest="limit", type=int, default=50, metavar="N", help="Maximum artifact rows to print")
    p.set_defaults(func=cmd_artifacts)


def add_extract(sub) -> None:
    p = sub.add_parser(
        "extract",
        help="Extract/carve detected artifacts",
        description="Best-effort carving of detected artifacts into <out>/artifacts/.",
        formatter_class=PCATFormatter,
        epilog="""Examples:
  pcat extract -i capture.pcap -o pcat/demo
  pcat extract -i capture.pcap --http -o pcat/http-demo --force
""",
    )
    add_common(p)
    add_output(p)
    p.add_argument("--http", action="store_true", help="Export HTTP objects with tshark when possible")
    p.add_argument("--include-raw", action="store_true", help="Include raw PCAP byte carving. Disabled by default to reduce false-positive extraction.")
    p.add_argument("--no-raw", action="store_true", help="Legacy alias kept for scripts; raw carving is already disabled by default")
    p.add_argument("--no-payloads", action="store_true", help="Skip parsed packet payload carving")
    p.add_argument("--limit", "--top", dest="limit", type=int, default=50, metavar="N", help="Maximum artifacts to extract")
    p.set_defaults(func=cmd_extract)


def add_suspicious(sub) -> None:
    p = sub.add_parser(
        "suspicious",
        help="Rank suspicious artifact/file hits",
        description="Rank detected file signatures by investigation value so high-value artifacts can be inspected first.",
        formatter_class=PCATFormatter,
        epilog="""Examples:
  pcat suspicious -i capture.pcap
  pcat suspicious capture.pcap --type zip,pdf,png --min-risk 30
""",
    )
    add_common(p)
    p.add_argument("--no-raw", action="store_true", help="Skip raw PCAP byte scanning")
    p.add_argument("--no-payloads", action="store_true", help="Skip parsed packet payload scanning")
    p.add_argument("--type", metavar="LIST", help="Comma-separated artifact type filter, for example zip,pdf,png")
    p.add_argument("--min-risk", type=int, default=20, metavar="N", help="Minimum artifact score to display")
    p.add_argument("--limit", "--top", dest="limit", type=int, default=30, metavar="N", help="Maximum artifact rows to print")
    p.set_defaults(func=cmd_suspicious)


def add_hunt(sub) -> None:
    p = sub.add_parser(
        "hunt",
        help="CTF-oriented automatic hunt",
        description="Run a CTF-focused workflow: possible flags, credentials, decoded strings, detected files, and next steps.",
        formatter_class=PCATFormatter,
        epilog="""Examples:
  pcat hunt -i capture.pcap
  pcat hunt capture.pcap --ctf-flag "CTF101{<flag>}" --limit 50
""",
    )
    add_common(p)
    p.add_argument("--min", type=int, default=5, dest="min_len", metavar="N", help="Minimum printable string length")
    p.add_argument("--limit", "--top", dest="limit", type=int, default=30, metavar="N", help="Maximum rows to print per hunt section")
    p.add_argument("--ctf-flag", default="", metavar="PATTERN", help='Custom CTF flag format, for example "CTF101{<flag>}"')
    p.set_defaults(func=cmd_hunt)


def add_doctor(sub) -> None:
    p = sub.add_parser(
        "doctor",
        help="Check PCAT dependencies and environment",
        description="Check local tools PCAT can use, including tshark, capinfos, file, Zeek, Suricata, and optional ML support.",
        formatter_class=PCATFormatter,
        epilog="""Examples:
  pcat doctor
  pcat doctor --json
""",
    )
    p.add_argument("--json", action="store_true", help="Print command output as JSON")
    p.add_argument("--debug", action="store_true", help="Show Python tracebacks for debugging")
    p.set_defaults(func=cmd_doctor)


def resolve_input(args) -> Path:
    if args.input_file and args.file:
        raise InvalidArgumentError("Provide input either as positional file or with -i/--input, not both.")
    value = args.input_file or args.file
    if not value:
        raise InvalidArgumentError("Input file is required. Use -i capture.pcap or provide a positional file.")
    return validate_input(value)


def resolve_mode(args) -> str:
    requested = []
    if getattr(args, "mode", None):
        requested.append(args.mode)
    if getattr(args, "ctf", False):
        requested.append("ctf")
    if getattr(args, "triage", False):
        requested.append("triage")
    if len(set(requested)) > 1:
        raise InvalidArgumentError("Conflicting mode options were provided.")
    return requested[0] if requested else "triage"


def parse_formats(value: str | None) -> set[str]:
    if not value:
        return set()
    aliases = {"markdown": "md", "plaintext": "txt", "terminal": "terminal"}
    formats = set()
    for item in value.split(","):
        key = item.strip().lower()
        if not key:
            continue
        formats.add(aliases.get(key, key))
    allowed = {"html", "json", "csv", "md", "txt", "terminal"}
    unknown = formats - allowed
    if unknown:
        raise InvalidArgumentError(f"Unknown report format(s): {', '.join(sorted(unknown))}")
    return formats


def output_dir_for(args, input_path: Path, formats: set[str], extract: bool = False) -> Path | None:
    if args.out:
        return prepare_output_dir(Path(args.out), args.force)
    if formats or extract:
        return prepare_output_dir(default_output_dir(input_path), getattr(args, "force", False))
    return None


def print_json(value) -> None:
    print(json.dumps(to_plain(value), indent=2))


def cmd_analyze(args) -> int:
    path = resolve_input(args)
    mode = resolve_mode(args)
    options = AnalyzeOptions(mode=mode, top=args.top, min_risk=args.min_risk, no_ml=args.no_ml, ctf_flag=args.ctf_flag)
    formats = parse_formats(args.formats)
    file_formats = formats - {"terminal"}
    if args.out and not file_formats:
        file_formats = set(DEFAULT_FORMATS)
    output_dir = output_dir_for(args, path, file_formats, extract=args.extract)
    if args.verbose and not args.quiet and not args.json:
        print(f"Parsing and analyzing {path} in {mode} mode...")
    report = analyze(path, options)
    if args.extract and output_dir:
        artifacts_dir = output_dir / "artifacts"
        packets = parse_packets(path)
        payload_rows, payload_map = payload_sources(packets)
        found_count = len(report.artifacts)
        candidates = report.artifacts if args.include_raw_artifacts else [item for item in report.artifacts if item.source != "raw-file"]
        saved = extract_artifacts(path, candidates, artifacts_dir, payload_map, limit=args.extract_limit)
        write_artifact_manifest(saved, artifacts_dir)
        report.artifacts = saved or report.artifacts
        if saved:
            strings = gather_strings(path, payload_rows, include_raw=True)
            build_report_evidence(report, packets, strings)
        if not args.quiet and not args.json:
            print(f"Artifacts found: {found_count}")
            print(f"Artifacts selected for extraction: {min(len(candidates), args.extract_limit)}")
            print(f"Artifacts extracted: {len(saved)}")
    if output_dir and file_formats:
        written = write_reports(report, output_dir, file_formats)
        if args.verbose and not args.quiet and not args.json:
            for item in written:
                print(f"Wrote {item}")
    if args.json:
        print_json(report)
    elif not args.no_terminal and not args.quiet:
        print(render_terminal(report, top=args.top))
    return 0


def cmd_summary(args) -> int:
    report = analyze(resolve_input(args), AnalyzeOptions(no_ml=True, min_risk=0))
    if args.json:
        print_json({"schema_version": report.schema_version, "capture": report.capture, "summary": report.summary, "warnings": report.warnings})
        return 0
    print_summary(report, args.top)
    return 0


def cmd_streams(args) -> int:
    report = analyze(resolve_input(args), AnalyzeOptions(no_ml=True, min_risk=0))
    if args.json:
        print_json(report.streams[: args.top])
        return 0
    print("Streams")
    print("-" * 7)
    for stream in report.streams[: args.top]:
        print(f"tcp.stream {stream.stream_id}: {stream.src_ip}:{stream.src_port} -> {stream.dst_ip}:{stream.dst_port} packets={stream.packet_count} bytes={stream.byte_count} score={stream.interest_score}")
    return 0


def cmd_dns(args) -> int:
    report = analyze(resolve_input(args), AnalyzeOptions(no_ml=True, min_risk=0))
    if args.json:
        print_json({"top_dns": report.summary.top_dns, "records": report.dns_records[: args.top]})
        return 0
    print_counter("Top DNS Queries", report.summary.top_dns, args.top)
    print("")
    print("DNS Records")
    print("-" * 11)
    for record in report.dns_records[: args.top]:
        print(f"frame={record.frame_number} {record.src_ip} -> {record.dst_ip} query={record.query} answer={record.answer} rcode={record.rcode}")
    return 0


def cmd_http(args) -> int:
    report = analyze(resolve_input(args), AnalyzeOptions(no_ml=True, min_risk=0))
    if args.json:
        print_json({"top_http_hosts": report.summary.top_http_hosts, "records": report.http_records[: args.top]})
        return 0
    print_counter("Top HTTP Hosts", report.summary.top_http_hosts, args.top)
    print("")
    print("HTTP Records")
    print("-" * 12)
    for record in report.http_records[: args.top]:
        uri = record.full_uri or f"{record.host}{record.uri}"
        length = f" length={record.content_length}" if record.content_length else ""
        print(f"frame={record.frame_number} stream={record.stream_id} {record.method} {uri} status={record.status} type={record.content_type}{length}")
    return 0


def cmd_evidence(args) -> int:
    report = analyze(resolve_input(args), AnalyzeOptions(no_ml=True, min_risk=0))
    records = report.evidence
    if args.type:
        records = [item for item in records if item.type == args.type]
    records = records[: args.top]
    if args.json:
        print_json(records)
        return 0
    if not records:
        print("No evidence records matched the filters.")
        return 0
    print("Evidence")
    print("-" * 8)
    for item in records:
        location = []
        if item.frame_start:
            location.append(f"frame={item.frame_start}")
        if item.stream_id:
            location.append(f"stream={item.stream_id}")
        loc = f" {' '.join(location)}" if location else ""
        filters = f" filters={'; '.join(item.handoff_filters)}" if item.handoff_filters else ""
        print(f"{item.evidence_id} [{item.type}] confidence={item.confidence}{loc}{filters}")
        if item.preview:
            print(f"  {item.preview}")
    return 0


def cmd_timeline(args) -> int:
    report = analyze(resolve_input(args), AnalyzeOptions(no_ml=True, min_risk=0))
    events = report.timeline[: args.top]
    if not events:
        events = [
            {"timestamp": item.timestamp, "title": item.type, "detail": item.preview, "severity": "info"}
            for item in report.evidence
            if item.timestamp is not None
        ][: args.top]
    if args.json:
        print_json(events)
        return 0
    if not events:
        print("No timeline events were generated.")
        return 0
    print("Timeline")
    print("-" * 8)
    for event in events:
        if isinstance(event, dict):
            print(f"{event['timestamp']:.6f} [{event['severity']}] {event['title']} - {event['detail']}")
        else:
            print(f"{event.timestamp:.6f} [{event.severity}] {event.title} - {event.detail}")
    return 0


def cmd_strings(args) -> int:
    path = resolve_input(args)
    rows = load_strings_for_command(path, args.min_len, not args.no_raw, not args.no_payloads)
    if args.grep:
        rows = find_matches(rows, args.grep, regex=True, ignore_case=args.ignore_case)
    if args.output:
        output = Path(args.output)
        output.write_text("\n".join(f"[{source}] {text}" for source, text in rows) + "\n", encoding="utf-8", errors="ignore")
        if not args.quiet and not args.json:
            print(f"Strings written to {output}")
        if args.json:
            print_json({"output": str(output), "count": len(rows)})
        return 0
    if args.json:
        print_json([{"source": source, "text": text} for source, text in rows[: args.limit]])
        return 0
    for source, text in rows[: args.limit]:
        print(f"[{source}] {text}")
    if not args.quiet:
        print(f"Displayed {min(len(rows), args.limit)} of {len(rows)} strings.")
    return 0


def cmd_search(args) -> int:
    path = resolve_input(args)
    rows = load_strings_for_command(path, args.min_len, not args.no_raw, not args.no_payloads)
    matches = find_matches(rows, args.keyword, regex=args.regex, ignore_case=args.ignore_case)
    if args.json:
        print_json([{"source": source, "text": text} for source, text in matches[: args.limit]])
        return 0
    if not matches:
        print("No matches found.")
        return 0
    for source, text in matches[: args.limit]:
        print(f"[{source}] {text}")
    print(f"Displayed {min(len(matches), args.limit)} of {len(matches)} matches.")
    return 0


def cmd_files(args) -> int:
    path = resolve_input(args)
    artifacts = load_artifacts_for_command(path, not args.no_raw, not args.no_payloads)
    if args.json:
        ranked = sorted(artifacts, key=lambda a: a.score, reverse=True)
        print_json(ranked[: args.limit])
        return 0
    if not artifacts:
        print("No common embedded file signatures detected.")
        return 0
    print("Detected Files")
    print("-" * 14)
    ranked = sorted(artifacts, key=lambda a: a.score, reverse=True)
    for idx, artifact in enumerate(ranked[: args.limit], start=1):
        print(f"{idx}. type={artifact.kind} source={artifact.source} offset={artifact.offset} score={artifact.score} validation={artifact.validation} tags={','.join(artifact.tags)} reason={'; '.join(artifact.reasons)}")
    if len(ranked) > args.limit:
        print(f"... and {len(ranked) - args.limit} more. Use --top/--limit to change this.")
    return 0


def cmd_artifacts(args) -> int:
    path = resolve_input(args)
    artifacts = load_artifacts_for_command(path, args.include_raw, not args.no_payloads)
    ranked = sorted(artifacts, key=lambda a: a.score, reverse=True)
    if args.json:
        print_json(ranked[: args.limit])
        return 0
    if not ranked:
        print("No artifacts detected with the selected sources.")
        return 0
    print("Artifacts")
    print("-" * 9)
    for idx, artifact in enumerate(ranked[: args.limit], start=1):
        status = artifact.extraction_status or "not-extracted"
        print(f"{idx}. score={artifact.score} type={artifact.kind} source={artifact.source} offset={artifact.offset} validation={artifact.validation} status={status} tags={','.join(artifact.tags)}")
        if artifact.reasons:
            print(f"   reason={'; '.join(artifact.reasons)}")
    if len(ranked) > args.limit:
        print(f"... and {len(ranked) - args.limit} more. Use --top/--limit to change this.")
    return 0


def cmd_extract(args) -> int:
    path = resolve_input(args)
    out = prepare_output_dir(Path(args.out) if args.out else default_output_dir(path), args.force)
    include_raw = bool(args.include_raw) and not args.no_raw
    artifacts = load_artifacts_for_command(path, include_raw, not args.no_payloads)
    _, payload_map = payload_sources(parse_packets(path)) if not args.no_payloads else ([], {})
    ranked = sorted(artifacts, key=lambda a: a.score, reverse=True)
    saved = extract_artifacts(path, ranked, out / "artifacts", payload_map, limit=args.limit)
    manifest = write_artifact_manifest(saved, out / "artifacts")
    if args.http:
        run_tshark_export_http(path, out)
    if args.json:
        print_json({"output_dir": str(out), "manifest": str(manifest), "found": len(artifacts), "selected": min(len(ranked), args.limit), "extracted": saved})
        return 0
    if not saved:
        print("No artifacts were extracted.")
        return 0
    print(f"Artifacts found: {len(artifacts)}")
    print(f"Artifacts selected for extraction: {min(len(ranked), args.limit)}")
    print(f"Artifacts extracted: {len(saved)} to {out / 'artifacts'}")
    for artifact in saved:
        print(f"- {artifact.path} sha256={artifact.sha256} validation={artifact.validation}")
    return 0


def cmd_suspicious(args) -> int:
    path = resolve_input(args)
    artifacts = load_artifacts_for_command(path, not args.no_raw, not args.no_payloads)
    if args.type:
        wanted = {item.strip().lower() for item in args.type.split(",") if item.strip()}
        artifacts = [artifact for artifact in artifacts if artifact.kind.lower() in wanted]
    ranked = sorted((score_artifact(artifact) for artifact in artifacts), key=lambda a: a.score, reverse=True)
    ranked = [artifact for artifact in ranked if artifact.score >= args.min_risk]
    if args.json:
        print_json(ranked[: args.limit])
        return 0
    if not ranked:
        print("No suspicious artifacts matched the filters.")
        return 0
    print("Suspicious Artifacts")
    print("-" * 20)
    for idx, artifact in enumerate(ranked[: args.limit], start=1):
        print(f"{idx}. score={artifact.score} type={artifact.kind} source={artifact.source} offset={artifact.offset} validation={artifact.validation} tags={','.join(artifact.tags)} reason={'; '.join(artifact.reasons)}")
    print("")
    print("Next steps:")
    print(f"- pcat extract -i {shlex.quote(str(path))} -o {shlex.quote(str(default_output_dir(path)))}")
    print("- Run file/strings against extracted artifacts if needed.")
    return 0


def cmd_hunt(args) -> int:
    path = resolve_input(args)
    packets = parse_packets(path)
    payload_rows, payload_map = payload_sources(packets)
    rows = gather_strings(path, payload_rows, include_raw=True, min_len=args.min_len)
    flags = detect_flags(rows, args.ctf_flag)
    creds = detect_credentials(rows)
    decoded = []
    for source, text in rows:
        for item in decode_interesting(text):
            decoded.append((source, item))
    fragments = decoded_payload_fragments(packets)
    for packet, encoded, decoded_text in fragments:
        decoded.append((f"packet:{packet.frame_number}", f"base64-fragment:{encoded} -> {decoded_text}"))
    if len(fragments) >= 2:
        by_time = "".join(text for _, _, text in sorted(fragments, key=lambda item: (item[0].timestamp, item[0].frame_number)))
        by_frame = "".join(text for _, _, text in sorted(fragments, key=lambda item: item[0].frame_number))
        decoded.append(("payload-fragments", f"base64-reconstruction:timestamp-order -> {by_time}"))
        if by_frame != by_time:
            decoded.append(("payload-fragments", f"base64-reconstruction:frame-order -> {by_frame}"))
    clues = clue_rows(rows)
    emails = email_clue_rows(rows)
    artifacts = detect_artifacts(path, list(payload_map.items()), include_raw=True)
    for artifact in artifacts:
        score_artifact(artifact)
    if args.json:
        print_json({
            "file": str(path),
            "packets": len(packets),
            "possible_flags": [{"source": source, "text": text} for source, text in flags[: args.limit]],
            "possible_credentials": [{"source": source, "text": text} for source, text in creds[: args.limit]],
            "possible_email_clues": [{"source": source, "text": text} for source, text in emails[: args.limit]],
            "possible_clues": [{"source": source, "text": text} for source, text in clues[: args.limit]],
            "decoded_strings": [{"source": source, "text": text} for source, text in decoded[: args.limit]],
            "artifacts": sorted(artifacts, key=lambda a: a.score, reverse=True)[: args.limit],
        })
        return 0
    print(f"PCAT CTF Hunt: {path}")
    print("=" * (15 + len(str(path))))
    print(f"Packets: {len(packets)}")
    print("")
    print_hunt_section("Possible Flags", flags, args.limit)
    print_hunt_section("Possible Credentials / Secrets", creds, args.limit)
    print_hunt_section("Possible Email Clues", emails, args.limit)
    print_hunt_section("Possible Clues", clues, args.limit)
    print_hunt_section("Decoded-looking Strings", decoded, args.limit)
    print_hunt_protocol_sections(packets, args.limit)
    print("")
    print("Detected Files")
    print("-" * 14)
    if artifacts:
        for artifact in sorted(artifacts, key=lambda a: a.score, reverse=True)[: args.limit]:
            print(f"[{artifact.kind}] source={artifact.source} offset={artifact.offset} score={artifact.score}")
    else:
        print("No common magic-byte file signatures detected.")
    print("")
    print("Recommended Next Steps")
    print("-" * 22)
    if artifacts:
        print(f"- Extract artifacts: pcat extract -i {shlex.quote(str(path))} -o {shlex.quote(str(default_output_dir(path)))}")
    if flags or creds:
        print(f"- Save strings: pcat strings -i {shlex.quote(str(path))} --output strings.txt")
    print(f"- Run full report: pcat analyze -i {shlex.quote(str(path))} --ctf --extract -o {shlex.quote(str(default_output_dir(path)))}")
    return 0


def cmd_doctor(args) -> int:
    tools = [doctor_tool(name) for name in ["tshark", "capinfos", "file", "7z", "zeek", "suricata"]]
    optional_ml = {
        "name": "scikit-learn",
        "status": "available" if importlib.util.find_spec("sklearn") else "missing",
        "purpose": "optional ML anomaly scoring",
    }
    result = {
        "pcat_version": "0.2.0",
        "python": sys.version.split()[0],
        "tools": tools,
        "python_packages": [optional_ml],
        "notes": [
            "tshark is required for parsing.",
            "capinfos improves capture metadata.",
            "zeek and suricata are planned integration targets, not required for V2 baseline.",
        ],
    }
    if args.json:
        print_json(result)
        return 0
    print("PCAT Doctor")
    print("-" * 11)
    print(f"PCAT: {result['pcat_version']}")
    print(f"Python: {result['python']}")
    print("")
    print("Tools")
    print("-" * 5)
    for tool in tools:
        version = f" - {tool['version']}" if tool.get("version") else ""
        print(f"{tool['name']}: {tool['status']}{version}")
    print("")
    print("Python Packages")
    print("-" * 15)
    print(f"scikit-learn: {optional_ml['status']} ({optional_ml['purpose']})")
    print("")
    print("Notes")
    print("-" * 5)
    for note in result["notes"]:
        print(f"- {note}")
    return 0


def doctor_tool(name: str) -> dict[str, str]:
    path = shutil.which(name)
    return {
        "name": name,
        "status": "available" if path else "missing",
        "path": path or "",
        "version": tool_version(name) if path else "",
    }


def load_strings_for_command(path: Path, min_len: int, include_raw: bool, include_payloads: bool) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    if include_raw:
        rows.extend(raw_file_strings(path, min_len=min_len))
    if include_payloads:
        packets = parse_packets(path)
        payload_rows, _ = payload_sources(packets)
        rows.extend(strings_from_payload_hex(payload_rows, min_len=min_len))
    seen = set()
    deduped = []
    for row in rows:
        if row not in seen:
            seen.add(row)
            deduped.append(row)
    return deduped


def load_artifacts_for_command(path: Path, include_raw: bool, include_payloads: bool):
    payloads = []
    if include_payloads:
        packets = parse_packets(path)
        _, payload_map = payload_sources(packets)
        payloads = list(payload_map.items())
    artifacts = detect_artifacts(path, payloads, include_raw=include_raw)
    return [score_artifact(artifact) for artifact in artifacts]


def run_tshark_export_http(path: Path, out: Path) -> None:
    http_dir = out / "http_objects"
    http_dir.mkdir(parents=True, exist_ok=True)
    cmd = ["tshark", "-r", str(path), "--export-objects", f"http,{http_dir}"]
    subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)


def print_summary(report, top: int) -> None:
    s = report.summary
    print("PCAT Summary")
    print("-" * 12)
    print(f"File: {s.file}")
    print(f"Size: {s.size_bytes:,} bytes")
    print(f"Packets: {s.packet_count:,}")
    print(f"Duration: {s.duration:.2f}s")
    print_counter("Protocols", s.protocols, top)
    print_counter("Top Hosts", s.top_hosts, top)
    print_counter("Top Ports", s.top_ports, top)


def print_counter(title: str, data: dict[str, int], top: int) -> None:
    if not data:
        return
    print("")
    print(title)
    print("-" * len(title))
    for key, value in list(data.items())[:top]:
        print(f"{key}: {value}")


def print_hunt_section(title: str, rows: list[tuple[str, str]], limit: int) -> None:
    print("")
    print(title)
    print("-" * len(title))
    if not rows:
        print("None found.")
        return
    for source, text in rows[:limit]:
        compact = re.sub(r"\s+", " ", text).strip()
        if len(compact) > 250:
            compact = compact[:247] + "..."
        print(f"[{source}] {compact}")


def print_hunt_protocol_sections(packets, limit: int) -> None:
    mqtt_rows = []
    smtp_rows = []
    syn_payload_rows = []
    http_object_rows = []
    for packet in packets:
        if packet.mqtt_topic or packet.mqtt_message or packet.mqtt_username or packet.mqtt_password:
            parts = []
            if packet.mqtt_topic:
                parts.append(f"topic={packet.mqtt_topic}")
            if packet.mqtt_message:
                parts.append(f"message={packet.mqtt_message}")
            if packet.mqtt_username:
                parts.append(f"username={packet.mqtt_username}")
            if packet.mqtt_password:
                parts.append("password field present")
            mqtt_rows.append((f"frame:{packet.frame_number}", "; ".join(parts)))
        if packet.smtp_command or packet.smtp_response or packet.smtp_message or packet.smtp_auth_username or packet.smtp_auth_password:
            parts = []
            if packet.smtp_command:
                parts.append(f"{packet.smtp_command} {packet.smtp_parameter}".strip())
            if packet.smtp_response:
                parts.append(packet.smtp_response)
            if packet.smtp_message:
                parts.append(packet.smtp_message)
            if packet.smtp_auth_username:
                parts.append(f"username={packet.smtp_auth_username}")
            if packet.smtp_auth_password:
                parts.append("password field present")
            smtp_rows.append((f"frame:{packet.frame_number}", "; ".join(parts)))
        if packet.http_status and (packet.http_content_type or packet.http_content_length):
            parts = [f"status={packet.http_status}"]
            if packet.http_uri:
                parts.append(f"uri={packet.http_uri}")
            if packet.http_content_type:
                parts.append(f"type={packet.http_content_type}")
            if packet.http_content_length:
                parts.append(f"length={packet.http_content_length}")
            http_object_rows.append((f"frame:{packet.frame_number}", "; ".join(parts)))
        if is_syn_payload(packet):
            syn_payload_rows.append((f"frame:{packet.frame_number}", f"{packet.src_ip}:{packet.src_port} -> {packet.dst_ip}:{packet.dst_port} len={packet.tcp_len} payload={payload_preview(packet.payload_hex)}"))
    print_hunt_section("HTTP Object / Transfer Clues", http_object_rows, limit)
    print_hunt_section("SMTP Records", smtp_rows, limit)
    print_hunt_section("MQTT Records", mqtt_rows, limit)
    print_hunt_section("SYN Payload Candidates", syn_payload_rows, limit)


def is_syn_payload(packet) -> bool:
    try:
        is_syn = bool(int(packet.tcp_flags, 16) & 0x02)
    except Exception:
        is_syn = "syn" in str(packet.tcp_flags).lower()
    return is_syn and (safe_int(packet.tcp_len) > 0 or bool(packet.payload_hex))


def safe_int(value: str) -> int:
    try:
        return int(str(value).split(",", 1)[0])
    except Exception:
        return 0


def payload_preview(payload_hex: str) -> str:
    if not payload_hex:
        return ""
    try:
        text = bytes.fromhex(payload_hex.replace(":", "")).decode("utf-8", errors="ignore")
    except ValueError:
        text = payload_hex
    text = re.sub(r"\s+", " ", text).strip()
    return text[:80]
