from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

from .analysis import (
    AnalyzeOptions,
    analyze,
    build_tftp_records,
    build_tftp_transfers,
    clue_rows,
    decoded_payload_fragments,
    email_clue_rows,
    gather_strings,
    payload_sources,
    tftp_reconstructed_bytes,
)
from .artifacts import artifact_is_extractable, detect_artifacts, extract_artifacts, score_artifact, write_artifact_manifest
from .evidence import build_report_evidence
from .errors import InvalidArgumentError, PCATError
from .models import to_plain
from .reports import render_briefing, render_terminal, write_reports
from .stringtools import (
    decode_interesting,
    decode_base64_value,
    detect_credentials,
    detect_flags,
    find_matches,
    raw_file_strings,
    strings_from_payload_hex,
)
from .stories import build_briefing, build_stories
from .tshark_parser import parse_packets
from .utils import default_output_dir, format_shell_command, prepare_output_dir, tool_version, validate_input


DEFAULT_FORMATS = {"html", "json", "csv"}
PCAT_VERSION = "0.2.4.1"
HIDDEN_COMPAT_COMMANDS = {"files", "suspicious", "tftp"}


class PCATFormatter(argparse.ArgumentDefaultsHelpFormatter, argparse.RawDescriptionHelpFormatter):
    pass


def main(argv: list[str] | None = None) -> int:
    argv = list(argv if argv is not None else sys.argv[1:])
    short_help_command = short_help_command_from_args(argv)
    if short_help_command is not None:
        print_short_help(short_help_command)
        return 0
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


def short_help_command_from_args(argv: list[str]) -> str | None:
    """Return the command requested by --help-short, or "" for global help."""
    if not argv:
        return None
    if argv[0] == "help-short":
        return argv[1] if len(argv) > 1 else ""
    if "--help-short" not in argv:
        return None
    idx = argv.index("--help-short")
    if idx == 0:
        return argv[1] if len(argv) > 1 and not argv[1].startswith("-") else ""
    return argv[0] if argv[0] not in {"-h", "--help"} else ""


def print_short_help(command: str) -> None:
    if not command:
        print("""PCAT short help
Usage:
  pcat analyze -i capture.pcap
  pcat summary -i capture.pcap
  pcat hunt -i capture.pcap
  pcat extract -i capture.pcap --http --tftp -o case-output

Common commands:
  analyze    Full triage report and optional report files
  summary    Quick capture overview
  streams    TCP streams and UDP conversations
  dns        DNS records
  http       HTTP records
  evidence   Structured evidence records
  timeline   Chronological evidence timeline
  strings    Printable strings from raw bytes and payloads
  search     Search strings, evidence, protocols, findings, and artifacts
  artifacts  Artifact candidates with validation and ranking
  extract    Carve artifacts and export HTTP/TFTP objects
  hunt       CTF-oriented triage workflow
  doctor     Dependency check

More help:
  pcat <command> --help
  pcat <command> --help-short
""")
        return

    short = SHORT_COMMAND_HELP.get(command)
    if short:
        print(short)
        return
    if command in HIDDEN_COMPAT_COMMANDS:
        print(f"""pcat {command}
This compatibility command is hidden from normal help.

Preferred commands:
  pcat artifacts -i capture.pcap
  pcat extract -i capture.pcap --tftp -o case-output
  pcat evidence -i capture.pcap --type tftp_transfer --json
""")
        return
    print(f"Unknown command for short help: {command}", file=sys.stderr)


SHORT_COMMAND_HELP = {
    "analyze": """pcat analyze
Run the full triage pipeline and optionally write reports.

Usage:
  pcat analyze -i capture.pcap
  pcat analyze -i capture.pcap --ctf --extract -o case-output

Common options:
  -i, --input PCAP
  --ctf
  --extract
  -o, --out DIR
  -f, --format html,json,csv,md,txt
  --top N
  --json
""",
    "summary": """pcat summary
Show a quick capture overview.

Usage:
  pcat summary -i capture.pcap
  pcat summary -i capture.pcap --top 20

Common options:
  -i, --input PCAP
  --top N
  --json
""",
    "streams": """pcat streams
Show ranked TCP streams and UDP conversations.

Usage:
  pcat streams -i capture.pcap
  pcat streams -i capture.pcap --top 25

Common options:
  -i, --input PCAP
  --top N
  --json
""",
    "dns": """pcat dns
Show DNS queries and records.

Usage:
  pcat dns -i capture.pcap
  pcat dns -i capture.pcap --top 50

Common options:
  -i, --input PCAP
  --top N
  --json
""",
    "http": """pcat http
Show plaintext HTTP records.

Usage:
  pcat http -i capture.pcap
  pcat http -i capture.pcap --top 50

Common options:
  -i, --input PCAP
  --top N
  --json
""",
    "evidence": """pcat evidence
Show structured evidence records.

Usage:
  pcat evidence -i capture.pcap
  pcat evidence -i capture.pcap --type tftp_transfer --json

Common options:
  -i, --input PCAP
  --type TYPE
  --top N
  --json
""",
    "timeline": """pcat timeline
Show chronological findings and evidence events.

Usage:
  pcat timeline -i capture.pcap
  pcat timeline -i capture.pcap --top 100 --json

Common options:
  -i, --input PCAP
  --top N
  --json
""",
    "strings": """pcat strings
Extract printable strings from raw bytes and packet payloads.

Usage:
  pcat strings -i capture.pcap
  pcat strings -i capture.pcap --grep flag --ignore-case
  pcat strings -i capture.pcap --output strings.txt

Common options:
  -i, --input PCAP
  --grep PATTERN
  --ignore-case
  --output FILE
  --limit N
  --json
""",
    "search": """pcat search
Search PCAT strings, evidence, protocols, findings, and artifacts.

Usage:
  pcat search -i capture.pcap password
  pcat search -i capture.pcap "flag\\{.*\\}" --regex --ignore-case

Common options:
  -i, --input PCAP
  KEYWORD
  --regex
  --ignore-case
  --scope all|strings|decoded|evidence|protocols|artifacts|findings
  --limit N
  --json
""",
    "artifacts": """pcat artifacts
Show detected artifact candidates with validation and ranking.

Usage:
  pcat artifacts -i capture.pcap
  pcat artifacts -i capture.pcap --include-raw --suspicious

Common options:
  -i, --input PCAP
  --include-raw
  --type LIST
  --min-score N
  --suspicious
  --limit N
  --json
""",
    "extract": """pcat extract
Carve validated artifacts and export protocol objects.

Usage:
  pcat extract -i capture.pcap -o case-output
  pcat extract -i capture.pcap --http --tftp -o case-output

Common options:
  -i, --input PCAP
  -o, --out DIR
  --force
  --include-raw
  --http
  --tftp
  --limit N
  --json
""",
    "hunt": """pcat hunt
Run a CTF-oriented triage workflow.

Usage:
  pcat hunt -i capture.pcap
  pcat hunt -i capture.pcap --ctf-flag "CTF{<flag>}"

Common options:
  -i, --input PCAP
  --ctf-flag PATTERN
  --limit N
  --json
""",
    "doctor": """pcat doctor
Check PCAT dependencies and local tool availability.

Usage:
  pcat doctor
  pcat doctor --json

Common options:
  --json
""",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pcat",
        description="PCAT - PCAP Assistant for Triage",
        formatter_class=PCATFormatter,
        epilog="""Examples:
  pcat analyze -i capture.pcap
  pcat analyze -i capture.pcap --ctf --extract -o pcat/demo
  pcat strings -i capture.pcap --grep flag --ignore-case
  pcat extract -i capture.pcap --http --tftp -o pcat/demo
  pcat hunt -i capture.pcap

Command help:
  pcat analyze -h
  pcat -h analyze
  pcat help analyze
  pcat --help-short
  pcat extract --help-short
""",
    )
    parser.add_argument("--version", action="version", version=f"PCAT {PCAT_VERSION}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND", title="commands")

    add_analyze(sub)
    add_summary(sub)
    add_streams(sub)
    add_dns(sub)
    add_http(sub)
    add_tftp(sub)
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


def hide_subcommand(sub, name: str) -> None:
    sub._choices_actions = [item for item in sub._choices_actions if item.dest != name]


def add_common(parser: argparse.ArgumentParser) -> None:
    input_help = "Input capture readable by tshark, such as .pcap, .pcapng, .cap, .pcap.gz, or a valid capture with an unusual extension."
    parser.add_argument("file", nargs="?", metavar="PCAP", help=f"{input_help} Do not use this together with -i/--input.")
    parser.add_argument("-i", "--input", dest="input_file", metavar="PCAP", help=f"{input_help} Preferred explicit input style.")
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
    p.add_argument("--redact", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--no-redact", action="store_true", help=argparse.SUPPRESS)
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


def add_tftp(sub) -> None:
    p = sub.add_parser(
        "tftp",
        help="Show and export TFTP transfers",
        description="Hidden compatibility command. Prefer `pcat extract --tftp` for export and `pcat evidence --type tftp_transfer` for metadata.",
        formatter_class=PCATFormatter,
        epilog="""Examples:
  pcat extract -i capture.pcap --tftp -o pcat/tftp-case
  pcat evidence -i capture.pcap --type tftp_transfer --json
""",
    )
    hide_subcommand(sub, "tftp")
    add_common(p)
    add_output(p)
    p.add_argument("--export", action="store_true", help="Write recoverable TFTP objects to <out>/tftp_objects/")
    p.add_argument("--include-incomplete", action="store_true", help="Export incomplete or unknown-completeness transfers when bytes are available")
    p.add_argument("--top", "--limit", dest="top", type=int, default=50, metavar="N", help="Number of TFTP transfers to display or export")
    p.set_defaults(func=cmd_tftp)


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
    p.add_argument("--source", choices=["all", "raw", "packet"], default="all", help="String source to scan. all uses enabled raw and packet-payload sources.")
    p.add_argument("--no-raw", action="store_true", help="Skip raw PCAP byte scanning")
    p.add_argument("--no-payloads", action="store_true", help="Skip parsed packet payload scanning")
    p.set_defaults(func=cmd_strings)


def add_search(sub) -> None:
    p = sub.add_parser(
        "search",
        help="Search strings, decoded values, evidence, protocols, findings, and artifacts",
        description="Search PCAT's evidence index. By default this includes strings, decoded strings, protocol records, evidence, findings, and artifacts.",
        formatter_class=PCATFormatter,
        epilog="""Examples:
  pcat search -i capture.pcap password
  pcat search -i capture.pcap "flag\\{.*\\}" --regex
  pcat search capture.pcap token --ignore-case --limit 50
  pcat search -i capture.pcap firmware --scope protocols
  pcat search -i capture.pcap tftp --scope evidence --json
""",
    )
    add_common(p)
    p.add_argument("keyword", metavar="KEYWORD", help="Keyword to search for, or regex pattern when --regex is used")
    p.add_argument("--regex", action="store_true", help="Treat KEYWORD as a regular expression")
    p.add_argument("--ignore-case", action="store_true", help="Use case-insensitive matching")
    p.add_argument("--scope", choices=["all", "strings", "decoded", "evidence", "protocols", "artifacts", "findings"], default="all", help="Evidence scope to search")
    p.add_argument("--min", type=int, default=5, dest="min_len", metavar="N", help="Minimum printable string length before searching")
    p.add_argument("--limit", "--top", dest="limit", type=int, default=100, metavar="N", help="Maximum matches to print")
    p.add_argument("--source", choices=["all", "raw", "packet"], default="all", help="String source to search. all uses enabled raw and packet-payload sources.")
    p.add_argument("--no-raw", action="store_true", help="Skip raw PCAP byte scanning")
    p.add_argument("--no-payloads", action="store_true", help="Skip parsed packet payload scanning")
    p.set_defaults(func=cmd_search)


def add_files(sub) -> None:
    p = sub.add_parser(
        "files",
        help="Deprecated alias for artifact detection",
        description="Compatibility alias for artifact listing. Prefer `pcat artifacts`; this command keeps old raw-scan defaults for scripts.",
        formatter_class=PCATFormatter,
        epilog="""Examples:
  pcat files -i capture.pcap
  pcat files capture.pcap --no-raw
""",
    )
    hide_subcommand(sub, "files")
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
  pcat artifacts -i capture.pcap --type pe,zip --min-score 40
  pcat artifacts -i capture.pcap --suspicious --extractable
""",
    )
    add_common(p)
    p.add_argument("--include-raw", action="store_true", help="Include raw PCAP byte scanning in addition to packet payload artifacts")
    p.add_argument("--no-payloads", action="store_true", help="Skip parsed packet payload scanning")
    p.add_argument("--type", metavar="LIST", help="Comma-separated artifact type filter, for example pe,zip,pdf,png")
    p.add_argument("--min-score", type=int, default=None, metavar="N", help="Minimum artifact score to display")
    p.add_argument("--extractable", action="store_true", help="Only show artifacts that PCAT would select for extraction")
    p.add_argument("--show-rejected", action="store_true", help="Show rejected signature hits in text output")
    p.add_argument("--suspicious", action="store_true", help="Apply suspicious-artifact ranking defaults")
    p.add_argument("--limit", "--top", dest="limit", type=int, default=50, metavar="N", help="Maximum artifact rows to print")
    p.set_defaults(func=cmd_artifacts)


def add_extract(sub) -> None:
    p = sub.add_parser(
        "extract",
        help="Extract artifacts and export HTTP/TFTP objects",
        description="Best-effort artifact carving plus supported protocol object export into a PCAT output folder.",
        formatter_class=PCATFormatter,
        epilog="""Examples:
  pcat extract -i capture.pcap -o pcat/demo
  pcat extract -i capture.pcap --http -o pcat/http-demo --force
  pcat extract -i capture.pcap --tftp -o pcat/tftp-demo
""",
    )
    add_common(p)
    add_output(p)
    p.add_argument("--http", action="store_true", help="Export HTTP objects with tshark when possible")
    p.add_argument("--tftp", action="store_true", help="Export recoverable TFTP transfer objects to <out>/tftp_objects/")
    p.add_argument("--include-incomplete-tftp", action="store_true", help="Export incomplete or unknown-completeness TFTP transfers when bytes are available")
    p.add_argument("--include-raw", action="store_true", help="Include raw PCAP byte carving. Disabled by default to reduce false-positive extraction.")
    p.add_argument("--no-raw", action="store_true", help="Legacy alias kept for scripts; raw carving is already disabled by default")
    p.add_argument("--no-payloads", action="store_true", help="Skip parsed packet payload carving")
    p.add_argument("--limit", "--top", dest="limit", type=int, default=50, metavar="N", help="Maximum artifacts to extract")
    p.set_defaults(func=cmd_extract)


def add_suspicious(sub) -> None:
    p = sub.add_parser(
        "suspicious",
        help="Deprecated alias for suspicious artifact ranking",
        description="Compatibility alias for `pcat artifacts --suspicious`. Prefer the consolidated artifacts command.",
        formatter_class=PCATFormatter,
        epilog="""Examples:
  pcat suspicious -i capture.pcap
  pcat suspicious capture.pcap --type zip,pdf,png --min-risk 30
""",
    )
    hide_subcommand(sub, "suspicious")
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
    if args.redact:
        raise InvalidArgumentError("Redaction is not implemented yet. PCAT does not redact by default; rerun without --redact.")
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
        selected = selectable_artifacts(candidates, payload_map)[: max(0, args.extract_limit)]
        saved = extract_artifacts(path, selected, artifacts_dir, payload_map, limit=args.extract_limit)
        write_artifact_manifest(selected, artifacts_dir)
        extraction_summary = artifact_extraction_summary(selected, report.artifacts, include_raw=args.include_raw_artifacts, saved=saved)
        if saved:
            strings = gather_strings(path, payload_rows, include_raw=True)
            build_report_evidence(report, packets, strings)
            report.stories = build_stories(report, packets)
            report.briefing = build_briefing(report, packets)
        if not args.quiet and not args.json:
            counts = artifact_certainty_counts(selected)
            print(f"Artifacts found: {found_count}")
            print(f"Artifacts selected for extraction: {len(selected)}")
            print(f"Selected certainty: confirmed={counts['confirmed']} candidate={counts['candidate']} rejected={counts['rejected']}")
            print_unextractable_summary(candidates)
            print(f"Artifacts extracted: {len(saved)}")
            if extraction_summary["skipped_raw_disabled"]:
                print(f"Raw-capture artifacts skipped: {extraction_summary['skipped_raw_disabled']} (use --include-raw-artifacts to include them)")
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
        print_json({"schema_version": report.schema_version, "capture": report.capture, "summary": report.summary, "briefing": report.briefing, "stories": report.stories[: args.top], "warnings": report.warnings})
        return 0
    for line in render_briefing(report, args.top):
        print(line)
    if report.briefing:
        print("")
    print_summary(report, args.top)
    return 0


def cmd_streams(args) -> int:
    report = analyze(resolve_input(args), AnalyzeOptions(no_ml=True, min_risk=0))
    if args.json:
        print_json(report.streams[: args.top])
        return 0
    print("Streams")
    print("-" * 7)
    if not report.streams:
        print("No TCP streams or UDP conversations found in parsed TShark fields.")
        return 0
    for stream in report.streams[: args.top]:
        if stream.kind == "udp_conversation":
            label = stream.conversation_id or "udp"
            arrow = "<->"
        else:
            label = f"tcp.stream {stream.stream_id}"
            arrow = "->"
        print(f"{label}: {stream.src_ip}:{stream.src_port} {arrow} {stream.dst_ip}:{stream.dst_port} protocol={stream.protocol} packets={stream.packet_count} bytes={stream.byte_count} score={stream.interest_score}")
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
    if not report.dns_records:
        print("No DNS records found in parsed TShark fields.")
        return 0
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
    if not report.http_records:
        print("No HTTP records found in parsed TShark fields.")
        return 0
    for record in report.http_records[: args.top]:
        uri = record.full_uri or f"{record.host}{record.uri}"
        length = f" length={record.content_length}" if record.content_length else ""
        print(f"frame={record.frame_number} stream={record.stream_id} {record.method} {uri} status={record.status} type={record.content_type}{length}")
    return 0


def cmd_tftp(args) -> int:
    print(
        "Warning: pcat tftp is deprecated; use `pcat extract --tftp` for export "
        "or `pcat evidence --type tftp_transfer` for metadata.",
        file=sys.stderr,
    )
    path = resolve_input(args)
    report = analyze(path, AnalyzeOptions(no_ml=True, min_risk=0))
    export_summary = None
    if args.export and report.tftp_transfers:
        out = prepare_output_dir(Path(args.out) if args.out else default_output_dir(path), args.force)
        export_summary = export_tftp_transfers(report.tftp_records, report.tftp_transfers, out / "tftp_objects", args.top, args.include_incomplete)
    elif args.export:
        export_summary = {"output_dir": "", "exported": 0, "skipped": 0, "exported_records": [], "skipped_records": [], "status": "no_tftp_transfers"}
    if args.json:
        print_json({
            "schema_version": report.schema_version,
            "records": report.tftp_records,
            "transfers": report.tftp_transfers[: args.top],
            "export": export_summary,
        })
        return 0
    print("TFTP Transfers")
    print("-" * 14)
    if not report.tftp_records and not report.tftp_transfers:
        print("No TFTP records found in parsed TShark fields.")
        return 0
    if not report.tftp_transfers:
        print(f"TFTP packets found: {len(report.tftp_records)}, but PCAT could not group them into transfers.")
        return 0
    for transfer in report.tftp_transfers[: args.top]:
        request = f" request_frame={transfer.request_frame}" if transfer.request_frame else ""
        exported = f" export={transfer.export_path}" if transfer.export_path else ""
        print(
            f"{transfer.transfer_id}: file={transfer.filename or '(unknown)'} direction={transfer.direction} "
            f"{transfer.client_ip}->{transfer.server_ip}{request} blocks={transfer.block_count} "
            f"bytes={transfer.byte_count} completeness={transfer.completeness}{exported}"
        )
        if transfer.error:
            print(f"  error={transfer.error}")
    if export_summary:
        print("")
        print("Export Summary")
        print("-" * 14)
        print(f"Output: {export_summary['output_dir']}")
        print(f"Exported: {export_summary['exported']}")
        print(f"Skipped: {export_summary['skipped']}")
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
        events = sorted([
            {"timestamp": item.timestamp, "title": item.type, "detail": item.preview, "severity": "info"}
            for item in report.evidence
            if item.timestamp is not None
        ], key=lambda item: (float(item["timestamp"]), item["title"]))[: args.top]
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
            timestamp = format_timeline_timestamp(event.get("timestamp"))
            print(f"{timestamp} [{event['severity']}] {event['title']} - {event['detail']}")
        else:
            timestamp = format_timeline_timestamp(event.timestamp)
            print(f"{timestamp} [{event.severity}] {event.title} - {event.detail}")
    return 0


def cmd_strings(args) -> int:
    path = resolve_input(args)
    include_raw, include_payloads = resolve_string_source_flags(args.source, not args.no_raw, not args.no_payloads)
    rows = load_strings_for_command(path, args.min_len, include_raw, include_payloads)
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
    pattern = compile_search_pattern(args.keyword, args.regex, args.ignore_case)
    records = build_search_records(path, args)
    matches = [record for record in records if pattern.search(search_record_haystack(record))]
    if args.json:
        print_json(matches[: args.limit])
        return 0
    if not matches:
        print("No matches found.")
        return 0
    for record in matches[: args.limit]:
        location = f" {record['location']}" if record.get("location") else ""
        print(f"[{record['scope']}:{record['type']}] {record['source']}{location} {record['text']}")
    print(f"Displayed {min(len(matches), args.limit)} of {len(matches)} matches.")
    return 0


def cmd_files(args) -> int:
    print_deprecated_alias("files", "artifacts", "--include-raw" if not args.no_raw else "")
    path = resolve_input(args)
    artifacts = load_artifacts_for_command(path, not args.no_raw, not args.no_payloads)
    ranked = sorted(artifacts, key=lambda a: a.score, reverse=True)
    if args.json:
        print_json(ranked[: args.limit])
        return 0
    if not artifacts:
        print("No common embedded file signatures detected.")
        return 0
    print("Detected Files")
    print("-" * 14)
    display = ranked if args.verbose else [artifact for artifact in ranked if artifact.certainty != "rejected"]
    for idx, artifact in enumerate(display[: args.limit], start=1):
        print(format_artifact_row(idx, artifact, include_reasons=True))
    if not display:
        print("No confirmed or candidate artifacts found in the selected sources.")
    print_rejected_artifact_groups(ranked, verbose=args.verbose)
    if len(ranked) > args.limit:
        print(f"... and {len(ranked) - args.limit} more. Use --top/--limit to change this.")
    return 0


def cmd_artifacts(args) -> int:
    path = resolve_input(args)
    artifacts = load_artifacts_for_command(path, args.include_raw, not args.no_payloads)
    ranked = filter_artifacts_for_display(
        artifacts,
        types=getattr(args, "type", None),
        min_score=getattr(args, "min_score", None),
        extractable=getattr(args, "extractable", False),
        suspicious=getattr(args, "suspicious", False),
    )
    if args.json:
        print_json(ranked[: args.limit])
        return 0
    if not ranked:
        print("No artifacts detected with the selected sources.")
        return 0
    print("Artifacts")
    print("-" * 9)
    display = ranked if (args.verbose or args.show_rejected) else [artifact for artifact in ranked if artifact.certainty != "rejected"]
    for idx, artifact in enumerate(display[: args.limit], start=1):
        status = artifact.extraction_status or "not-extracted"
        print(f"{format_artifact_row(idx, artifact)} status={status}")
        if artifact.reasons:
            print(f"   reason={'; '.join(artifact.reasons)}")
    if not display:
        print("No confirmed or candidate artifacts found in the selected sources.")
    print_rejected_artifact_groups(ranked, verbose=args.verbose)
    if len(ranked) > args.limit:
        print(f"... and {len(ranked) - args.limit} more. Use --top/--limit to change this.")
    return 0


def cmd_extract(args) -> int:
    path = resolve_input(args)
    out = prepare_output_dir(Path(args.out) if args.out else default_output_dir(path), args.force)
    include_raw = bool(args.include_raw) and not args.no_raw
    packets = parse_packets(path) if (not args.no_payloads or args.tftp) else []
    _, payload_map = payload_sources(packets) if not args.no_payloads else ([], {})
    all_artifacts = [score_artifact(artifact) for artifact in detect_artifacts(path, list(payload_map.items()), include_raw=True)]
    artifacts = [artifact for artifact in all_artifacts if include_raw or artifact.source != "raw-file"]
    selected = selectable_artifacts(artifacts, payload_map)[: max(0, args.limit)]
    saved = extract_artifacts(path, selected, out / "artifacts", payload_map, limit=args.limit)
    manifest = write_artifact_manifest(selected, out / "artifacts")
    counts = artifact_certainty_counts(selected)
    summary = artifact_extraction_summary(selected, all_artifacts, include_raw=include_raw, saved=saved)
    http_export = None
    if args.http:
        http_export = run_tshark_export_http(path, out)
        summary["http_objects_exported"] = http_export["exported_count"]
        summary["http_objects_dir"] = http_export["output_dir"]
        summary["http_export_status"] = http_export["status"]
    tftp_export = None
    if args.tftp:
        tftp_records = build_tftp_records(packets)
        tftp_transfers = build_tftp_transfers(tftp_records)
        if tftp_transfers:
            tftp_export = export_tftp_transfers(tftp_records, tftp_transfers, out / "tftp_objects", args.limit, args.include_incomplete_tftp)
        else:
            tftp_export = {
                "output_dir": str(out / "tftp_objects"),
                "exported": 0,
                "skipped": 0,
                "exported_records": [],
                "skipped_records": [],
                "status": "no_tftp_transfers",
            }
        summary["tftp_transfers_found"] = len(tftp_transfers)
        summary["tftp_objects_exported"] = tftp_export["exported"]
        summary["tftp_objects_dir"] = tftp_export["output_dir"]
        summary["tftp_export_status"] = tftp_export["status"]
        summary["tftp_transfers_skipped"] = tftp_export["skipped"]
    if args.json:
        print_json({
            "output_dir": str(out),
            "manifest": str(manifest),
            "found": len(all_artifacts),
            "selected": len(selected),
            "certainty_counts": counts,
            "extraction_summary": summary,
            "http_export": http_export,
            "tftp_export": tftp_export,
            "extracted_count": len(saved),
            "extracted": saved,
            "selected_artifacts": selected,
        })
        return 0
    print(f"Artifacts found: {len(all_artifacts)}")
    print(f"Artifacts selected for extraction: {len(selected)}")
    print(f"Selected certainty: confirmed={counts['confirmed']} candidate={counts['candidate']} rejected={counts['rejected']}")
    print_unextractable_summary(artifacts)
    if summary["skipped_raw_disabled"]:
        print(f"Raw-capture artifacts skipped: {summary['skipped_raw_disabled']} (use --include-raw to include raw PCAP byte hits)")
    if summary["validation_failed"] or summary["skipped_incomplete"] or summary["missing_source"]:
        print(f"Skipped selected artifacts: validation_failed={summary['validation_failed']} incomplete={summary['skipped_incomplete']} missing_source={summary['missing_source']}")
    if http_export:
        print(f"HTTP objects exported: {http_export['exported_count']} to {http_export['output_dir']} ({http_export['status']})")
        if http_export.get("error") and args.verbose:
            print(f"HTTP export detail: {http_export['error']}")
    if tftp_export:
        print(f"TFTP transfers found: {summary['tftp_transfers_found']}")
        print(f"TFTP objects exported: {tftp_export['exported']} to {tftp_export['output_dir']} ({tftp_export['status']})")
        if tftp_export["skipped"]:
            print(f"TFTP transfers skipped: {tftp_export['skipped']} (use --include-incomplete-tftp to export incomplete transfers with bytes)")
    if not saved:
        print(f"Artifacts extracted: 0")
        protocol_objects_exported = bool((http_export and http_export["exported_count"]) or (tftp_export and tftp_export["exported"]))
        if protocol_objects_exported:
            print("No artifact signatures were carved; protocol object export completed separately.")
        else:
            print("No artifacts were extracted. Selected hits were rejected, missing source data, or otherwise not extractable.")
        print(f"Manifest written to {manifest}")
        return 0
    print(f"Artifacts extracted: {len(saved)} to {out / 'artifacts'}")
    for artifact in saved:
        print(f"- {artifact.path} sha256={artifact.sha256} certainty={artifact.certainty} validation={artifact.validation}")
    return 0


def cmd_suspicious(args) -> int:
    print_deprecated_alias("suspicious", "artifacts", "--suspicious")
    path = resolve_input(args)
    artifacts = load_artifacts_for_command(path, not args.no_raw, not args.no_payloads)
    ranked = filter_artifacts_for_display(
        artifacts,
        types=args.type,
        min_score=args.min_risk,
        extractable=False,
        suspicious=True,
    )
    if args.json:
        print_json(ranked[: args.limit])
        return 0
    if not ranked:
        print("No suspicious artifacts matched the filters.")
        return 0
    print("Suspicious Artifacts")
    print("-" * 20)
    for idx, artifact in enumerate(ranked[: args.limit], start=1):
        print(f"{idx}. score={artifact.score} certainty={artifact.certainty} type={artifact.kind} source={artifact.source} offset={artifact.offset} validation={artifact.validation} tags={','.join(artifact.tags)} reason={'; '.join(artifact.reasons)}")
    print("")
    print("Next steps:")
    if has_extractable_artifacts(ranked):
        command = extract_command_for_artifacts(path, ranked)
        print(f"- {command}")
        print("- Run file/strings against extracted artifacts if needed.")
    else:
        print("- No extractable artifacts in this filtered set; inspect artifact metadata first.")
    return 0


def cmd_hunt(args) -> int:
    path = resolve_input(args)
    packets = parse_packets(path)
    tftp_records = build_tftp_records(packets)
    tftp_transfers = build_tftp_transfers(tftp_records)
    payload_rows, payload_map = payload_sources(packets)
    rows = gather_strings(path, payload_rows, include_raw=True, min_len=args.min_len)
    flags = detect_flags(rows, args.ctf_flag)
    creds = dedupe_hunt_rows(smtp_auth_credentials_from_packets(packets) + detect_credentials(rows))
    decoded = []
    for source, text in rows:
        for item in decode_interesting(text):
            if args.verbose or decoded_default_visible(item):
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
            "tftp_transfers": tftp_transfers[: args.limit],
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
    print_tftp_hunt_section(tftp_transfers, args.limit)
    print("")
    print("Detected Files")
    print("-" * 14)
    if artifacts:
        ranked_artifacts = sorted(artifacts, key=lambda a: a.score, reverse=True)
        display_artifacts = ranked_artifacts if args.verbose else [artifact for artifact in ranked_artifacts if artifact.certainty != "rejected"]
        for artifact in display_artifacts[: args.limit]:
            print(f"[{artifact.certainty} {artifact.kind}] source={artifact.source} offset={artifact.offset} score={artifact.score} validation={artifact.validation}")
        if not display_artifacts:
            print("No confirmed or candidate artifacts found.")
        print_rejected_artifact_groups(ranked_artifacts, verbose=args.verbose)
    else:
        print("No common magic-byte file signatures detected.")
    print("")
    print("Recommended Next Steps")
    print("-" * 22)
    if has_extractable_artifacts(artifacts):
        print(f"- Extract artifacts: {extract_command_for_artifacts(path, artifacts)}")
    elif artifacts:
        print("- Artifact signatures were rejected by validation; inspect pcat artifacts output before attempting extraction.")
    if tftp_transfers:
        print(f"- Inspect TFTP transfer metadata: {format_shell_command(['pcat', 'evidence', '-i', path, '--type', 'tftp_transfer', '--json'])}")
        if any(transfer.completeness == "complete" and transfer.byte_count for transfer in tftp_transfers):
            print(f"- Export TFTP objects: {format_shell_command(['pcat', 'extract', '-i', path, '--tftp', '-o', default_output_dir(path)])}")
    if flags or creds:
        print(f"- Save strings: {format_shell_command(['pcat', 'strings', '-i', path, '--output', 'strings.txt'])}")
    print(f"- Run full report: {format_shell_command(['pcat', 'analyze', '-i', path, '--ctf', '--extract', '-o', default_output_dir(path)])}")
    return 0


def smtp_auth_credentials_from_packets(packets) -> list[tuple[str, str]]:
    rows = []
    for packet in packets:
        username = decode_base64_value(packet.smtp_auth_username)
        password = decode_base64_value(packet.smtp_auth_password)
        if not username and not password:
            continue
        parts = ["SMTP AUTH"]
        if username:
            parts.append(f"username={username}")
        if password:
            parts.append(f"password={password}")
        rows.append((f"frame:{packet.frame_number}", " ".join(parts)))
    return rows


def dedupe_hunt_rows(rows: list[tuple[str, str]]) -> list[tuple[str, str]]:
    seen = set()
    deduped = []
    for row in rows:
        if row in seen:
            continue
        seen.add(row)
        deduped.append(row)
    return deduped


def cmd_doctor(args) -> int:
    tools = [doctor_tool(name) for name in ["tshark", "capinfos", "file", "7z", "zeek", "suricata"]]
    optional_ml = {
        "name": "scikit-learn",
        "status": "available" if importlib.util.find_spec("sklearn") else "missing",
        "purpose": "optional ML anomaly scoring",
    }
    result = {
        "pcat_version": PCAT_VERSION,
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


def resolve_string_source_flags(source: str, include_raw: bool, include_payloads: bool) -> tuple[bool, bool]:
    if source == "raw":
        return True, False
    if source == "packet":
        return False, True
    return include_raw, include_payloads


def compile_search_pattern(keyword: str, regex: bool, ignore_case: bool):
    flags = re.IGNORECASE if ignore_case else 0
    pattern = keyword if regex else re.escape(keyword)
    try:
        return re.compile(pattern, flags)
    except re.error as exc:
        raise InvalidArgumentError(f"Invalid regex pattern: {exc}") from exc


def build_search_records(path: Path, args) -> list[dict[str, str]]:
    scopes = search_scopes(args.scope)
    records: list[dict[str, str]] = []
    need_strings = bool(scopes & {"strings", "decoded"})
    string_rows: list[tuple[str, str]] = []
    if need_strings:
        include_raw, include_payloads = resolve_string_source_flags(args.source, not args.no_raw, not args.no_payloads)
        string_rows = load_strings_for_command(path, args.min_len, include_raw, include_payloads)
    if "strings" in scopes:
        for source, text in string_rows:
            records.append(search_record("strings", "raw_string" if source == "raw-file" else "payload_string", source, text, source))
    if "decoded" in scopes:
        for source, text in string_rows:
            for decoded in decode_interesting(text):
                records.append(search_record("decoded", "decoded_string", source, decoded, source))
    if scopes & {"evidence", "protocols", "artifacts", "findings"}:
        report = analyze(path, AnalyzeOptions(no_ml=True, min_risk=0))
        if "protocols" in scopes:
            records.extend(protocol_search_records(report))
        if "evidence" in scopes:
            for item in report.evidence:
                if args.scope == "all" and item.type in {"raw_string", "payload_string", "decoded_string"}:
                    continue
                records.append(search_record("evidence", item.type, item.evidence_id, item.preview, evidence_location(item), item.fields))
        if "artifacts" in scopes:
            for artifact in report.artifacts:
                text = f"{artifact.kind} {artifact.filename} {artifact.source} {artifact.certainty} {artifact.validation} {' '.join(artifact.tags)} {' '.join(artifact.reasons)}"
                records.append(search_record("artifacts", artifact.kind, artifact.artifact_id, text, artifact.source, to_plain(artifact)))
        if "findings" in scopes:
            for finding in report.findings:
                text = " ".join([finding.title, finding.category, finding.explanation, finding.next_step, " ".join(finding.evidence)])
                records.append(search_record("findings", finding.category, finding.finding_id or finding.title, text, finding.related, to_plain(finding)))
    return records


def search_scopes(scope: str) -> set[str]:
    if scope == "all":
        return {"strings", "decoded", "evidence", "protocols", "artifacts", "findings"}
    return {scope}


def search_record(scope: str, record_type: str, source: str, text: str, location: str = "", fields=None) -> dict[str, str]:
    return {
        "scope": scope,
        "type": record_type,
        "source": source,
        "location": location,
        "text": re.sub(r"\s+", " ", str(text)).strip(),
        "fields": fields or {},
    }


def search_record_haystack(record: dict) -> str:
    return json.dumps(to_plain(record), sort_keys=True, default=str)


def evidence_location(item) -> str:
    parts = []
    if item.frame_start:
        parts.append(f"frame:{item.frame_start}")
    if item.stream_id:
        parts.append(f"stream:{item.stream_id}")
    return " ".join(parts)


def protocol_search_records(report) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    for item in report.dns_records:
        text = f"{item.query} {item.answer} {item.rcode}"
        records.append(search_record("protocols", "dns", f"frame:{item.frame_number}", text, f"frame:{item.frame_number}", to_plain(item)))
    for item in report.http_records:
        text = " ".join([item.method, item.full_uri or item.uri, item.host, item.status, item.content_type, item.user_agent])
        records.append(search_record("protocols", "http", f"frame:{item.frame_number}", text, f"frame:{item.frame_number} stream:{item.stream_id}".strip(), to_plain(item)))
    for item in report.smtp_records:
        text = " ".join([item.command, item.parameter, item.response, item.message, item.auth_username])
        records.append(search_record("protocols", "smtp", f"frame:{item.frame_number}", text, f"frame:{item.frame_number} stream:{item.stream_id}".strip(), to_plain(item)))
    for item in report.mqtt_records:
        text = " ".join([item.topic, item.message, item.username])
        records.append(search_record("protocols", "mqtt", f"frame:{item.frame_number}", text, f"frame:{item.frame_number} stream:{item.stream_id}".strip(), to_plain(item)))
    for item in report.tftp_records:
        text = " ".join([item.opcode, item.source_file, item.destination_file, item.transfer_type, item.block, item.error_message])
        records.append(search_record("protocols", "tftp_packet", f"frame:{item.frame_number}", text, f"frame:{item.frame_number}", to_plain(item)))
    for item in report.tftp_transfers:
        text = " ".join([item.transfer_id, item.filename, item.direction, item.completeness, item.error])
        records.append(search_record("protocols", "tftp_transfer", item.transfer_id, text, f"request_frame:{item.request_frame or ''}", to_plain(item)))
    return records


def load_artifacts_for_command(path: Path, include_raw: bool, include_payloads: bool):
    payloads = []
    if include_payloads:
        packets = parse_packets(path)
        _, payload_map = payload_sources(packets)
        payloads = list(payload_map.items())
    artifacts = detect_artifacts(path, payloads, include_raw=include_raw)
    return [score_artifact(artifact) for artifact in artifacts]


def filter_artifacts_for_display(
    artifacts,
    types: str | None = None,
    min_score: int | None = None,
    extractable: bool = False,
    suspicious: bool = False,
):
    ranked = sorted((score_artifact(artifact) for artifact in artifacts), key=lambda a: a.score, reverse=True)
    if types:
        wanted = {item.strip().lower() for item in types.split(",") if item.strip()}
        ranked = [artifact for artifact in ranked if artifact.kind.lower() in wanted]
    threshold = min_score
    if suspicious and threshold is None:
        threshold = 20
    if threshold is not None:
        ranked = [artifact for artifact in ranked if artifact.score >= threshold]
    if extractable:
        ranked = [artifact for artifact in ranked if artifact_is_extractable(artifact)]
    return ranked


def print_deprecated_alias(command: str, replacement: str, extra: str = "") -> None:
    parts = ["pcat", replacement]
    if extra:
        parts.append(extra)
    print(f"Warning: pcat {command} is deprecated; use {format_shell_command(parts)}.", file=sys.stderr)


def selectable_artifacts(artifacts, payload_map: dict[str, bytes]):
    return [
        artifact
        for artifact in sorted(artifacts, key=lambda a: a.score, reverse=True)
        if artifact_is_extractable(artifact) and artifact_source_available(artifact, payload_map)
    ]


def artifact_source_available(artifact, payload_map: dict[str, bytes]) -> bool:
    return artifact.source == "raw-file" or artifact.source in payload_map


def print_unextractable_summary(artifacts) -> None:
    rejected = sum(1 for artifact in artifacts if artifact.certainty == "rejected")
    incomplete = sum(
        1
        for artifact in artifacts
        if artifact.certainty != "rejected" and (artifact.validation == "truncated" or artifact.complete_file_valid is False)
    )
    missing_source = sum(1 for artifact in artifacts if artifact.source != "raw-file" and artifact.extraction_status == "skipped_missing_source")
    if rejected or incomplete or missing_source:
        print(f"Unextractable artifact hits: rejected={rejected} incomplete={incomplete} missing_source={missing_source}")


def has_extractable_artifacts(artifacts) -> bool:
    return any(artifact_is_extractable(artifact) for artifact in artifacts)


def extract_command_for_artifacts(path: Path, artifacts) -> str:
    return format_shell_command([
        "pcat",
        "extract",
        "-i",
        path,
        "-o",
        default_output_dir(path),
        "--include-raw" if needs_include_raw(artifacts) else "",
    ])


def needs_include_raw(artifacts) -> bool:
    raw = [artifact for artifact in artifacts if artifact.source == "raw-file" and artifact_is_extractable(artifact)]
    packet = [artifact for artifact in artifacts if artifact.source != "raw-file" and artifact_is_extractable(artifact)]
    return bool(raw) and not packet


def artifact_certainty_counts(artifacts) -> dict[str, int]:
    counts = {"confirmed": 0, "candidate": 0, "rejected": 0}
    for artifact in artifacts:
        key = artifact.certainty if artifact.certainty in counts else "candidate"
        counts[key] += 1
    return counts


def artifact_extraction_summary(selected, all_artifacts, include_raw: bool, saved) -> dict[str, int | str]:
    return {
        "found": len(all_artifacts),
        "selected": len(selected),
        "extracted": len(saved),
        "rejected": sum(1 for artifact in selected if artifact.certainty == "rejected"),
        "skipped_raw_disabled": sum(1 for artifact in all_artifacts if artifact.source == "raw-file" and not include_raw),
        "validation_failed": sum(1 for artifact in selected if artifact.extraction_status == "skipped_invalid"),
        "skipped_incomplete": sum(1 for artifact in selected if artifact.extraction_status == "skipped_incomplete"),
        "missing_source": sum(1 for artifact in selected if artifact.extraction_status == "skipped_missing_source"),
        "http_objects_exported": 0,
        "http_objects_dir": "",
        "http_export_status": "not_requested",
        "tftp_transfers_found": 0,
        "tftp_objects_exported": 0,
        "tftp_objects_dir": "",
        "tftp_export_status": "not_requested",
        "tftp_transfers_skipped": 0,
    }


def rejected_artifact_groups(artifacts) -> dict[tuple[str, str, str], int]:
    groups: dict[tuple[str, str, str], int] = {}
    for artifact in artifacts:
        if artifact.certainty != "rejected":
            continue
        reason = artifact.skip_reason or next((item for item in artifact.reasons if "invalid" in item or "complete" in item), "validation rejected")
        key = (artifact.kind, artifact.validation, reason)
        groups[key] = groups.get(key, 0) + 1
    return groups


def print_rejected_artifact_groups(artifacts, verbose: bool = False) -> None:
    if verbose:
        return
    groups = rejected_artifact_groups(artifacts)
    if not groups:
        return
    print("")
    print("Rejected artifact groups")
    print("-" * 24)
    for (kind, validation, reason), count in sorted(groups.items()):
        print(f"- {count} {kind} hit(s): validation={validation} reason={reason}")
    print("Use --verbose or --json to inspect individual rejected offsets.")


def format_artifact_row(index: int, artifact, include_reasons: bool = False) -> str:
    base = (
        f"{index}. score={artifact.score} certainty={artifact.certainty} type={artifact.kind} "
        f"source={artifact.source} scope={artifact.source_scope} offset={artifact.offset} "
        f"validation={artifact.validation} complete={artifact.complete_file_valid} "
        f"truncated={artifact.truncated} tags={','.join(artifact.tags)}"
    )
    if include_reasons and artifact.reasons:
        return f"{base} reason={'; '.join(artifact.reasons)}"
    return base


def format_timeline_timestamp(value) -> str:
    if value is None:
        return "unknown"
    return f"{float(value):.6f}"


def decoded_default_visible(text: str) -> bool:
    lowered = text.lower()
    return any(token in lowered for token in ["flag", "ctf{", "password", "passwd", "token", "secret", "base85", "base64-fragment"])


def run_tshark_export_http(path: Path, out: Path) -> dict[str, str | int]:
    http_dir = out / "http_objects"
    http_dir.mkdir(parents=True, exist_ok=True)
    cmd = ["tshark", "-r", str(path), "--export-objects", f"http,{http_dir}"]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    except FileNotFoundError as exc:
        return {"output_dir": str(http_dir), "exported_count": 0, "status": "missing_tshark", "error": str(exc)}
    after = {item for item in http_dir.rglob("*") if item.is_file()}
    exported = len(after)
    status = "ok" if result.returncode == 0 else "failed"
    error = result.stderr.strip()
    return {"output_dir": str(http_dir), "exported_count": exported, "status": status, "error": error}


def export_tftp_transfers(records, transfers, out_dir: Path, limit: int, include_incomplete: bool) -> dict[str, object]:
    out_dir.mkdir(parents=True, exist_ok=True)
    exported = []
    skipped = []
    used_names: set[str] = set()
    for transfer in transfers[: max(0, limit)]:
        transfer_records = tftp_records_for_transfer(records, transfer)
        blob = tftp_reconstructed_bytes(transfer_records)
        if not blob:
            skipped.append({"transfer_id": transfer.transfer_id, "reason": "no_reconstructed_bytes"})
            continue
        if transfer.completeness != "complete" and not include_incomplete:
            skipped.append({"transfer_id": transfer.transfer_id, "reason": f"completeness={transfer.completeness}"})
            continue
        filename = unique_export_name(safe_export_filename(transfer.filename or transfer.transfer_id, ".bin"), used_names)
        output_path = out_dir / filename
        output_path.write_bytes(blob)
        transfer.export_path = str(output_path)
        transfer.sha256 = hashlib.sha256(blob).hexdigest()
        exported.append({
            "transfer_id": transfer.transfer_id,
            "path": transfer.export_path,
            "size": len(blob),
            "sha256": transfer.sha256,
            "completeness": transfer.completeness,
        })
    return {
        "output_dir": str(out_dir),
        "exported": len(exported),
        "skipped": len(skipped),
        "exported_records": exported,
        "skipped_records": skipped,
        "status": "ok" if exported else "all_skipped" if skipped else "no_exported_objects",
    }


def tftp_records_for_transfer(records, transfer):
    frames = set(transfer.data_frames)
    request_frame = transfer.request_frame or 0
    selected = [
        record
        for record in records
        if record.frame_number in frames or (request_frame and safe_int(record.request_frame) == request_frame)
    ]
    return selected or [
        record
        for record in records
        if {record.src_ip, record.dst_ip} == {transfer.client_ip, transfer.server_ip}
    ]


def safe_export_filename(name: str, fallback_ext: str = "") -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", name).strip("._")
    if not cleaned:
        cleaned = "tftp_object"
    if fallback_ext and "." not in Path(cleaned).name:
        cleaned += fallback_ext
    return cleaned


def unique_export_name(name: str, used: set[str]) -> str:
    candidate = name
    stem = Path(name).stem
    suffix = Path(name).suffix
    counter = 1
    while candidate in used:
        counter += 1
        candidate = f"{stem}_{counter:03d}{suffix}"
    used.add(candidate)
    return candidate


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
    icmp_rows = []
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
            decoded_username = decode_base64_value(packet.smtp_auth_username)
            decoded_password = decode_base64_value(packet.smtp_auth_password)
            if packet.smtp_auth_username:
                parts.append(f"username={decoded_username or packet.smtp_auth_username}")
            if packet.smtp_auth_password:
                parts.append(f"password={decoded_password}" if decoded_password else "password field present")
            smtp_rows.append((f"frame:{packet.frame_number}", "; ".join(parts)))
        if packet.transport == "ICMP" and packet.payload_hex:
            preview = payload_preview(packet.payload_hex)
            if has_interesting_payload_preview(preview):
                icmp_rows.append((f"frame:{packet.frame_number}", preview))
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
    print_hunt_section("ICMP Payload Clues", icmp_rows, limit)
    print_hunt_section("SYN Payload Candidates", syn_payload_rows, limit)


def print_tftp_hunt_section(transfers, limit: int) -> None:
    rows = []
    for transfer in transfers:
        rows.append((
            transfer.transfer_id,
            (
                f"file={transfer.filename or '(unknown)'} direction={transfer.direction} "
                f"bytes={transfer.byte_count} completeness={transfer.completeness}"
            ),
        ))
    print_hunt_section("TFTP Transfers", rows, limit)


def has_interesting_payload_preview(text: str) -> bool:
    lowered = text.lower()
    return any(token in lowered for token in ["ssh-", "openssh", "http/", "ftp ", "smtp", "ptunnel", "flag", "ctf{"])


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
