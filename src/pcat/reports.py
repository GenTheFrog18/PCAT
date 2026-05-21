from __future__ import annotations

import csv
import html
import json
from pathlib import Path

from .errors import ReportWriteError
from .models import AnalysisReport, to_plain


def render_terminal(report: AnalysisReport, top: int = 10) -> str:
    lines: list[str] = []
    s = report.summary
    lines.append("PCAT - PCAP Assistant for Triage")
    lines.append("=" * 38)
    lines.append(f"Schema: {report.schema_version}")
    lines.append(f"File: {s.file}")
    if report.capture and report.capture.sha256:
        lines.append(f"SHA256: {report.capture.sha256}")
    lines.append(f"Size: {s.size_bytes:,} bytes")
    lines.append(f"Packets: {s.packet_count:,}")
    lines.append(f"Duration: {s.duration:.2f}s")
    lines.append("")
    lines.append(f"Showing top {top} results in terminal output. Use --top N to change this.")
    lines.append("")
    lines.extend(section_counter("Protocols", s.protocols, top))
    lines.extend(section_counter("Top Hosts", s.top_hosts, top))
    lines.extend(section_counter("Top Ports", s.top_ports, top))
    lines.extend(section_counter("Top DNS Queries", s.top_dns, top))
    lines.extend(section_counter("Top HTTP Hosts", s.top_http_hosts, top))
    lines.extend(render_queue(report, top))
    lines.extend(render_evidence(report, top))
    lines.extend(render_findings(report, top))
    lines.extend(render_handoff(report, top))
    if report.warnings:
        lines.append("")
        lines.append("Warnings")
        lines.append("-" * 8)
        for warning in report.warnings[:top]:
            detail = f" ({warning.detail})" if warning.detail else ""
            lines.append(f"- [{warning.stage}] {warning.message}{detail}")
    if report.skipped:
        lines.append("")
        lines.append("Skipped Capabilities")
        lines.append("-" * 20)
        lines.extend(f"- {item}" for item in report.skipped)
    if report.notes:
        lines.append("")
        lines.append("Notes")
        lines.append("-" * 5)
        lines.extend(f"- {item}" for item in report.notes)
    lines.append("")
    lines.append("Warning: PCAP reports may contain sensitive data captured from network traffic.")
    return "\n".join(lines)


def section_counter(title: str, values: dict[str, int], top: int) -> list[str]:
    if not values:
        return []
    lines = ["", title, "-" * len(title)]
    width = max([len(str(k)) for k in list(values)[:top]] + [4])
    for key, value in list(values.items())[:top]:
        lines.append(f"{str(key):<{width}}  {value}")
    return lines


def render_queue(report: AnalysisReport, top: int) -> list[str]:
    if not report.investigation_queue:
        return []
    lines = ["", "Investigation Queue", "-" * 19]
    for idx, item in enumerate(report.investigation_queue[:top], start=1):
        lines.append(f"{idx}. [{item.priority}] {item.reason}")
        lines.append(f"   Evidence: {item.evidence_summary}")
        lines.append(f"   Next: {item.suggested_action}")
        for hint in item.handoff[:2]:
            lines.append(f"   {hint.tool}: {hint.text}")
    return lines


def render_findings(report: AnalysisReport, top: int) -> list[str]:
    if not report.findings:
        return ["", "Top Findings", "-" * 12, "No high-priority findings were found."]
    lines = ["", "Top Findings", "-" * 12]
    for idx, finding in enumerate(sorted(report.findings, key=lambda f: f.risk_score, reverse=True)[:top], start=1):
        lines.append(f"{idx}. [{finding.severity}] {finding.title} ({finding.risk_score}/100)")
        lines.append(f"   Category: {finding.category}")
        if finding.explanation:
            lines.append(f"   Why: {finding.explanation}")
        if finding.evidence:
            lines.append(f"   Evidence: {'; '.join(finding.evidence[:2])}")
        if finding.next_step:
            lines.append(f"   Next: {finding.next_step}")
    return lines


def render_evidence(report: AnalysisReport, top: int) -> list[str]:
    if not report.evidence:
        return []
    lines = ["", "Evidence Highlights", "-" * 19]
    for item in report.evidence[:top]:
        location = []
        if item.frame_start:
            location.append(f"frame={item.frame_start}")
        if item.stream_id:
            location.append(f"stream={item.stream_id}")
        suffix = f" ({', '.join(location)})" if location else ""
        lines.append(f"- [{item.type}] {item.preview}{suffix}")
    return lines


def render_handoff(report: AnalysisReport, top: int) -> list[str]:
    if not report.handoff:
        return []
    lines = ["", "Tool Handoff Hints", "-" * 18]
    for hint in report.handoff[:top]:
        lines.append(f"- {hint.tool}: {hint.text} ({hint.purpose})")
    return lines


def write_reports(report: AnalysisReport, out_dir: Path, formats: set[str]) -> list[Path]:
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        written: list[Path] = []
        if "json" in formats:
            report_path = out_dir / "report.json"
            report_path.write_text(json.dumps(to_plain(report), indent=2), encoding="utf-8")
            written.append(report_path)
            findings_path = out_dir / "findings.json"
            findings_path.write_text(json.dumps(to_plain(report.findings), indent=2), encoding="utf-8")
            written.append(findings_path)
            evidence_path = out_dir / "evidence.json"
            evidence_path.write_text(json.dumps(to_plain(report.evidence), indent=2), encoding="utf-8")
            written.append(evidence_path)
        if "csv" in formats:
            for name, writer in [
                ("flows.csv", write_flows_csv),
                ("hosts.csv", write_hosts_csv),
                ("dns.csv", write_dns_csv),
                ("http.csv", write_http_csv),
                ("artifacts.csv", write_artifacts_csv),
                ("findings.csv", write_findings_csv),
            ]:
                path = out_dir / name
                writer(report, path)
                written.append(path)
        if "html" in formats:
            path = out_dir / "report.html"
            path.write_text(render_html(report), encoding="utf-8")
            written.append(path)
        if "md" in formats or "markdown" in formats:
            path = out_dir / "report.md"
            path.write_text(render_markdown(report), encoding="utf-8")
            written.append(path)
        if "txt" in formats or "plaintext" in formats:
            path = out_dir / "report.txt"
            path.write_text(render_terminal(report, top=9999), encoding="utf-8")
            written.append(path)
        return written
    except OSError as exc:
        raise ReportWriteError(f"Could not write report files: {exc}") from exc


def write_flows_csv(report: AnalysisReport, path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["flow_id", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "packets", "bytes", "duration", "tags", "anomaly_score"])
        for flow in report.flows:
            writer.writerow([
                flow.flow_id,
                flow.src_ip,
                flow.src_port,
                flow.dst_ip,
                flow.dst_port,
                flow.protocol,
                flow.packet_count,
                flow.byte_count,
                f"{flow.duration:.6f}",
                ";".join(flow.tags),
                "" if flow.anomaly_score is None else flow.anomaly_score,
            ])


def write_hosts_csv(report: AnalysisReport, path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["host", "count"])
        for host, count in report.summary.top_hosts.items():
            writer.writerow([host, count])


def write_dns_csv(report: AnalysisReport, path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["frame", "timestamp", "src_ip", "dst_ip", "query", "answer", "rcode"])
        for record in report.dns_records:
            writer.writerow([record.frame_number, f"{record.timestamp:.6f}", record.src_ip, record.dst_ip, record.query, record.answer, record.rcode])


def write_http_csv(report: AnalysisReport, path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["frame", "timestamp", "stream_id", "src_ip", "dst_ip", "host", "method", "uri", "status", "content_type", "content_length", "user_agent"])
        for record in report.http_records:
            writer.writerow([
                record.frame_number,
                f"{record.timestamp:.6f}",
                record.stream_id,
                record.src_ip,
                record.dst_ip,
                record.host,
                record.method,
                record.full_uri or record.uri,
                record.status,
                record.content_type,
                record.content_length,
                record.user_agent,
            ])


def write_artifacts_csv(report: AnalysisReport, path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["artifact_id", "kind", "source", "offset", "filename", "path", "size", "sha256", "validation", "score", "tags"])
        for artifact in report.artifacts:
            writer.writerow([
                artifact.artifact_id,
                artifact.kind,
                artifact.source,
                artifact.offset,
                artifact.filename,
                artifact.path,
                artifact.size,
                artifact.sha256,
                artifact.validation,
                artifact.score,
                ";".join(artifact.tags),
            ])


def write_findings_csv(report: AnalysisReport, path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["finding_id", "title", "category", "severity", "risk_score", "confidence", "related", "evidence_ids", "next_step"])
        for finding in report.findings:
            writer.writerow([
                finding.finding_id,
                finding.title,
                finding.category,
                finding.severity,
                finding.risk_score,
                finding.confidence,
                finding.related,
                ";".join(finding.evidence_ids),
                finding.next_step,
            ])


def render_markdown(report: AnalysisReport) -> str:
    s = report.summary
    lines = [
        "# PCAT Report",
        "",
        "## Executive Summary",
        "",
        f"- File: `{s.file}`",
        f"- Schema: `{report.schema_version}`",
        f"- SHA256: `{report.capture.sha256 if report.capture else ''}`",
        f"- Packets: `{s.packet_count}`",
        f"- Duration: `{s.duration:.2f}s`",
        f"- Findings: `{len(report.findings)}`",
        f"- Artifacts: `{len(report.artifacts)}`",
        f"- Evidence records: `{len(report.evidence)}`",
        "",
        "## Investigation Queue",
        "",
    ]
    if report.investigation_queue:
        for idx, item in enumerate(report.investigation_queue, start=1):
            lines.append(f"{idx}. **{item.reason}** [{item.priority}] - {item.suggested_action}")
    else:
        lines.append("No high-priority investigation items were generated.")
    lines.extend(["", "## Evidence Highlights", ""])
    if report.evidence:
        for item in report.evidence[:25]:
            lines.append(f"- `{item.type}`: {item.preview}")
    else:
        lines.append("No structured evidence records were generated.")
    lines.extend(["", "## Findings", ""])
    for finding in sorted(report.findings, key=lambda f: f.risk_score, reverse=True):
        lines.append(f"### {finding.title}")
        lines.append(f"- Severity: `{finding.severity}`")
        lines.append(f"- Risk: `{finding.risk_score}/100`")
        lines.append(f"- Explanation: {finding.explanation}")
        lines.append(f"- Next step: {finding.next_step}")
        for evidence in finding.evidence:
            lines.append(f"- Evidence: `{evidence}`")
        lines.append("")
    lines.extend(["## Limitations / Skipped Capabilities", ""])
    if report.skipped:
        lines.extend(f"- {item}" for item in report.skipped)
    else:
        lines.append("- None recorded.")
    lines.append("")
    lines.append("> Warning: PCAP reports may contain sensitive network data.")
    return "\n".join(lines)


def render_html(report: AnalysisReport) -> str:
    md = render_markdown(report)
    body_lines = []
    for line in md.splitlines():
        escaped = html.escape(line)
        if line.startswith("# "):
            body_lines.append(f"<h1>{html.escape(line[2:])}</h1>")
        elif line.startswith("## "):
            body_lines.append(f"<h2>{html.escape(line[3:])}</h2>")
        elif line.startswith("### "):
            body_lines.append(f"<h3>{html.escape(line[4:])}</h3>")
        elif line.startswith("- "):
            body_lines.append(f"<li>{html.escape(line[2:])}</li>")
        elif line.startswith("> "):
            body_lines.append(f"<blockquote>{html.escape(line[2:])}</blockquote>")
        elif line.strip():
            body_lines.append(f"<p>{escaped}</p>")
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>PCAT Report</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 960px; margin: 32px auto; line-height: 1.5; color: #1f2933; }
    h1, h2, h3 { color: #102a43; }
    code { background: #f0f4f8; padding: 2px 4px; border-radius: 3px; }
    li { margin: 4px 0; }
    blockquote { border-left: 4px solid #bcccdc; padding-left: 12px; color: #52606d; }
  </style>
</head>
<body>
""" + "\n".join(body_lines) + "\n</body>\n</html>\n"
