from __future__ import annotations

import math
import base64
import re
from collections import Counter, defaultdict
from pathlib import Path

from .artifacts import detect_artifacts, score_artifact
from .capture import build_capture_record
from .evidence import build_report_evidence
from .models import (
    AnalysisReport,
    ArtifactRecord,
    CaptureSummary,
    DnsRecord,
    Finding,
    FlowRecord,
    HandoffHint,
    HttpRecord,
    InvestigationItem,
    MqttRecord,
    PacketRecord,
    SmtpRecord,
    StreamRecord,
    TimelineEvent,
    severity_from_score,
)
from .stringtools import (
    decode_interesting,
    dedupe_strings,
    detect_credentials,
    detect_flags,
    raw_file_strings,
    strings_from_payload_hex,
)
from .tshark_parser import parse_packets
from .utils import tool_version


COMMON_PORTS = {"20", "21", "22", "25", "53", "80", "110", "123", "143", "443", "445", "587", "993", "995", "3389"}
SUSPICIOUS_EXTENSIONS = (".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".sh", ".jar", ".zip", ".rar", ".7z")
CLUE_WORDS = {
    "decode",
    "base64",
    "base85",
    "hex",
    "password",
    "passwd",
    "pass:",
    "archive",
    "http://",
    "https://",
    "drive.google.com",
    "mission",
    "target",
    "template",
    "flag",
    "laporan",
}


class AnalyzeOptions:
    def __init__(
        self,
        mode: str = "triage",
        top: int = 10,
        min_risk: int = 10,
        no_ml: bool = False,
        ctf_flag: str = "",
        preview_len: int = 250,
    ) -> None:
        self.mode = mode
        self.top = top
        self.min_risk = min_risk
        self.no_ml = no_ml
        self.ctf_flag = ctf_flag
        self.preview_len = preview_len


def analyze(path: Path, options: AnalyzeOptions | None = None) -> AnalysisReport:
    options = options or AnalyzeOptions()
    capture, tools, warnings = build_capture_record(path)
    packets = parse_packets(path)
    flows = build_flows(packets)
    dns_records = build_dns_records(packets)
    http_records = build_http_records(packets)
    smtp_records = build_smtp_records(packets)
    mqtt_records = build_mqtt_records(packets)
    streams = build_streams(packets)
    payload_rows, payload_map = payload_sources(packets)
    strings = gather_strings(path, payload_rows, include_raw=True)
    artifacts = detect_artifacts(path, list(payload_map.items()), include_raw=True)
    for artifact in artifacts:
        score_artifact(artifact)
    summary = build_summary(path, packets, flows, dns_records, http_records)
    report = AnalysisReport(
        summary=summary,
        capture=capture,
        tools=tools,
        flows=flows,
        streams=streams,
        dns_records=dns_records,
        http_records=http_records,
        smtp_records=smtp_records,
        mqtt_records=mqtt_records,
        artifacts=artifacts,
        warnings=warnings,
        tool_versions={"tshark": tool_version("tshark")},
    )
    report.findings.extend(run_detectors(report, packets, strings, options))
    maybe_apply_ml(report, options)
    score_streams(report.streams, report.findings)
    report.investigation_queue = build_queue(report.findings, report.streams, report.artifacts)
    report.handoff = collect_handoff(report.findings)
    report.timeline = build_timeline(report.findings)
    build_report_evidence(report, packets, strings)
    if not report.findings:
        report.notes.append("No findings were generated. This does not prove the capture is safe.")
    add_capture_notes(report, packets)
    return report


def build_summary(path: Path, packets: list[PacketRecord], flows: list[FlowRecord], dns: list[DnsRecord], http: list[HttpRecord]) -> CaptureSummary:
    protocols = Counter(p.protocol or p.transport or "UNKNOWN" for p in packets)
    hosts = Counter()
    ports = Counter()
    conversations = Counter()
    dns_counter = Counter()
    http_hosts = Counter()
    for packet in packets:
        if packet.src_ip:
            hosts[packet.src_ip] += 1
        if packet.dst_ip:
            hosts[packet.dst_ip] += 1
        if packet.src_port:
            ports[packet.src_port] += 1
        if packet.dst_port:
            ports[packet.dst_port] += 1
        if packet.src_ip and packet.dst_ip:
            conversations[f"{packet.src_ip} -> {packet.dst_ip}"] += 1
    for record in dns:
        if record.query:
            dns_counter[record.query] += 1
    for record in http:
        if record.host:
            http_hosts[record.host] += 1
    start = min((p.timestamp for p in packets), default=0.0)
    end = max((p.timestamp for p in packets), default=0.0)
    return CaptureSummary(
        file=str(path),
        size_bytes=path.stat().st_size,
        packet_count=len(packets),
        start_time=start,
        end_time=end,
        duration=max(0.0, end - start),
        protocols=dict(protocols.most_common()),
        top_hosts=dict(hosts.most_common(20)),
        top_ports=dict(ports.most_common(20)),
        top_conversations=dict(conversations.most_common(20)),
        top_dns=dict(dns_counter.most_common(20)),
        top_http_hosts=dict(http_hosts.most_common(20)),
    )


def flow_key(packet: PacketRecord) -> tuple[str, str, str, str, str]:
    left = (packet.src_ip, packet.src_port)
    right = (packet.dst_ip, packet.dst_port)
    if left <= right:
        return (packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port, packet.transport or packet.protocol)
    return (packet.dst_ip, packet.dst_port, packet.src_ip, packet.src_port, packet.transport or packet.protocol)


def build_flows(packets: list[PacketRecord]) -> list[FlowRecord]:
    flows: dict[tuple[str, str, str, str, str], FlowRecord] = {}
    for packet in packets:
        if not packet.src_ip or not packet.dst_ip:
            continue
        key = flow_key(packet)
        flow_id = "|".join(key)
        flow = flows.setdefault(
            key,
            FlowRecord(
                flow_id=flow_id,
                src_ip=key[0],
                src_port=key[1],
                dst_ip=key[2],
                dst_port=key[3],
                protocol=key[4],
                start_time=packet.timestamp,
                end_time=packet.timestamp,
            ),
        )
        flow.packet_count += 1
        flow.byte_count += packet.length
        flow.start_time = min(flow.start_time, packet.timestamp)
        flow.end_time = max(flow.end_time, packet.timestamp)
        if packet.tcp_stream and packet.tcp_stream not in flow.tcp_streams:
            flow.tcp_streams.append(packet.tcp_stream)
        if packet.tcp_flags:
            flow.flags[packet.tcp_flags] = flow.flags.get(packet.tcp_flags, 0) + 1
    return sorted(flows.values(), key=lambda f: f.byte_count, reverse=True)


def build_dns_records(packets: list[PacketRecord]) -> list[DnsRecord]:
    return [
        DnsRecord(p.frame_number, p.timestamp, p.src_ip, p.dst_ip, p.dns_query, p.dns_answer, p.dns_rcode)
        for p in packets
        if p.dns_query or p.dns_answer or p.dns_rcode
    ]


def build_http_records(packets: list[PacketRecord]) -> list[HttpRecord]:
    return [
        HttpRecord(
            p.frame_number,
            p.timestamp,
            p.src_ip,
            p.dst_ip,
            p.http_host,
            p.http_method,
            p.http_uri,
            p.http_full_uri,
            p.http_user_agent,
            p.http_status,
            p.http_content_type,
            p.http_content_length,
            p.tcp_stream,
        )
        for p in packets
        if p.http_host or p.http_method or p.http_uri or p.http_status or p.http_content_type
    ]


def build_smtp_records(packets: list[PacketRecord]) -> list[SmtpRecord]:
    return [
        SmtpRecord(
            p.frame_number,
            p.timestamp,
            p.src_ip,
            p.dst_ip,
            p.smtp_command,
            p.smtp_parameter,
            p.smtp_response,
            p.smtp_response_code,
            p.smtp_message,
            p.smtp_auth_username,
            p.smtp_auth_password,
            p.tcp_stream,
        )
        for p in packets
        if p.smtp_command
        or p.smtp_parameter
        or p.smtp_response
        or p.smtp_response_code
        or p.smtp_message
        or p.smtp_auth_username
        or p.smtp_auth_password
    ]


def build_mqtt_records(packets: list[PacketRecord]) -> list[MqttRecord]:
    return [
        MqttRecord(
            p.frame_number,
            p.timestamp,
            p.src_ip,
            p.dst_ip,
            p.mqtt_msg_type,
            p.mqtt_topic,
            p.mqtt_message,
            p.mqtt_username,
            p.mqtt_password,
            p.tcp_stream,
        )
        for p in packets
        if p.mqtt_msg_type or p.mqtt_topic or p.mqtt_message or p.mqtt_username or p.mqtt_password
    ]


def build_streams(packets: list[PacketRecord]) -> list[StreamRecord]:
    grouped: dict[str, StreamRecord] = {}
    for p in packets:
        if not p.tcp_stream:
            continue
        stream = grouped.setdefault(
            p.tcp_stream,
            StreamRecord(
                stream_id=p.tcp_stream,
                protocol=p.transport or p.protocol,
                src_ip=p.src_ip,
                src_port=p.src_port,
                dst_ip=p.dst_ip,
                dst_port=p.dst_port,
                start_time=p.timestamp,
                end_time=p.timestamp,
            ),
        )
        stream.packet_count += 1
        stream.byte_count += p.length
        stream.start_time = min(stream.start_time, p.timestamp)
        stream.end_time = max(stream.end_time, p.timestamp)
    return sorted(grouped.values(), key=lambda s: s.byte_count, reverse=True)


def payload_sources(packets: list[PacketRecord]) -> tuple[list[tuple[str, str]], dict[str, bytes]]:
    rows: list[tuple[str, str]] = []
    payload_map: dict[str, bytes] = {}
    for p in packets:
        if not p.payload_hex:
            continue
        source = f"packet:{p.frame_number}"
        clean_hex = p.payload_hex.replace(":", "")
        rows.append((source, clean_hex))
        try:
            payload_map[source] = bytes.fromhex(clean_hex)
        except ValueError:
            pass
    return rows, payload_map


def gather_strings(path: Path, payload_hex_rows: list[tuple[str, str]], include_raw: bool = True, min_len: int = 5) -> list[tuple[str, str]]:
    rows = []
    if include_raw:
        rows.extend(raw_file_strings(path, min_len=min_len))
    rows.extend(strings_from_payload_hex(payload_hex_rows, min_len=min_len))
    return dedupe_strings(rows)


def run_detectors(report: AnalysisReport, packets: list[PacketRecord], strings: list[tuple[str, str]], options: AnalyzeOptions) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(scan_findings(report.flows))
    findings.extend(heavy_talker_findings(report.summary))
    findings.extend(http_findings(report.http_records))
    findings.extend(smtp_findings(report.smtp_records, strings))
    findings.extend(mqtt_findings(report.mqtt_records))
    findings.extend(dns_findings(report.dns_records))
    findings.extend(secret_findings(strings, options))
    findings.extend(clue_findings(strings))
    findings.extend(base64_reconstruction_findings(packets, options))
    findings.extend(artifact_findings(report.artifacts))
    findings.extend(beacon_findings(report.flows))
    findings.extend(unusual_port_findings(report.flows))
    findings.extend(icmp_findings(packets))
    findings.extend(syn_payload_findings(packets))
    filtered = [f for f in findings if f.risk_score >= options.min_risk or f.severity == "info"]
    return dedupe_findings(filtered)


def scan_findings(flows: list[FlowRecord]) -> list[Finding]:
    findings = []
    by_src_dst: dict[tuple[str, str], set[str]] = defaultdict(set)
    by_src_hosts: dict[str, set[str]] = defaultdict(set)
    for flow in flows:
        if flow.src_ip and flow.dst_ip:
            by_src_dst[(flow.src_ip, flow.dst_ip)].add(flow.dst_port)
            by_src_hosts[flow.src_ip].add(flow.dst_ip)
    for (src, dst), ports in by_src_dst.items():
        if len(ports) >= 15:
            findings.append(make_finding(
                "Possible port scan",
                "scan",
                min(90, 35 + len(ports)),
                [f"{src} contacted {len(ports)} ports on {dst}."],
                "One source contacted many destination ports on one host.",
                f"Inspect traffic from {src} to {dst}.",
                src,
                dst,
            ))
    for src, hosts in by_src_hosts.items():
        if len(hosts) >= 25:
            findings.append(make_finding(
                "Possible host sweep",
                "scan",
                min(85, 30 + len(hosts)),
                [f"{src} contacted {len(hosts)} destination hosts."],
                "One source contacted many hosts, which can indicate reconnaissance.",
                f"Inspect traffic from {src}.",
                src,
                "",
            ))
    return findings


def heavy_talker_findings(summary: CaptureSummary) -> list[Finding]:
    findings = []
    if not summary.top_hosts:
        return findings
    total = sum(summary.top_hosts.values())
    for host, count in list(summary.top_hosts.items())[:3]:
        if total and count / total >= 0.35 and count >= 20:
            findings.append(make_finding(
                "Heavy talker",
                "traffic",
                30,
                [f"{host} appears in {count} packet endpoint observations."],
                "A single host accounts for a large portion of observed traffic.",
                f"Review conversations involving {host}.",
                host,
                "",
            ))
    return findings


def http_findings(records: list[HttpRecord]) -> list[Finding]:
    findings = []
    for r in records:
        uri = r.uri or ""
        combined = " ".join([r.host, r.method, uri, r.user_agent, r.content_type])
        length = safe_int(r.content_length)
        if r.method:
            score = 25 if r.method.upper() == "GET" else 40
            if r.method.upper() == "POST":
                findings.append(make_finding(
                    "HTTP POST observed",
                    "http",
                    score,
                    [f"{r.src_ip} sent POST to {r.host}{uri}."],
                    "Plaintext HTTP POST data may contain submitted form values or uploads.",
                    f"Inspect tcp.stream == {r.stream_id} in Wireshark." if r.stream_id else "Inspect the HTTP request.",
                    r.src_ip,
                    r.dst_ip,
                    stream=r.stream_id,
                ))
        if r.status and (r.content_type or r.content_length):
            details = [f"frame {r.frame_number}: HTTP {r.status} {r.host}{uri}".strip()]
            if r.content_type:
                details.append(f"type={r.content_type}")
            if r.content_length:
                details.append(f"length={r.content_length}")
            file_like = any(token in (r.content_type or "").lower() for token in ["zip", "octet-stream", "pdf", "excel", "msword", "officedocument"])
            large_transfer = length >= 5 * 1024 * 1024
            if file_like or large_transfer:
                findings.append(make_finding(
                    "HTTP file transfer candidate",
                    "http",
                    65 if file_like else 45,
                    ["; ".join(details)],
                    "HTTP response metadata suggests a downloadable object or large transfer.",
                    f"Inspect tcp.stream == {r.stream_id} or export HTTP objects with tshark." if r.stream_id else "Inspect the HTTP response and consider exporting HTTP objects.",
                    r.src_ip,
                    r.dst_ip,
                    stream=r.stream_id,
                ))
        if r.method and r.method.upper() == "POST" and length >= 1024 * 1024:
            findings.append(make_finding(
                "Large HTTP upload observed",
                "http",
                55,
                [f"{r.src_ip} sent POST to {r.host}{uri} with declared length {r.content_length}."],
                "Large plaintext HTTP uploads are useful triage anchors for exfiltration, forms, or CTF artifact submission.",
                f"Inspect tcp.stream == {r.stream_id} and multipart metadata." if r.stream_id else "Inspect the HTTP POST request.",
                r.src_ip,
                r.dst_ip,
                stream=r.stream_id,
            ))
        if any(ext in uri.lower() for ext in SUSPICIOUS_EXTENSIONS):
            findings.append(make_finding(
                "Suspicious HTTP file path",
                "http",
                60,
                [f"HTTP path references suspicious file extension: {r.host}{uri}"],
                "Executable, archive, or script downloads can be important artifacts.",
                "Review the HTTP object and related stream.",
                r.src_ip,
                r.dst_ip,
                stream=r.stream_id,
            ))
        if "authorization:" in combined.lower() or "password" in combined.lower() or "token" in combined.lower():
            findings.append(make_finding(
                "Possible credential in HTTP metadata",
                "secret",
                75,
                [f"Credential-like HTTP metadata near frame {r.frame_number}."],
                "Credentials over plaintext HTTP can be exposed in the capture.",
                f"Inspect frame {r.frame_number} and related stream.",
                r.src_ip,
                r.dst_ip,
                stream=r.stream_id,
            ))
    if records:
        findings.append(make_finding(
            "Plaintext HTTP observed",
            "http",
            25,
            [f"{len(records)} HTTP metadata records were parsed."],
            "Plaintext HTTP traffic can expose URLs, headers, forms, and files.",
            "Review the HTTP summary and interesting streams.",
        ))
    return findings


def smtp_findings(records: list[SmtpRecord], strings: list[tuple[str, str]]) -> list[Finding]:
    findings = []
    if records:
        senders = sorted({r.parameter for r in records if r.command.upper() in {"MAIL", "MAIL FROM"} and r.parameter})
        recipients = sorted({r.parameter for r in records if r.command.upper() in {"RCPT", "RCPT TO"} and r.parameter})
        evidence = []
        if senders:
            evidence.append(f"senders: {', '.join(senders[:5])}")
        if recipients:
            evidence.append(f"recipients: {', '.join(recipients[:5])}")
        if not evidence:
            evidence.append(f"{len(records)} SMTP records parsed.")
        findings.append(make_finding(
            "SMTP/email traffic observed",
            "smtp",
            35,
            evidence,
            "Plaintext email can expose URLs, attachments, subjects, and passwords.",
            "Review SMTP streams and email bodies.",
        ))
    for source, text in email_clue_rows(strings)[:10]:
        findings.append(make_finding(
            "Email clue found",
            "smtp",
            65 if "pass" in text.lower() or "http://" in text.lower() else 45,
            [f"{source}: {truncate(text, 250)}"],
            "Email content contains a URL, subject, sender/recipient, or password-like clue.",
            "Correlate the email with HTTP downloads or extracted artifacts.",
            related=source,
        ))
    return findings


def mqtt_findings(records: list[MqttRecord]) -> list[Finding]:
    findings = []
    for record in records[:30]:
        evidence = []
        if record.topic:
            evidence.append(f"topic={record.topic}")
        if record.message:
            evidence.append(f"message={truncate(record.message, 180)}")
        if record.username:
            evidence.append(f"username={record.username}")
        if record.password:
            evidence.append("password field present")
        if not evidence:
            continue
        score = 45
        combined = " ".join(evidence).lower()
        if any(word in combined for word in CLUE_WORDS):
            score = 65
        findings.append(make_finding(
            "MQTT message/topic observed",
            "mqtt",
            score,
            [f"frame {record.frame_number}: " + "; ".join(evidence)],
            "MQTT topics and messages are common places for CTF instructions or IoT evidence.",
            f"Inspect tcp.stream == {record.stream_id}." if record.stream_id else "Inspect MQTT packets and payloads.",
            record.src_ip,
            record.dst_ip,
            stream=record.stream_id,
        ))
    return findings


def dns_findings(records: list[DnsRecord]) -> list[Finding]:
    findings = []
    by_src = Counter(r.src_ip for r in records if r.src_ip)
    nxdomain = Counter(r.src_ip for r in records if r.rcode and r.rcode not in {"0", "NoError"})
    for record in records:
        query = record.query or ""
        labels = query.split(".")
        longest = max((len(label) for label in labels), default=0)
        if len(query) > 80 or longest > 45 or entropy(query) > 4.2:
            findings.append(make_finding(
                "Suspicious DNS query shape",
                "dns",
                55,
                [f"Query from {record.src_ip}: {query}"],
                "Long or high-entropy DNS names may indicate tunneling or encoded data.",
                f"Inspect DNS traffic from {record.src_ip}.",
                record.src_ip,
                record.dst_ip,
            ))
    for src, count in by_src.items():
        if count >= 50:
            findings.append(make_finding(
                "DNS-heavy host",
                "dns",
                35,
                [f"{src} made {count} DNS-related requests/responses."],
                "High DNS volume can be normal, but it is worth checking in unknown captures.",
                f"Review DNS queries from {src}.",
                src,
                "",
            ))
    for src, count in nxdomain.items():
        if count >= 10:
            findings.append(make_finding(
                "Repeated DNS failures",
                "dns",
                45,
                [f"{src} had {count} non-success DNS response codes."],
                "Repeated failed lookups can indicate typo-squatting, DGA behavior, or failed challenge clues.",
                f"Review failed DNS queries from {src}.",
                src,
                "",
            ))
    return findings


def secret_findings(rows: list[tuple[str, str]], options: AnalyzeOptions) -> list[Finding]:
    findings = []
    flag_hits = detect_flags(rows, options.ctf_flag)
    for source, text in flag_hits[:20]:
        score = 95 if options.mode == "ctf" else 70
        findings.append(make_finding(
            "Flag-like string found",
            "ctf",
            score,
            [f"{source}: {truncate(text, 250)}"],
            "A string matched a known or custom CTF flag pattern.",
            "Verify the string and use it in the challenge workflow.",
            related=source,
        ))
    cred_hits = detect_credentials(rows)
    for source, text in cred_hits[:30]:
        findings.append(make_finding(
            "Credential-like string found",
            "secret",
            75,
            [f"{source}: {truncate(text, 250)}"],
            "The capture contains a password, token, authorization header, or similar value candidate.",
            "Inspect the surrounding stream or packet context.",
            related=source,
        ))
    decoded_count = 0
    for source, text in rows:
        for decoded in decode_interesting(text):
            decoded_count += 1
            if decoded_count > 20:
                break
            findings.append(make_finding(
                "Encoded-looking string decoded",
                "ctf",
                40 if options.mode == "ctf" else 25,
                [f"{source}: {truncate(decoded, 250)}"],
                "A base64-like or hex-like value decoded into mostly printable text.",
                "Review the decoded value and surrounding context.",
                related=source,
            ))
    return findings


def clue_findings(rows: list[tuple[str, str]]) -> list[Finding]:
    findings = []
    for source, text in clue_rows(rows)[:25]:
        score = 55
        lowered = text.lower()
        if "password" in lowered or "pass:" in lowered or "http://" in lowered or "https://" in lowered:
            score = 65
        findings.append(make_finding(
            "Possible clue string",
            "ctf",
            score,
            [f"{source}: {truncate(text, 250)}"],
            "The string contains clue-like words such as decode, password, archive, URL, or flag.",
            "Inspect nearby packets or streams and correlate with artifacts.",
            related=source,
        ))
    return findings


def clue_rows(rows: list[tuple[str, str]]) -> list[tuple[str, str]]:
    hits = []
    seen = set()
    for source, text in rows:
        compact = " ".join(text.split())
        lowered = compact.lower()
        if any(word in lowered for word in CLUE_WORDS):
            key = (source, compact[:250])
            if key not in seen:
                seen.add(key)
                hits.append((source, compact))
    return hits


def email_clue_rows(rows: list[tuple[str, str]]) -> list[tuple[str, str]]:
    email_terms = ("from:", "to:", "subject:", "mail from:", "rcpt to:", "smtp", "pass:", "password")
    hits = []
    seen = set()
    for source, text in rows:
        compact = " ".join(text.split())
        lowered = compact.lower()
        if any(term in lowered for term in email_terms) and ("@" in compact or "subject:" in lowered or "pass" in lowered):
            key = (source, compact[:250])
            if key not in seen:
                seen.add(key)
                hits.append((source, compact))
    return hits


def base64_reconstruction_findings(packets: list[PacketRecord], options: AnalyzeOptions) -> list[Finding]:
    findings = []
    candidates = decoded_payload_fragments(packets)
    if len(candidates) < 2:
        return findings
    for label, ordered in [
        ("timestamp order", sorted(candidates, key=lambda item: (item[0].timestamp, item[0].frame_number))),
        ("frame order", sorted(candidates, key=lambda item: item[0].frame_number)),
    ]:
        reconstructed = "".join(text for _, _, text in ordered)
        if not reconstructed:
            continue
        score = 70 if options.mode == "ctf" else 50
        if detect_flags([("reconstructed", reconstructed)], options.ctf_flag):
            score = 95
        findings.append(make_finding(
            f"Reconstructed base64 payload fragments ({label})",
            "ctf",
            score,
            [truncate(reconstructed, 300)],
            "Multiple packet payloads decode as base64 fragments and can be concatenated for CTF/covert-channel analysis.",
            "Verify both timestamp and frame order if the capture is not strictly time ordered.",
            related="payload-fragments",
        ))
    return findings


def decoded_payload_fragments(packets: list[PacketRecord]) -> list[tuple[PacketRecord, str, str]]:
    results = []
    for packet in packets:
        if not packet.payload_hex:
            continue
        try:
            payload = bytes.fromhex(packet.payload_hex.replace(":", ""))
        except ValueError:
            continue
        text = payload.decode("utf-8", errors="ignore").strip()
        if not re.fullmatch(r"[A-Za-z0-9+/]{2,}={0,2}", text):
            continue
        try:
            raw = base64.b64decode(text + "=" * (-len(text) % 4), validate=True)
        except Exception:
            continue
        if not raw or any(byte not in b"\t\r\n" and (byte < 32 or byte > 126) for byte in raw):
            continue
        decoded = raw.decode("utf-8", errors="ignore")
        useful = sum(ch.isalpha() or ch.isdigit() or ch in "{}_:-" for ch in decoded)
        if decoded and useful >= 1:
            results.append((packet, text, decoded))
    return results


def artifact_findings(artifacts: list[ArtifactRecord]) -> list[Finding]:
    findings = []
    for artifact in sorted(artifacts, key=lambda a: a.score, reverse=True)[:30]:
        if artifact.score < 20:
            continue
        findings.append(make_finding(
            "Embedded file signature found",
            "artifact",
            artifact.score,
            [f"{artifact.kind} at offset {artifact.offset} in {artifact.source} ({artifact.validation}).", "; ".join(artifact.reasons + artifact.tags)],
            "A known file magic byte signature was detected.",
            "Run extract or inspect the artifact entry.",
            related=artifact.artifact_id,
        ))
    return findings


def beacon_findings(flows: list[FlowRecord]) -> list[Finding]:
    findings = []
    by_dst = defaultdict(list)
    for flow in flows:
        if flow.src_ip and flow.dst_ip:
            by_dst[(flow.src_ip, flow.dst_ip, flow.dst_port)].append(flow)
    for (src, dst, port), grouped in by_dst.items():
        if len(grouped) >= 5:
            sizes = [f.byte_count for f in grouped]
            if max(sizes) - min(sizes) <= max(1000, int(sum(sizes) / len(sizes))):
                findings.append(make_finding(
                    "Beacon candidate",
                    "beacon",
                    45,
                    [f"{len(grouped)} similar flows from {src} to {dst}:{port}."],
                    "Repeated similar connections can be a beaconing candidate.",
                    f"Inspect repeated traffic from {src} to {dst}:{port}.",
                    src,
                    dst,
                ))
    return findings


def unusual_port_findings(flows: list[FlowRecord]) -> list[Finding]:
    findings = []
    for flow in flows[:100]:
        ports = {flow.src_port, flow.dst_port}
        if flow.packet_count >= 3 and not ports.intersection(COMMON_PORTS):
            findings.append(make_finding(
                "Unusual port conversation",
                "traffic",
                25,
                [f"{flow.src_ip}:{flow.src_port} <-> {flow.dst_ip}:{flow.dst_port} ({flow.packet_count} packets)."],
                "The conversation does not use common service ports.",
                "Review whether this protocol is expected.",
                flow.src_ip,
                flow.dst_ip,
            ))
    return findings[:10]


def icmp_findings(packets: list[PacketRecord]) -> list[Finding]:
    count = sum(1 for p in packets if p.transport == "ICMP")
    payload = sum(1 for p in packets if p.transport == "ICMP" and p.payload_hex)
    if count and payload:
        return [make_finding(
            "ICMP payload data observed",
            "icmp",
            25,
            [f"{payload} of {count} ICMP packets include data payload fields."],
            "ICMP payloads can be normal, but CTF challenges sometimes hide data there.",
            "Inspect ICMP packets and payload strings.",
        )]
    return []


def syn_payload_findings(packets: list[PacketRecord]) -> list[Finding]:
    hits = []
    for packet in packets:
        if not tcp_syn(packet.tcp_flags):
            continue
        length = safe_int(packet.tcp_len)
        if length <= 0 and not packet.payload_hex:
            continue
        preview = ""
        if packet.payload_hex:
            try:
                preview = bytes.fromhex(packet.payload_hex.replace(":", "")).decode("utf-8", errors="ignore")
            except ValueError:
                preview = packet.payload_hex[:80]
        hits.append(f"frame {packet.frame_number} {packet.src_ip}:{packet.src_port} -> {packet.dst_ip}:{packet.dst_port} len={length} payload={truncate(preview, 80)}")
    if not hits:
        return []
    return [make_finding(
        "TCP SYN packets carrying payload",
        "ctf",
        75,
        hits[:10],
        "TCP SYN packets normally do not carry application payload. This can indicate a covert channel or CTF encoding trick.",
        "Inspect the listed frames and reconstruct payloads in timestamp order.",
    )]


def make_finding(
    title: str,
    category: str,
    score: int,
    evidence: list[str],
    explanation: str,
    next_step: str,
    src: str = "",
    dst: str = "",
    related: str = "",
    stream: str = "",
) -> Finding:
    hints = []
    if src and dst:
        hints.append(HandoffHint("wireshark", "Filter related hosts", f"ip.addr == {src} && ip.addr == {dst}", related))
        hints.append(HandoffHint("tcpdump", "Filter related hosts", f"host {src} and host {dst}", related))
    if stream:
        hints.append(HandoffHint("wireshark", "Open stream", f"tcp.stream == {stream}", related))
    return Finding(
        title=title,
        category=category,
        risk_score=max(0, min(100, score)),
        severity=severity_from_score(score),
        evidence=evidence,
        explanation=explanation,
        next_step=next_step,
        src_ip=src,
        dst_ip=dst,
        related=related or (f"tcp.stream:{stream}" if stream else ""),
        handoff=hints,
    )


def maybe_apply_ml(report: AnalysisReport, options: AnalyzeOptions) -> None:
    if options.no_ml:
        report.skipped.append("ML anomaly scoring disabled by user.")
        return
    if len(report.flows) < 8:
        report.skipped.append("ML anomaly scoring skipped: not enough flows.")
        return
    try:
        from sklearn.ensemble import IsolationForest
    except Exception:
        report.skipped.append("ML anomaly scoring skipped: scikit-learn is not installed.")
        return
    matrix = [[f.packet_count, f.byte_count, f.duration, int(f.src_port or 0), int(f.dst_port or 0)] for f in report.flows]
    try:
        model = IsolationForest(random_state=42, contamination="auto")
        scores = model.fit_predict(matrix)
        decision = model.decision_function(matrix)
    except Exception as exc:
        report.skipped.append(f"ML anomaly scoring skipped: {exc}")
        return
    for flow, pred, raw_score in zip(report.flows, scores, decision):
        flow.anomaly_score = float(raw_score)
        if pred == -1:
            report.findings.append(make_finding(
                "ML anomaly candidate",
                "ml",
                35,
                [f"Flow {flow.flow_id} is unusual compared with other flows in this capture."],
                "ML anomaly scoring marked this flow as unusual relative to this PCAP.",
                "Inspect the flow and compare it with the rest of the capture.",
                flow.src_ip,
                flow.dst_ip,
                related=flow.flow_id,
            ))


def score_streams(streams: list[StreamRecord], findings: list[Finding]) -> None:
    related = Counter(f.related.replace("tcp.stream:", "") for f in findings if f.related.startswith("tcp.stream:"))
    for stream in streams:
        stream.interest_score = min(100, int(stream.byte_count / 1000) + related.get(stream.stream_id, 0) * 20)
        if related.get(stream.stream_id):
            stream.tags.append("finding-related")
        if stream.byte_count > 100000:
            stream.tags.append("large")
    streams.sort(key=lambda s: s.interest_score, reverse=True)


def build_queue(findings: list[Finding], streams: list[StreamRecord], artifacts: list[ArtifactRecord]) -> list[InvestigationItem]:
    items: list[InvestigationItem] = []
    for finding in sorted(findings, key=lambda f: f.risk_score, reverse=True)[:20]:
        items.append(InvestigationItem(
            priority=finding.severity,
            reason=finding.title,
            related=finding.related,
            evidence_summary="; ".join(finding.evidence[:2]),
            suggested_action=finding.next_step,
            handoff=finding.handoff,
        ))
    for artifact in sorted(artifacts, key=lambda a: a.score, reverse=True)[:5]:
        if artifact.score >= 20:
            items.append(InvestigationItem(
                priority=severity_from_score(artifact.score),
                reason=f"Review {artifact.kind} artifact",
                related=artifact.artifact_id,
                evidence_summary=f"{artifact.kind} at {artifact.source} offset {artifact.offset}",
                suggested_action="Run extract or inspect the artifact metadata.",
            ))
    return items[:20]


def collect_handoff(findings: list[Finding]) -> list[HandoffHint]:
    hints = []
    seen = set()
    for finding in findings:
        for hint in finding.handoff:
            key = (hint.tool, hint.text)
            if key not in seen:
                seen.add(key)
                hints.append(hint)
    return hints


def build_timeline(findings: list[Finding]) -> list[TimelineEvent]:
    return [TimelineEvent(0.0, f.title, "; ".join(f.evidence[:1]), f.severity) for f in sorted(findings, key=lambda f: f.risk_score, reverse=True)[:20]]


def add_capture_notes(report: AnalysisReport, packets: list[PacketRecord]) -> None:
    stacks = " ".join(p.protocol_stack.lower() for p in packets[:2000])
    has_ip = any(p.src_ip or p.dst_ip for p in packets)
    if "usb" in stacks and not has_ip:
        report.notes.append("This appears to be a USB/non-network capture. Network-focused DNS/HTTP/stream views may be empty; inspect USB/HID data with Wireshark or USB-focused tools.")


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    deduped: list[Finding] = []
    seen: dict[tuple[str, str, str, str], Finding] = {}
    for finding in sorted(findings, key=lambda f: f.risk_score, reverse=True):
        evidence_key = " ".join(finding.evidence[:1]).lower()
        key = (finding.category, finding.title, evidence_key[:180], finding.related)
        existing = seen.get(key)
        if existing:
            if finding.risk_score > existing.risk_score:
                existing.risk_score = finding.risk_score
                existing.severity = finding.severity
            continue
        seen[key] = finding
        deduped.append(finding)
    return deduped


def safe_int(value: str) -> int:
    if not value:
        return 0
    try:
        return int(str(value).split(",", 1)[0].strip())
    except ValueError:
        return 0


def tcp_syn(flags: str) -> bool:
    if not flags:
        return False
    try:
        return bool(int(flags, 16) & 0x02)
    except ValueError:
        return "syn" in flags.lower()


def entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def truncate(text: str, limit: int) -> str:
    compact = " ".join(text.split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 3] + "..."
