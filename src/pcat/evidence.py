from __future__ import annotations

import hashlib
import re
from typing import Any

from .models import (
    AnalysisReport,
    ArtifactRecord,
    DnsRecord,
    EvidenceRecord,
    Finding,
    FlowRecord,
    HttpRecord,
    MqttRecord,
    PacketRecord,
    SmtpRecord,
    StreamRecord,
)
from .stringtools import decode_interesting, detect_credentials, detect_flags


def stable_id(*parts: object) -> str:
    text = "|".join("" if part is None else str(part) for part in parts)
    return hashlib.sha1(text.encode("utf-8", errors="ignore")).hexdigest()[:16]


def build_report_evidence(
    report: AnalysisReport,
    packets: list[PacketRecord],
    strings: list[tuple[str, str]],
) -> None:
    evidence: list[EvidenceRecord] = []
    evidence.extend(flow_evidence(report.flows))
    evidence.extend(stream_evidence(report.streams))
    evidence.extend(dns_evidence(report.dns_records))
    evidence.extend(http_evidence(report.http_records))
    evidence.extend(smtp_evidence(report.smtp_records))
    evidence.extend(mqtt_evidence(report.mqtt_records))
    evidence.extend(payload_weirdness_evidence(packets))
    evidence.extend(string_evidence(strings))
    evidence.extend(artifact_evidence(report.artifacts))
    report.evidence = dedupe_evidence(evidence)
    report.hosts = [{"host": host, "count": count} for host, count in report.summary.top_hosts.items()]
    report.conversations = [{"conversation": conv, "count": count} for conv, count in report.summary.top_conversations.items()]
    link_findings_to_evidence(report)


def flow_evidence(flows: list[FlowRecord]) -> list[EvidenceRecord]:
    records = []
    for flow in flows[:200]:
        records.append(EvidenceRecord(
            evidence_id=stable_id("flow", flow.flow_id),
            type="flow",
            source_module="flows",
            protocol=flow.protocol,
            timestamp=flow.start_time,
            src_ip=flow.src_ip,
            src_port=flow.src_port,
            dst_ip=flow.dst_ip,
            dst_port=flow.dst_port,
            fields={
                "flow_id": flow.flow_id,
                "packet_count": flow.packet_count,
                "byte_count": flow.byte_count,
                "duration": flow.duration,
                "tcp_streams": flow.tcp_streams,
            },
            preview=f"{flow.src_ip}:{flow.src_port} <-> {flow.dst_ip}:{flow.dst_port} packets={flow.packet_count} bytes={flow.byte_count}",
            confidence="high",
            confidence_score=0.9,
            handoff_filters=host_filters(flow.src_ip, flow.dst_ip),
        ))
    return records


def stream_evidence(streams: list[StreamRecord]) -> list[EvidenceRecord]:
    records = []
    for stream in streams[:200]:
        records.append(EvidenceRecord(
            evidence_id=stable_id("stream", stream.stream_id),
            type="stream",
            source_module="streams",
            protocol=stream.protocol,
            timestamp=stream.start_time,
            stream_id=stream.stream_id,
            src_ip=stream.src_ip,
            src_port=stream.src_port,
            dst_ip=stream.dst_ip,
            dst_port=stream.dst_port,
            fields={
                "packet_count": stream.packet_count,
                "byte_count": stream.byte_count,
                "duration": stream.duration,
                "tags": stream.tags,
                "interest_score": stream.interest_score,
            },
            preview=f"tcp.stream {stream.stream_id} {stream.src_ip}:{stream.src_port} -> {stream.dst_ip}:{stream.dst_port}",
            confidence="high",
            confidence_score=0.9,
            handoff_filters=[f"tcp.stream == {stream.stream_id}"],
        ))
    return records


def dns_evidence(records: list[DnsRecord]) -> list[EvidenceRecord]:
    return [
        EvidenceRecord(
            evidence_id=stable_id("dns", r.frame_number, r.query, r.answer, r.rcode),
            type="dns_query",
            source_module="protocols.dns",
            protocol="DNS",
            timestamp=r.timestamp,
            frame_start=r.frame_number,
            frame_end=r.frame_number,
            src_ip=r.src_ip,
            dst_ip=r.dst_ip,
            fields={"query": r.query, "answer": r.answer, "rcode": r.rcode},
            preview=f"{r.query} -> {r.answer or r.rcode}",
            confidence="high",
            confidence_score=0.9,
            handoff_filters=[f"frame.number == {r.frame_number}"],
        )
        for r in records[:500]
    ]


def http_evidence(records: list[HttpRecord]) -> list[EvidenceRecord]:
    evidence = []
    for r in records[:500]:
        is_upload = r.method.upper() == "POST" and safe_int(r.content_length) >= 1024 * 1024
        is_download = bool(r.status and (r.content_type or r.content_length))
        ev_type = "http_upload" if is_upload else "http_download" if is_download else "http_request"
        evidence.append(EvidenceRecord(
            evidence_id=stable_id(ev_type, r.frame_number, r.stream_id, r.method, r.host, r.uri, r.status),
            type=ev_type,
            source_module="protocols.http",
            protocol="HTTP",
            timestamp=r.timestamp,
            frame_start=r.frame_number,
            frame_end=r.frame_number,
            stream_id=r.stream_id,
            src_ip=r.src_ip,
            dst_ip=r.dst_ip,
            fields={
                "host": r.host,
                "method": r.method,
                "uri": r.uri,
                "full_uri": r.full_uri,
                "user_agent": r.user_agent,
                "status": r.status,
                "content_type": r.content_type,
                "content_length": r.content_length,
            },
            preview=f"{r.method or 'HTTP'} {r.full_uri or (r.host + r.uri)} status={r.status} type={r.content_type} length={r.content_length}".strip(),
            confidence="high",
            confidence_score=0.9,
            handoff_filters=stream_or_frame_filter(r.stream_id, r.frame_number),
        ))
    return evidence


def smtp_evidence(records: list[SmtpRecord]) -> list[EvidenceRecord]:
    evidence = []
    for r in records[:500]:
        evidence.append(EvidenceRecord(
            evidence_id=stable_id("smtp", r.frame_number, r.stream_id, r.command, r.parameter, r.message, r.response),
            type="smtp_message" if r.message else "smtp_command",
            source_module="protocols.smtp",
            protocol="SMTP",
            timestamp=r.timestamp,
            frame_start=r.frame_number,
            frame_end=r.frame_number,
            stream_id=r.stream_id,
            src_ip=r.src_ip,
            dst_ip=r.dst_ip,
            fields={
                "command": r.command,
                "parameter": r.parameter,
                "response": r.response,
                "response_code": r.response_code,
                "message": r.message,
                "auth_username": r.auth_username,
                "auth_password_present": bool(r.auth_password),
            },
            preview=" ".join(item for item in [r.command, r.parameter, r.response, r.message] if item)[:512],
            confidence="high",
            confidence_score=0.9,
            handoff_filters=stream_or_frame_filter(r.stream_id, r.frame_number),
        ))
    return evidence


def mqtt_evidence(records: list[MqttRecord]) -> list[EvidenceRecord]:
    evidence = []
    for r in records[:500]:
        evidence.append(EvidenceRecord(
            evidence_id=stable_id("mqtt", r.frame_number, r.stream_id, r.topic, r.message),
            type="mqtt_message",
            source_module="protocols.mqtt",
            protocol="MQTT",
            timestamp=r.timestamp,
            frame_start=r.frame_number,
            frame_end=r.frame_number,
            stream_id=r.stream_id,
            src_ip=r.src_ip,
            dst_ip=r.dst_ip,
            fields={
                "msg_type": r.msg_type,
                "topic": r.topic,
                "message": r.message,
                "username": r.username,
                "password_present": bool(r.password),
            },
            preview="; ".join(item for item in [f"topic={r.topic}" if r.topic else "", r.message] if item)[:512],
            confidence="high",
            confidence_score=0.9,
            handoff_filters=stream_or_frame_filter(r.stream_id, r.frame_number),
        ))
    return evidence


def payload_weirdness_evidence(packets: list[PacketRecord]) -> list[EvidenceRecord]:
    evidence = []
    for packet in packets[:5000]:
        if tcp_syn(packet.tcp_flags) and (safe_int(packet.tcp_len) > 0 or packet.payload_hex):
            evidence.append(EvidenceRecord(
                evidence_id=stable_id("syn_payload", packet.frame_number, packet.payload_hex),
                type="syn_payload",
                source_module="protocols.payloads",
                protocol=packet.protocol or "TCP",
                timestamp=packet.timestamp,
                frame_start=packet.frame_number,
                frame_end=packet.frame_number,
                stream_id=packet.tcp_stream,
                src_ip=packet.src_ip,
                src_port=packet.src_port,
                dst_ip=packet.dst_ip,
                dst_port=packet.dst_port,
                fields={"tcp_flags": packet.tcp_flags, "tcp_len": packet.tcp_len, "payload_hex": packet.payload_hex[:1024]},
                preview=payload_preview(packet.payload_hex),
                confidence="high",
                confidence_score=0.85,
                handoff_filters=[f"frame.number == {packet.frame_number}"],
            ))
        elif packet.transport == "ICMP" and packet.payload_hex:
            evidence.append(EvidenceRecord(
                evidence_id=stable_id("icmp_payload", packet.frame_number, packet.payload_hex[:128]),
                type="icmp_payload",
                source_module="protocols.icmp",
                protocol="ICMP",
                timestamp=packet.timestamp,
                frame_start=packet.frame_number,
                frame_end=packet.frame_number,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                fields={"payload_hex": packet.payload_hex[:1024]},
                preview=payload_preview(packet.payload_hex),
                confidence="medium",
                confidence_score=0.65,
                handoff_filters=[f"frame.number == {packet.frame_number}"],
            ))
    return evidence


def string_evidence(strings: list[tuple[str, str]]) -> list[EvidenceRecord]:
    evidence = []
    rows = []
    rows.extend(detect_flags(strings))
    rows.extend(detect_credentials(strings))
    for source, text in strings:
        lowered = text.lower()
        if any(word in lowered for word in ["decode", "base64", "base85", "password", "pass:", "archive", "http://", "https://", "flag"]):
            rows.append((source, text))
        for decoded in decode_interesting(text):
            evidence.append(EvidenceRecord(
                evidence_id=stable_id("decoded", source, decoded),
                type="decoded_string",
                source_module="decoders",
                fields={"source": source, "decoded": decoded},
                preview=decoded[:512],
                confidence="medium",
                confidence_score=0.65,
                directly_observed=False,
                inferred=True,
            ))
    for source, text in rows[:300]:
        evidence.append(EvidenceRecord(
            evidence_id=stable_id("string", source, text[:256]),
            type="raw_string" if source == "raw-file" else "payload_string",
            source_module="strings",
            fields={"source": source, "text": text},
            preview=text[:512],
            confidence="medium",
            confidence_score=0.6,
            handoff_filters=source_filter(source),
        ))
    return evidence


def artifact_evidence(artifacts: list[ArtifactRecord]) -> list[EvidenceRecord]:
    evidence = []
    for artifact in artifacts[:500]:
        evidence.append(EvidenceRecord(
            evidence_id=stable_id("artifact", artifact.artifact_id, artifact.sha256, artifact.path),
            type="artifact_extracted" if artifact.path else "artifact_signature",
            source_module="artifacts",
            fields={
                "artifact_id": artifact.artifact_id,
                "kind": artifact.kind,
                "source": artifact.source,
                "offset": artifact.offset,
                "filename": artifact.filename,
                "size": artifact.size,
                "sha256": artifact.sha256,
                "path": artifact.path,
                "validation": artifact.validation,
                "certainty": artifact.certainty,
                "magic_header_valid": artifact.magic_header_valid,
                "structure_valid": artifact.structure_valid,
                "complete_file_valid": artifact.complete_file_valid,
                "truncated": artifact.truncated,
                "source_scope": artifact.source_scope,
                "skip_reason": artifact.skip_reason,
                "tags": artifact.tags,
                "score": artifact.score,
            },
            preview=f"{artifact.kind} {artifact.source} offset={artifact.offset} scope={artifact.source_scope} certainty={artifact.certainty} validation={artifact.validation}",
            confidence=confidence_from_score(artifact.score),
            confidence_score=min(1.0, artifact.score / 100),
            related_artifact_ids=[artifact.artifact_id],
            handoff_filters=source_filter(artifact.source),
        ))
    return evidence


def link_findings_to_evidence(report: AnalysisReport) -> None:
    for finding in report.findings:
        finding.finding_id = stable_id("finding", finding.category, finding.title, finding.related, "|".join(finding.evidence))
        finding.evidence_summaries = list(finding.evidence[:3])
        matches = []
        if finding.related:
            matches.extend(match_evidence(report.evidence, finding.related))
        if not matches:
            matches.extend([e.evidence_id for e in report.evidence if e.type.startswith(finding.category) or e.protocol.lower() == finding.category.lower()][:3])
        finding.evidence_ids = list(dict.fromkeys(matches))[:5]
        finding.confidence = confidence_from_score(finding.risk_score)
        finding.confidence_score = min(1.0, finding.risk_score / 100)
        if "likely" in finding.title.lower() or "possible" in finding.title.lower():
            finding.inferred = True
            finding.directly_observed = False


def match_evidence(evidence: list[EvidenceRecord], related: str) -> list[str]:
    matches = []
    for item in evidence:
        haystack = " ".join([
            item.evidence_id,
            item.type,
            item.stream_id,
            item.preview,
            str(item.frame_start or ""),
            str(item.fields),
        ])
        if related in haystack:
            matches.append(item.evidence_id)
    return matches


def dedupe_evidence(records: list[EvidenceRecord]) -> list[EvidenceRecord]:
    seen = set()
    deduped = []
    for record in records:
        if record.evidence_id in seen:
            continue
        seen.add(record.evidence_id)
        deduped.append(record)
    return deduped


def source_filter(source: str) -> list[str]:
    if source.startswith("packet:"):
        frame = source.split(":", 1)[1]
        return [f"frame.number == {frame}"]
    return []


def stream_or_frame_filter(stream_id: str, frame_number: int) -> list[str]:
    if stream_id:
        return [f"tcp.stream == {stream_id}"]
    if frame_number:
        return [f"frame.number == {frame_number}"]
    return []


def host_filters(src: str, dst: str) -> list[str]:
    filters = []
    if src and dst:
        filters.append(f"ip.addr == {src} && ip.addr == {dst}")
    elif src:
        filters.append(f"ip.addr == {src}")
    return filters


def payload_preview(payload_hex: str) -> str:
    if not payload_hex:
        return ""
    try:
        text = bytes.fromhex(payload_hex.replace(":", "")).decode("utf-8", errors="ignore")
    except ValueError:
        text = payload_hex
    return re.sub(r"\s+", " ", text).strip()[:512]


def safe_int(value: str) -> int:
    try:
        return int(str(value).split(",", 1)[0].strip())
    except Exception:
        return 0


def tcp_syn(flags: str) -> bool:
    if not flags:
        return False
    try:
        return bool(int(flags, 16) & 0x02)
    except ValueError:
        return "syn" in flags.lower()


def confidence_from_score(score: int) -> str:
    if score >= 75:
        return "high"
    if score >= 40:
        return "medium"
    return "low"
