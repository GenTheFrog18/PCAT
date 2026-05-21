from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from typing import Any


SCHEMA_VERSION = "0.2"


@dataclass
class ReportMessage:
    stage: str
    message: str
    severity: str = "warning"
    detail: str = ""


@dataclass
class ToolRun:
    tool: str
    status: str
    version: str = ""
    command: str = ""
    output_path: str = ""
    error: str = ""


@dataclass
class CaptureRecord:
    path: str
    name: str
    stem: str
    size_bytes: int
    sha256: str = ""
    file_type: str = ""
    encapsulation: str = ""
    interfaces: list[str] = field(default_factory=list)
    packet_count: int = 0
    start_time: str = ""
    end_time: str = ""
    duration: float = 0.0
    strict_time_order: str = ""
    capture_application: str = ""
    protocol_hierarchy: dict[str, int] = field(default_factory=dict)


@dataclass
class EvidenceRecord:
    evidence_id: str
    type: str
    source_tool: str = "pcat"
    source_module: str = ""
    protocol: str = ""
    timestamp: float | None = None
    frame_start: int | None = None
    frame_end: int | None = None
    stream_id: str = ""
    src_ip: str = ""
    src_port: str = ""
    dst_ip: str = ""
    dst_port: str = ""
    fields: dict[str, Any] = field(default_factory=dict)
    preview: str = ""
    confidence: str = "medium"
    confidence_score: float = 0.5
    directly_observed: bool = True
    inferred: bool = False
    related_artifact_ids: list[str] = field(default_factory=list)
    handoff_filters: list[str] = field(default_factory=list)


@dataclass
class PacketRecord:
    frame_number: int
    timestamp: float
    length: int
    protocol: str = ""
    protocol_stack: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: str = ""
    dst_port: str = ""
    transport: str = ""
    tcp_flags: str = ""
    tcp_len: str = ""
    tcp_stream: str = ""
    dns_query: str = ""
    dns_answer: str = ""
    dns_rcode: str = ""
    http_host: str = ""
    http_method: str = ""
    http_uri: str = ""
    http_full_uri: str = ""
    http_user_agent: str = ""
    http_status: str = ""
    http_content_type: str = ""
    http_content_length: str = ""
    tls_sni: str = ""
    icmp_type: str = ""
    payload_hex: str = ""
    smtp_command: str = ""
    smtp_parameter: str = ""
    smtp_response: str = ""
    smtp_response_code: str = ""
    smtp_message: str = ""
    smtp_auth_username: str = ""
    smtp_auth_password: str = ""
    mqtt_msg_type: str = ""
    mqtt_topic: str = ""
    mqtt_message: str = ""
    mqtt_username: str = ""
    mqtt_password: str = ""


@dataclass
class FlowRecord:
    flow_id: str
    src_ip: str
    src_port: str
    dst_ip: str
    dst_port: str
    protocol: str
    packet_count: int = 0
    byte_count: int = 0
    start_time: float = 0.0
    end_time: float = 0.0
    tcp_streams: list[str] = field(default_factory=list)
    flags: dict[str, int] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    anomaly_score: float | None = None

    @property
    def duration(self) -> float:
        return max(0.0, self.end_time - self.start_time)


@dataclass
class StreamRecord:
    stream_id: str
    protocol: str
    src_ip: str
    src_port: str
    dst_ip: str
    dst_port: str
    packet_count: int = 0
    byte_count: int = 0
    start_time: float = 0.0
    end_time: float = 0.0
    preview: str = ""
    tags: list[str] = field(default_factory=list)
    interest_score: int = 0

    @property
    def duration(self) -> float:
        return max(0.0, self.end_time - self.start_time)


@dataclass
class DnsRecord:
    frame_number: int
    timestamp: float
    src_ip: str
    dst_ip: str
    query: str = ""
    answer: str = ""
    rcode: str = ""


@dataclass
class HttpRecord:
    frame_number: int
    timestamp: float
    src_ip: str
    dst_ip: str
    host: str = ""
    method: str = ""
    uri: str = ""
    full_uri: str = ""
    user_agent: str = ""
    status: str = ""
    content_type: str = ""
    content_length: str = ""
    stream_id: str = ""


@dataclass
class SmtpRecord:
    frame_number: int
    timestamp: float
    src_ip: str
    dst_ip: str
    command: str = ""
    parameter: str = ""
    response: str = ""
    response_code: str = ""
    message: str = ""
    auth_username: str = ""
    auth_password: str = ""
    stream_id: str = ""


@dataclass
class MqttRecord:
    frame_number: int
    timestamp: float
    src_ip: str
    dst_ip: str
    msg_type: str = ""
    topic: str = ""
    message: str = ""
    username: str = ""
    password: str = ""
    stream_id: str = ""


@dataclass
class ArtifactRecord:
    artifact_id: str
    kind: str
    source: str
    offset: int
    source_type: str = ""
    source_evidence_id: str = ""
    declared_type: str = ""
    validated_type: str = ""
    filename: str = ""
    size: int = 0
    sha256: str = ""
    path: str = ""
    validation: str = "signature_only"
    encrypted: bool = False
    members: list[str] = field(default_factory=list)
    manifest_path: str = ""
    extraction_status: str = ""
    tags: list[str] = field(default_factory=list)
    score: int = 0
    reasons: list[str] = field(default_factory=list)


@dataclass
class HandoffHint:
    tool: str
    purpose: str
    text: str
    related: str = ""


@dataclass
class Finding:
    title: str
    category: str
    risk_score: int
    severity: str
    finding_id: str = ""
    evidence_ids: list[str] = field(default_factory=list)
    evidence_summaries: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    explanation: str = ""
    next_step: str = ""
    confidence: str = "medium"
    confidence_score: float = 0.5
    directly_observed: bool = True
    inferred: bool = False
    src_ip: str = ""
    dst_ip: str = ""
    related: str = ""
    handoff: list[HandoffHint] = field(default_factory=list)


@dataclass
class InvestigationItem:
    priority: str
    reason: str
    related: str
    evidence_summary: str
    suggested_action: str
    handoff: list[HandoffHint] = field(default_factory=list)


@dataclass
class TimelineEvent:
    timestamp: float
    title: str
    detail: str = ""
    severity: str = "info"


@dataclass
class CaptureSummary:
    file: str
    size_bytes: int
    packet_count: int = 0
    start_time: float = 0.0
    end_time: float = 0.0
    duration: float = 0.0
    protocols: dict[str, int] = field(default_factory=dict)
    top_hosts: dict[str, int] = field(default_factory=dict)
    top_ports: dict[str, int] = field(default_factory=dict)
    top_conversations: dict[str, int] = field(default_factory=dict)
    top_dns: dict[str, int] = field(default_factory=dict)
    top_http_hosts: dict[str, int] = field(default_factory=dict)


@dataclass
class AnalysisReport:
    summary: CaptureSummary
    schema_version: str = SCHEMA_VERSION
    capture: CaptureRecord | None = None
    tools: list[ToolRun] = field(default_factory=list)
    hosts: list[dict[str, Any]] = field(default_factory=list)
    conversations: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[EvidenceRecord] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    investigation_queue: list[InvestigationItem] = field(default_factory=list)
    flows: list[FlowRecord] = field(default_factory=list)
    streams: list[StreamRecord] = field(default_factory=list)
    dns_records: list[DnsRecord] = field(default_factory=list)
    http_records: list[HttpRecord] = field(default_factory=list)
    smtp_records: list[SmtpRecord] = field(default_factory=list)
    mqtt_records: list[MqttRecord] = field(default_factory=list)
    artifacts: list[ArtifactRecord] = field(default_factory=list)
    timeline: list[TimelineEvent] = field(default_factory=list)
    handoff: list[HandoffHint] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    warnings: list[ReportMessage] = field(default_factory=list)
    errors: list[ReportMessage] = field(default_factory=list)
    tool_versions: dict[str, str] = field(default_factory=dict)


def to_plain(value: Any) -> Any:
    if is_dataclass(value):
        return {k: to_plain(v) for k, v in asdict(value).items()}
    if isinstance(value, list):
        return [to_plain(v) for v in value]
    if isinstance(value, dict):
        return {str(k): to_plain(v) for k, v in value.items()}
    return value


def severity_from_score(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    if score > 0:
        return "low"
    return "info"
