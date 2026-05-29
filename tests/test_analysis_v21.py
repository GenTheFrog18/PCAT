from pcat.analysis import build_timeline, dns_visibility_findings, icmp_findings
from pcat.evidence import build_report_evidence
from pcat.models import AnalysisReport, CaptureSummary, DnsRecord, EvidenceRecord, Finding, PacketRecord, SmtpRecord


def test_dns_visibility_finding_when_dns_packets_have_no_useful_records():
    packets = [
        PacketRecord(
            frame_number=1,
            timestamp=1.0,
            length=90,
            protocol="DNS",
            protocol_stack="eth:ip:udp:dns",
            src_ip="10.0.0.5",
            dst_ip="10.0.0.53",
        )
    ]
    findings = dns_visibility_findings(packets, [])
    assert len(findings) == 1
    assert findings[0].severity == "low"
    assert "manual parser review" in findings[0].title


def test_dns_visibility_finding_skipped_when_records_have_query_or_answer():
    packets = [PacketRecord(frame_number=1, timestamp=1.0, length=90, protocol="DNS", protocol_stack="eth:ip:udp:dns")]
    records = [DnsRecord(frame_number=1, timestamp=1.0, src_ip="10.0.0.5", dst_ip="10.0.0.53", query="example.test")]
    assert dns_visibility_findings(packets, records) == []


def test_timeline_uses_linked_evidence_timestamp():
    report = AnalysisReport(
        summary=CaptureSummary(file="capture.pcap", size_bytes=1),
        findings=[Finding("Suspicious thing", "test", 50, "high", evidence_ids=["ev1"])],
        evidence=[EvidenceRecord("ev1", "flow", timestamp=12.5, preview="flow detail")],
    )
    events = build_timeline(report)
    assert events[0].timestamp == 12.5
    assert events[0].detail == "flow detail"


def test_timeline_marks_missing_timestamp_unknown_without_inventing_zero():
    report = AnalysisReport(
        summary=CaptureSummary(file="capture.pcap", size_bytes=1),
        findings=[Finding("Suspicious thing", "test", 50, "high", evidence=["manual evidence"])],
    )
    events = build_timeline(report)
    assert events[0].timestamp is None
    assert events[0].timestamp != 0.0


def test_timeline_skips_unknown_time_decoder_noise():
    report = AnalysisReport(
        summary=CaptureSummary(file="capture.pcap", size_bytes=1),
        findings=[Finding("Encoded-looking string decoded", "ctf", 50, "high", evidence_ids=["ev1"])],
        evidence=[EvidenceRecord("ev1", "decoded_string", source_module="decoders", preview="base64:junk -> text")],
    )
    assert build_timeline(report) == []


def test_smtp_auth_credentials_become_sensitive_evidence():
    report = AnalysisReport(
        summary=CaptureSummary(file="mail.pcap", size_bytes=1),
        smtp_records=[
            SmtpRecord(
                frame_number=5,
                timestamp=10.0,
                src_ip="10.0.0.2",
                dst_ip="10.0.0.25",
                auth_username="Z2FsdW50",
                auth_password="VjF2MXRyMG4=",
                stream_id="2",
            )
        ],
    )
    build_report_evidence(report, [], [])
    creds = [item for item in report.evidence if item.type == "smtp_auth_credential"]
    assert len(creds) == 1
    assert creds[0].fields["auth_username"] == "galunt"
    assert creds[0].fields["auth_password"] == "V1v1tr0n"
    assert creds[0].fields["sensitive"] is True


def test_icmp_protocol_banner_is_promoted():
    packets = [
        PacketRecord(
            frame_number=15,
            timestamp=1.0,
            length=120,
            transport="ICMP",
            payload_hex=b"SSH-2.0-OpenSSH_5.3p1".hex(),
        )
    ]
    findings = icmp_findings(packets)
    assert findings[0].title == "Protocol banner inside ICMP payload"
    assert findings[0].severity == "critical"
