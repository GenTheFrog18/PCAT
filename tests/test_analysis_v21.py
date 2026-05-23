from pcat.analysis import build_timeline, dns_visibility_findings
from pcat.models import AnalysisReport, CaptureSummary, DnsRecord, EvidenceRecord, Finding, PacketRecord


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
