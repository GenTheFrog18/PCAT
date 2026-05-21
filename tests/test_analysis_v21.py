from pcat.analysis import dns_visibility_findings
from pcat.models import DnsRecord, PacketRecord


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
