from pcat.models import CaptureSummary, AnalysisReport, severity_from_score, to_plain


def test_report_serializes_to_plain_dict():
    report = AnalysisReport(summary=CaptureSummary(file="x.pcap", size_bytes=10))
    plain = to_plain(report)
    assert plain["summary"]["file"] == "x.pcap"
    assert plain["findings"] == []


def test_severity_mapping():
    assert severity_from_score(0) == "info"
    assert severity_from_score(10) == "low"
    assert severity_from_score(30) == "medium"
    assert severity_from_score(60) == "high"
    assert severity_from_score(90) == "critical"

