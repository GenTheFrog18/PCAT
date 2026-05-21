import json
from pathlib import Path

from pcat.models import AnalysisReport, CaptureSummary, Finding
from pcat.reports import write_reports
from pcat.utils import default_output_dir


def test_default_output_dir_uses_v2_case_layout(tmp_path):
    sample = tmp_path / "chall2.pcapng"
    assert default_output_dir(sample) == Path("chall2.pcapng-pcat") / "chall2"


def test_write_reports_emits_v2_json_and_csv_set(tmp_path):
    report = AnalysisReport(
        summary=CaptureSummary(file="capture.pcap", size_bytes=10, packet_count=1),
        findings=[Finding("Suspicious thing", "test", 50, "high", evidence=["frame 1"])],
    )
    written = write_reports(report, tmp_path, {"json", "csv"})
    names = {path.name for path in written}
    assert {
        "report.json",
        "evidence.json",
        "findings.json",
        "flows.csv",
        "hosts.csv",
        "dns.csv",
        "http.csv",
        "artifacts.csv",
        "findings.csv",
    } <= names
    data = json.loads((tmp_path / "report.json").read_text())
    assert data["schema_version"] == "0.2"
