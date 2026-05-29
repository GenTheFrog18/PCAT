from pcat.cli import main, parse_formats
from pcat.models import AnalysisReport, CaptureSummary, EvidenceRecord, PacketRecord


def test_parse_formats_aliases():
    assert parse_formats("html,json,markdown,plaintext") == {"html", "json", "md", "txt"}


def test_cli_help(capsys):
    assert main(["--help"]) == 0
    output = capsys.readouterr().out
    assert "PCAP Assistant for Triage" in output


def test_subcommand_help_after_command(capsys):
    assert main(["analyze", "-h"]) == 0
    output = capsys.readouterr().out
    assert "Run the full PCAT pipeline" in output
    assert "--min-risk" in output


def test_subcommand_help_before_command(capsys):
    assert main(["-h", "strings"]) == 0
    output = capsys.readouterr().out
    assert "Extract printable ASCII" in output
    assert "--grep" in output


def test_help_subcommand_alias(capsys):
    assert main(["help", "hunt"]) == 0
    output = capsys.readouterr().out
    assert "CTF-focused workflow" in output
    assert "--ctf-flag" in output


def test_strings_command_no_payloads(tmp_path, capsys):
    sample = tmp_path / "sample.pcap"
    sample.write_bytes(b"abc flag{demo} password=secret")
    assert main(["strings", "-i", str(sample), "--no-payloads", "--grep", "flag", "--ignore-case"]) == 0
    output = capsys.readouterr().out
    assert "flag{demo}" in output


def test_strings_source_raw_does_not_parse_packets(tmp_path, capsys, monkeypatch):
    sample = tmp_path / "sample.pcap"
    sample.write_bytes(b"rawflag packetflag")

    def fail_parse(_path):
        raise AssertionError("packet parser should not run for --source raw")

    monkeypatch.setattr("pcat.cli.parse_packets", fail_parse)
    assert main(["strings", "-i", str(sample), "--source", "raw", "--grep", "rawflag"]) == 0
    output = capsys.readouterr().out
    assert "rawflag" in output


def test_search_source_packet_uses_payload_source(tmp_path, capsys, monkeypatch):
    sample = tmp_path / "sample.pcap"
    sample.write_bytes(b"rawflag")

    def fake_parse(_path):
        return [PacketRecord(frame_number=7, timestamp=1.0, length=20, payload_hex=b"packetflag".hex())]

    monkeypatch.setattr("pcat.cli.parse_packets", fake_parse)
    assert main(["search", "-i", str(sample), "packetflag", "--source", "packet"]) == 0
    output = capsys.readouterr().out
    assert "[packet:7] packetflag" in output
    assert "rawflag" not in output


def test_strings_invalid_regex_returns_invalid_argument(tmp_path, capsys):
    sample = tmp_path / "sample.pcap"
    sample.write_bytes(b"abc flag{demo}")
    code = main(["strings", "-i", str(sample), "--no-payloads", "--grep", "["])
    captured = capsys.readouterr()
    assert code == 2
    assert "Invalid regex pattern" in captured.err


def test_search_invalid_regex_returns_invalid_argument(tmp_path, capsys):
    sample = tmp_path / "sample.pcap"
    sample.write_bytes(b"abc flag{demo}")
    code = main(["search", "-i", str(sample), "[", "--regex", "--no-payloads"])
    captured = capsys.readouterr()
    assert code == 2
    assert "Invalid regex pattern" in captured.err


def test_input_conflict_returns_invalid_argument(tmp_path, capsys):
    sample = tmp_path / "sample.pcap"
    sample.write_bytes(b"abc")
    code = main(["strings", str(sample), "-i", str(sample), "--no-payloads"])
    assert code == 2
    assert "not both" in capsys.readouterr().err


def test_suspicious_accepts_top_alias(tmp_path, capsys):
    sample = tmp_path / "sample.pcap"
    sample.write_bytes(b"%PDF-1.7\nbody\n%%EOF")
    assert main(["suspicious", "-i", str(sample), "--no-payloads", "--top", "1"]) == 0
    output = capsys.readouterr().out
    assert "Suspicious Artifacts" in output
    assert "validation=validated" in output


def test_extract_reports_rejected_artifact_when_nothing_extracts(tmp_path, capsys):
    sample = tmp_path / "sample.pcap"
    sample.write_bytes(b"noise\x1f\x8bnot-a-real-gzip")
    out = tmp_path / "case"
    code = main(["extract", "-i", str(sample), "--include-raw", "--no-payloads", "-o", str(out)])
    output = capsys.readouterr().out
    assert code == 0
    assert "Artifacts extracted: 0" in output
    assert "Artifacts selected for extraction: 0" in output
    assert "Unextractable artifact hits: rejected=1" in output
    assert "No artifacts were extracted" in output


def test_extract_reports_raw_disabled_skip(tmp_path, capsys):
    sample = tmp_path / "sample.pcap"
    sample.write_bytes(b"%PDF-1.7\nbody\n%%EOF")
    out = tmp_path / "case"
    code = main(["extract", "-i", str(sample), "--no-payloads", "-o", str(out)])
    output = capsys.readouterr().out
    assert code == 0
    assert "Raw-capture artifacts skipped: 1" in output
    assert "--include-raw" in output


def test_extract_reports_http_export_separately(tmp_path, capsys, monkeypatch):
    sample = tmp_path / "sample.pcap"
    sample.write_bytes(b"plain capture placeholder")
    out = tmp_path / "case"

    def fake_export(_path, output_dir):
        return {
            "output_dir": str(output_dir / "http_objects"),
            "exported_count": 2,
            "status": "ok",
            "error": "",
        }

    monkeypatch.setattr("pcat.cli.run_tshark_export_http", fake_export)
    code = main(["extract", "-i", str(sample), "--no-payloads", "--http", "-o", str(out)])
    output = capsys.readouterr().out
    assert code == 0
    assert "HTTP objects exported: 2" in output
    assert "Artifacts extracted: 0" in output


def test_analyze_redact_returns_unsupported_argument(tmp_path, capsys):
    sample = tmp_path / "sample.pcap"
    sample.write_bytes(b"abc")
    code = main(["analyze", "-i", str(sample), "--redact"])
    captured = capsys.readouterr()
    assert code == 2
    assert "Redaction is not implemented yet" in captured.err


def test_analyze_help_hides_redaction_flags(capsys):
    assert main(["analyze", "-h"]) == 0
    output = capsys.readouterr().out
    assert "--redact" not in output


def test_existing_output_folder_returns_report_write_error(tmp_path, capsys):
    sample = tmp_path / "sample.pcap"
    sample.write_bytes(b"abc")
    out = tmp_path / "case"
    out.mkdir()
    code = main(["extract", "-i", str(sample), "--no-payloads", "-o", str(out)])
    assert code == 5
    assert "Output folder already exists" in capsys.readouterr().err


def test_timeline_fallback_sorts_evidence_before_top(tmp_path, capsys, monkeypatch):
    sample = tmp_path / "sample.pcap"
    sample.write_bytes(b"abc")

    def fake_analyze(_path, _options):
        return AnalysisReport(
            summary=CaptureSummary(file=str(sample), size_bytes=3),
            evidence=[
                EvidenceRecord("late", "flow", timestamp=2.0, preview="late"),
                EvidenceRecord("early", "flow", timestamp=1.0, preview="early"),
            ],
        )

    monkeypatch.setattr("pcat.cli.analyze", fake_analyze)
    assert main(["timeline", "-i", str(sample)]) == 0
    output = capsys.readouterr().out
    assert output.index("1.000000") < output.index("2.000000")


def test_empty_protocol_views_are_explicit(tmp_path, capsys, monkeypatch):
    sample = tmp_path / "sample.pcap"
    sample.write_bytes(b"abc")

    def fake_analyze(_path, _options):
        return AnalysisReport(summary=CaptureSummary(file=str(sample), size_bytes=3))

    monkeypatch.setattr("pcat.cli.analyze", fake_analyze)
    assert main(["http", "-i", str(sample)]) == 0
    assert "No HTTP records found" in capsys.readouterr().out
    assert main(["dns", "-i", str(sample)]) == 0
    assert "No DNS records found" in capsys.readouterr().out
    assert main(["streams", "-i", str(sample)]) == 0
    assert "No TCP streams found" in capsys.readouterr().out
