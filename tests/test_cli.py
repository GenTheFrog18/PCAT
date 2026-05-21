from pcat.cli import main, parse_formats


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
