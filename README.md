# PCAT - PCAP Assistant for Triage

![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB)
![Version 0.2.4.1](https://img.shields.io/badge/version-0.2.4.1-1f6e67)
![Status](https://img.shields.io/badge/status-active%20prototype-c79a27)

# Hi ges, readme ini sementara, besok kubuatin yang ril

PCAT is an offline command-line tool for first-pass packet capture analysis. It accepts captures that TShark/Wireshark can parse, including `.pcap`, `.pcapng`, `.cap`, `.pcap.gz`, and valid captures with unusual extensions.

PCAT is built for general network triage and CTF workflows where the first questions are:

- What is inside this capture?
- What evidence is worth looking at first?
- What can be safely extracted?
- What should I inspect next in Wireshark, TShark, or another specialist tool?

PCAT is not a Wireshark replacement. It is a briefing and handoff layer that turns a capture into summaries, evidence records, investigation leads, reports, and extracted artifacts.

## Project Status

- Current tool version: `0.2.4.1`
- Current report schema version: `0.2.4`
- Stage: active prototype, ready for teammate testing
- Primary interface: CLI
- Required packet backend: TShark
- Default privacy behavior: no redaction; generated reports may contain sensitive capture data

## Key Features

- Capture summaries for protocols, hosts, ports, DNS, HTTP, TCP streams, and UDP conversations.
- Structured evidence records with stable IDs, confidence labels, previews, frame anchors, stream anchors, and handoff filters.
- Analyst briefing and evidence stories that explain what matters, what is uncertain, and what command to run next.
- CTF-oriented hunt workflow for flags, credentials, clue strings, decoded fragments, ICMP payload hints, and SYN payloads.
- Search across strings, decoded values, protocol records, evidence, findings, and artifacts.
- Artifact detection with `confirmed`, `candidate`, and `rejected` certainty labels.
- Safer extraction with bounded writes, skip reasons, manifests, SHA256 hashes, and raw carving disabled by default.
- HTTP object export and TFTP object export through `pcat extract`.
- JSON, CSV, HTML, Markdown, and text report outputs for handoff and automation.

## Requirements

Required:

- Python 3.10 or newer
- TShark from Wireshark

Optional:

- `capinfos` for richer capture metadata
- `file` for extracted artifact type labels
- `scikit-learn` for optional ML anomaly scoring
- `pytest` for running the test suite

Check your environment:

```bash
pcat doctor
```

## Installation

Install from the repository root:

```bash
python3 -m pip install -e .
```

Run without installing:

```bash
PYTHONPATH=src python3 -m pcat --help
```

Install optional development/test dependencies:

```bash
python3 -m pip install -e ".[test]"
```

Install optional ML support:

```bash
python3 -m pip install -e ".[ml]"
```

## Quickstart

```bash
pcat doctor
pcat summary -i capture.pcap
pcat analyze -i capture.pcap --ctf --extract -o case-output
pcat evidence -i capture.pcap --top 25 --json
pcat extract -i capture.pcap --http --tftp -o case-output
```

Every command supports `--json` for automation and teammate handoff.

Generated reports and artifacts are written under `<pcap-file-name>-pcat/<pcap-stem>/` unless `-o/--out` is provided. For example, `capture.pcapng` writes to `capture.pcapng-pcat/capture/`. Generated output folders are ignored by git.

## Common Commands

| Command | Purpose |
| --- | --- |
| `pcat doctor` | Check dependencies and local tool availability. |
| `pcat summary -i capture.pcap` | Show a quick capture overview. |
| `pcat analyze -i capture.pcap` | Run the full triage pipeline. |
| `pcat streams -i capture.pcap` | Show TCP streams and UDP conversations. |
| `pcat dns -i capture.pcap` | Show DNS-focused records. |
| `pcat http -i capture.pcap` | Show HTTP-focused records. |
| `pcat evidence -i capture.pcap --json` | Show structured evidence records. |
| `pcat timeline -i capture.pcap` | Show chronological findings and evidence events. |
| `pcat strings -i capture.pcap --grep flag --ignore-case` | Extract and filter strings. |
| `pcat search -i capture.pcap password --ignore-case` | Search across PCAT evidence sources. |
| `pcat artifacts -i capture.pcap --suspicious` | Review artifact candidates and suspicious file hits. |
| `pcat extract -i capture.pcap --http --tftp -o case-output` | Extract artifacts and protocol objects. |
| `pcat hunt -i capture.pcap --limit 50` | Run a CTF-oriented triage workflow. |

For shorter help output:

```bash
pcat --help-short
pcat extract --help-short
```

For full command help:

```bash
pcat --help
pcat analyze --help
pcat -h analyze
pcat help analyze
```

## Output Structure

When report writing or extraction is enabled, PCAT creates a case folder.

Typical output:

```text
case-output/
  report.html
  report.json
  evidence.json
  stories.json
  findings.csv
  artifacts.csv
  tftp.csv
  artifacts/
    manifest.json
    extracted-files...
  http_objects/
    exported-http-objects...
  tftp_objects/
    exported-tftp-objects...
```

Exact files depend on selected formats and enabled extraction options.

## Artifact Certainty

PCAT intentionally separates observations from claims:

- `confirmed`: PCAT found a signature and validated enough structure to treat it as a strong artifact lead.
- `candidate`: PCAT found something potentially useful, but it needs manual validation.
- `rejected`: PCAT found a signature-like hit but validation failed; it is preserved for transparency and skipped during extraction.

Candidate artifacts are leads, not proof. Check `complete_file_valid`, `truncated`, `source_scope`, and `skip_reason` before trusting a carved object.

## Current Limits

- Full TCP stream reassembly is not a first-class workflow yet.
- MQTT payload export, USB HID decoding, and deeper CTF decoders are planned improvements.
- Zeek and Suricata are currently checked by `pcat doctor` but are not orchestrated yet.
- PCAT does not redact by default. Treat reports and extracted artifacts as sensitive.
- Extracted artifacts may be malicious. Handle them with normal malware-analysis caution.

## Documentation

- GitHub Pages source: [docs/index.html](docs/index.html). Publish from the `main` branch `/docs` folder.
- [Architecture](docs/reference/PCAT_ARCHITECTURE.md): product philosophy, design decisions, structure, and contribution model.
- [Technical Reference](docs/reference/PCAT_TECHNICAL_REFERENCE.md): commands, data models, outputs, findings, artifacts, and planned features.
- [Manual](docs/reference/PCAT_MANUAL.md): systematic command manual and testing guide.
- [Roadmap And Decisions](docs/reference/PCAT_ROADMAP_AND_DECISIONS.md): version plans, decisions, and deferred work.
- [Future CTF Update](docs/reference/PCAT_FUTURE_CTF_UPDATE.md): planned CTF-focused improvements.
- [Indonesian README](README.id.md): localized project overview.

## Development

Run the test suite:

```bash
python3 -m pip install -e ".[test]"
pytest
```

Useful development commands:

```bash
PYTHONPATH=src python3 -m pcat --help
PYTHONPATH=src python3 -m pcat doctor --json
PYTHONPATH=src python3 -m pcat analyze -i sample.pcap --no-ml
```

## Contributing

PCAT is still evolving, so useful contributions should focus on correctness, clarity, and repeatable workflows:

- Bug reports with the command used, expected behavior, actual behavior, and capture characteristics.
- Tests for parser edge cases, artifact validation, extraction accounting, and CLI behavior.
- Documentation improvements that clarify what PCAT can and cannot conclude.
- Protocol workflow improvements that preserve evidence, confidence, and handoff context.

Avoid adding features that overclaim certainty. If PCAT is unsure, the output should say so.

## License

No license file has been added yet. Until a license is chosen, treat the repository as not licensed for reuse outside normal GitHub viewing and contribution workflows.

# Tes 123
