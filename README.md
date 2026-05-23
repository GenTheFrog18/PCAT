# PCAT - PCAP Assistant for Triage

PCAT is an offline command-line tool for first-pass packet capture analysis. It accepts captures that TShark/Wireshark can parse, including `.pcap`, `.pcapng`, `.cap`, `.pcap.gz`, and valid captures with unusual extensions. It is built for general network triage and CTF workflows where the first question is usually: what is inside this capture, what matters, and where should I look next?

## Requirements

- Python 3.10+
- `tshark` from Wireshark

Optional:

- `scikit-learn` for ML anomaly scoring
- `pytest` for tests

Install from the repository root:

```bash
python3 -m pip install -e .
```

Run without installing:

```bash
PYTHONPATH=src python3 -m pcat --help
```

## Common Commands

```bash
pcat doctor
pcat summary -i capture.pcap
pcat analyze -i capture.pcap --ctf --no-ml
pcat evidence -i capture.pcap --top 25
pcat timeline -i capture.pcap --top 50
pcat hunt -i capture.pcap --limit 50
pcat strings -i capture.pcap --grep flag --ignore-case
pcat strings -i capture.pcap --source packet --grep flag
pcat search -i capture.pcap password --ignore-case
pcat files -i capture.pcap --top 50
pcat artifacts -i capture.pcap --top 50
pcat suspicious -i capture.pcap --top 20
pcat extract -i capture.pcap --limit 10
```

Generated reports and artifacts are written under `<pcap-file-name>-pcat/<pcap-stem>/` unless `-o/--out` is provided. Example: `capture.pcapng` writes to `capture.pcapng-pcat/capture/`. Generated output folders are ignored by git.

Every command supports `--json` for automation and teammate handoff.

## V2 Capabilities

- Capture summaries with protocol, host, port, DNS, HTTP, and stream views.
- TShark-authority input handling with clearer guidance for archives, HTML/download placeholders, gzip files, and invalid captures.
- Capture metadata with SHA256, capinfos data when available, and protocol hierarchy.
- Structured evidence records with stable IDs, confidence, previews, frame/stream anchors, and handoff filters.
- Analyst briefing and evidence stories that summarize what matters first, what is limited, and what command to run next.
- Safer parser behavior for large HTTP/multipart captures.
- TCP/UDP payload string extraction, including Raw IPv4 TCP payloads.
- CTF hunt support for flags, credentials, clue strings, short base64 fragments, timestamp-order reconstruction, and SYN packets carrying payload.
- HTTP transfer triage using request/response metadata, content type, content length, and large upload/download hints.
- SMTP and MQTT evidence surfacing when TShark exposes those fields.
- Broader DNS extraction for common answer types such as A, AAAA, CNAME, PTR, NS, MX, and TXT where TShark exposes them.
- Timeline events use linked evidence timestamps when available and show `unknown` instead of inventing time zero.
- Magic-byte artifact detection with certainty labels: `confirmed`, `candidate`, or `rejected`, plus trust fields for magic-header, structure, completeness, truncation, source scope, and skip reason.
- Artifact manager output with `artifacts/manifest.json`; rejected artifacts are grouped in default stdout, with individual offsets preserved in JSON or verbose output.
- Safer extraction: `--limit` limits actual writes, invalid or incomplete artifacts are skipped, raw carving is opt-in, skipped reasons are counted, and HTTP object export is reported separately from artifact carving.
- `strings` and `search` share source behavior and support `--source raw`, `--source packet`, or `--source all`.
- JSON reports use `report.json`, `stories.json`, and `evidence.json`; CSV exports include flows, hosts, DNS, HTTP, artifacts, and findings.
- Copy-paste-safe generated commands for paths containing spaces.

## Current Limits

- `candidate` artifacts are leads, not confirmed files. Check `complete_file_valid`, `truncated`, and `source_scope` before trusting a carved object.
- Stream reassembly, TFTP export, MQTT payload export, USB HID decoding, and deeper CTF decoders are planned improvements.
- PCAT should be used as a briefing and handoff tool beside Wireshark/TShark and other specialist tools.

## Documentation

- [docs/reference/PCAT_ARCHITECTURE.md](docs/reference/PCAT_ARCHITECTURE.md): product philosophy, architecture, design decisions, contribution model, and implemented vs planned scope.
- [docs/reference/PCAT_TECHNICAL_REFERENCE.md](docs/reference/PCAT_TECHNICAL_REFERENCE.md): complete technical reference for commands, data models, outputs, findings, artifacts, and planned features.
- [docs/reference/PCAT_MANUAL.md](docs/reference/PCAT_MANUAL.md): systematic command manual.
