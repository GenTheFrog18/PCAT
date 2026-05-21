# PCAT - PCAP Assistant for Triage

PCAT is an offline command-line tool for first-pass `.pcap` and `.pcapng` analysis. It is built for general network triage and CTF workflows where the first question is usually: what is inside this capture, what matters, and where should I look next?

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
- Capture metadata with SHA256, capinfos data when available, and protocol hierarchy.
- Structured evidence records with stable IDs, confidence, previews, frame/stream anchors, and handoff filters.
- Safer parser behavior for large HTTP/multipart captures.
- TCP/UDP payload string extraction, including Raw IPv4 TCP payloads.
- CTF hunt support for flags, credentials, clue strings, short base64 fragments, timestamp-order reconstruction, and SYN packets carrying payload.
- HTTP transfer triage using request/response metadata, content type, content length, and large upload/download hints.
- SMTP and MQTT evidence surfacing when TShark exposes those fields.
- Magic-byte artifact detection with validation states such as `validated`, `signature_only`, and `invalid`.
- Artifact manager output with `artifacts/manifest.json`; default extraction focuses on packet payload artifacts and raw carving is opt-in.
- Safer extraction: `--limit` limits actual writes, invalid artifacts are skipped, and raw carving is bounded.
- JSON reports use `report.json` and `evidence.json`; CSV exports include flows, hosts, DNS, HTTP, artifacts, and findings.
- Copy-paste-safe generated commands for paths containing spaces.

## Documentation

- [docs/reference/PCAT_ARCHITECTURE.md](docs/reference/PCAT_ARCHITECTURE.md): product philosophy, architecture, design decisions, contribution model, and implemented vs planned scope.
- [docs/reference/PCAT_TECHNICAL_REFERENCE.md](docs/reference/PCAT_TECHNICAL_REFERENCE.md): complete technical reference for commands, data models, outputs, findings, artifacts, and planned features.
- [docs/reference/PCAT_MANUAL.md](docs/reference/PCAT_MANUAL.md): systematic command manual.
