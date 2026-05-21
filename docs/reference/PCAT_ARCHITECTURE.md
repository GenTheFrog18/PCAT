# PCAT Architecture And Product Philosophy

PCAT means **PCAP Assistant for Triage**. It is an offline command-line tool for first-pass packet capture analysis. Its job is to help an analyst quickly understand what is inside a TShark-readable capture, identify what deserves attention, and produce structured evidence that can be handed to other tools or teammates.

PCAT is not meant to replace Wireshark, TShark, Zeek, Suricata, CyberChef, tcpdump, or analyst judgment. It is meant to sit before and between those tools, reduce repetitive triage work, and keep findings, evidence, artifacts, and handoff filters in one consistent workflow.

## Core Identity

PCAT is an evidence-first triage assistant.

It does three things:

- It summarizes a capture into useful human and machine-readable views.
- It extracts normalized evidence from packets, protocol metadata, strings, and artifacts.
- It turns that evidence into findings, next steps, and handoff hints.

The most important output is not only the terminal report. The important output is the structured case folder: `report.json`, `evidence.json`, CSV exports, extracted artifacts, and manifest metadata. Those outputs are intended to support manual analysis, team review, scripting, and future external-tool integration.

## Goals

PCAT should make these workflows faster:

- First-pass inspection of unknown PCAPs.
- CTF packet forensics triage.
- General network-forensics triage.
- Finding strings, flags, credentials, URLs, suspicious transfers, and embedded files.
- Getting from "I have a PCAP" to "these frames, streams, hosts, artifacts, and commands matter".
- Producing repeatable JSON/CSV evidence for teammates.
- Preparing useful handoff context for Wireshark, TShark, tcpdump, Zeek, Suricata, and other tools.

PCAT should be useful even when the user does not yet know what protocol or clue matters.

## Non-Goals

PCAT should not try to be:

- A full Wireshark replacement.
- A full IDS.
- A malware sandbox.
- A live capture tool.
- A GUI application.
- An AI-first product.
- A forensic authority that declares a capture safe.

PCAT can say "this is suspicious" or "this is worth inspecting". It should not overclaim certainty. Findings should keep evidence, confidence, and next steps visible.

## Intended Users

PCAT is built for:

- CTF players who need to quickly find flags, credentials, files, encoded strings, and protocol clues.
- Students learning network forensics.
- Analysts doing quick triage before opening a capture in deeper tooling.
- Teams that need consistent JSON/CSV reports from many captures.
- Developers who want a practical CLI foundation for PCAP workflow automation.

PCAT is not designed for unattended high-stakes incident response without human review. Generated reports may contain sensitive captured data, and PCAT does not redact by default.

## Design Principles

### Evidence Before Conclusions

PCAT should preserve the observation that caused a finding. A useful finding must point back to frames, streams, strings, artifacts, hosts, or protocol records. This is why V2 introduced `EvidenceRecord` and stable evidence IDs.

### Tool-Friendly, Not Tool-Hostile

PCAT should pair well with existing packet tools. It should generate filters, hashes, CSV rows, JSON, and manifests that are easy to use elsewhere. Wireshark/TShark remain the source of packet parsing. Future Zeek and Suricata support should enrich PCAT, not replace those tools.

### Explicit Degradation

Optional capabilities should fail visibly but not catastrophically. If `capinfos` is missing, capture metadata is limited. If `scikit-learn` is missing, ML anomaly scoring is skipped. The report should explain skipped capabilities.

### Structured Output Is A First-Class Product

The terminal output is for quick reading. The JSON and CSV outputs are for reuse. Every command supports `--json` so PCAT can be used in scripts, notebooks, test harnesses, and future integrations.

### Safe Defaults For File Writes

Generated output belongs in a case folder and should not be committed accidentally. V2 uses:

```text
<pcap-file-name>-pcat/<capture-name>/
```

Those folders are ignored by git through `*-pcat/`. Raw PCAP byte artifact extraction is noisy, so extraction focuses on packet payload artifacts by default. Raw extraction is opt-in.

### No Redaction By Default

PCAT is used for investigation, so the current implementation does not hide evidence by default. This means reports may contain passwords, tokens, private hostnames, internal URLs, uploaded content, or challenge flags. Redaction controls are planned but not implemented yet.

## Implemented Architecture

The current implementation is a Python package under `src/pcat`.

```text
src/pcat/
  cli.py            command-line interface and command handlers
  analysis.py       main analysis pipeline, detectors, findings, queue
  tshark_parser.py  TShark field extraction and packet normalization
  capture.py        capture metadata, capinfos, protocol hierarchy
  evidence.py       normalized evidence records and finding links
  artifacts.py      magic-byte detection, validation, extraction, manifest
  stringtools.py    string extraction, search, flags, credentials, decoders
  reports.py        terminal, Markdown, HTML, JSON, and CSV output
  models.py         dataclasses and schema version
  utils.py          input validation, tool versions, output folders
  errors.py         typed CLI errors and exit codes
```

Tests live under `tests/`.

## Data Flow

The full `analyze` pipeline works like this:

1. Validate the input path and mode from the CLI.
2. Build capture metadata with local file data, `capinfos`, and TShark protocol hierarchy when available.
3. Parse packet fields through TShark.
4. Normalize packets into `PacketRecord`.
5. Build summaries, flows, streams, DNS records, HTTP records, SMTP records, MQTT records, payload maps, strings, and artifact candidates.
6. Run detectors to produce findings.
7. Optionally run ML anomaly scoring if dependencies and data are available.
8. Score streams and artifacts.
9. Build the investigation queue and handoff hints.
10. Build timeline events.
11. Build normalized evidence records and link findings to evidence.
12. Render terminal output or write selected report files.

## Primary Data Model

The schema version is currently `0.2`.

Implemented model groups:

- `CaptureRecord`: file identity and capture-level metadata.
- `ToolRun`: optional tool status, version, command, and error.
- `PacketRecord`: normalized packet fields from TShark.
- `FlowRecord`: bidirectional host/port/protocol conversation summary.
- `StreamRecord`: TCP stream/conversation summary when stream IDs exist.
- `DnsRecord`, `HttpRecord`, `SmtpRecord`, `MqttRecord`: protocol-specific records.
- `ArtifactRecord`: file signature, validation, score, extraction, hash, and manifest metadata.
- `EvidenceRecord`: normalized evidence with stable ID, source module, confidence, anchors, preview, fields, and handoff filters.
- `Finding`: human-readable issue or clue linked to evidence.
- `InvestigationItem`: prioritized next-step queue.
- `HandoffHint`: Wireshark/tcpdump style commands or filters.
- `TimelineEvent`: chronological finding/evidence event.
- `AnalysisReport`: top-level report object.

## Implemented Capabilities

### Capture Understanding

PCAT can identify file size, SHA256, packet count, duration, capture times, encapsulation, capture application, interface lines, strict time order, and protocol hierarchy when the local tools expose them.

### Packet And Protocol Views

PCAT currently extracts TShark fields for:

- Frame number, time, length, protocol stack, and protocol column.
- IPv4 and IPv6 source/destination.
- TCP and UDP ports.
- TCP flags, TCP payload length, and TCP stream ID.
- DNS query, common answer fields, and response code where TShark exposes them.
- HTTP host, method, URI, full URI, user agent, status, content type, and content length.
- TLS SNI.
- ICMP type.
- Generic data, TCP payload, and UDP payload bytes.
- SMTP command, parameter, response, response code, message, auth username, and auth password.
- MQTT message type, topic, text, username, and password.

### Findings And Triage

Implemented findings include:

- Possible port scan or broad fan-out.
- Heavy talker.
- HTTP POST.
- HTTP download or large transfer.
- Large plaintext HTTP upload.
- Suspicious HTTP extension.
- Credential-like values in HTTP metadata.
- SMTP activity and email-like clues.
- MQTT topic/message/credential clues.
- DNS anomalies such as long/random-looking domains and error-heavy DNS.
- CTF flag-like strings.
- Credential-like strings.
- Decoded base64/hex/base85-looking strings.
- Clue-like strings with terms such as password, decode, archive, URL, and flag.
- Base64 payload fragment reconstruction.
- Artifact hits from packet payloads or raw file bytes.
- Beacon-like timing.
- Unusual port usage.
- ICMP payloads.
- TCP SYN packets with payload.
- USB/non-network capture note.

### Artifact Management

Implemented magic-byte signatures:

- PNG.
- JPG.
- GIF.
- PDF.
- ZIP.
- gzip.
- RAR.
- 7z.
- ELF.
- BMP.
- SQLite.

Implemented artifact behavior:

- Detect signatures in packet payloads and optionally raw PCAP bytes.
- Validate known structures where possible.
- Mark artifacts as `validated`, `signature_only`, or `invalid`.
- Score artifacts by type, source, validation, and tags.
- Skip invalid artifacts during extraction.
- Hash extracted artifacts with SHA256.
- Add file type metadata when the local `file` command is available.
- Record ZIP members, encryption, and macro-related names when present.
- Write `artifacts/manifest.json`.

## Output Philosophy

PCAT produces outputs for different audiences:

- Terminal output: fast reading.
- Markdown/HTML/TXT: human reports.
- `report.json`: complete structured report.
- `evidence.json`: normalized evidence list.
- CSV files: spreadsheet and notebook workflows.
- `artifacts/manifest.json`: reproducible extracted artifact metadata.
- Handoff hints: filters and commands for deeper tools.

## Implemented Commands

Current command surface:

- `analyze`: full triage pipeline.
- `summary`: capture summary.
- `streams`: stream/conversation view.
- `dns`: DNS-focused view.
- `http`: HTTP-focused view.
- `evidence`: structured evidence records.
- `timeline`: chronological finding/evidence view.
- `strings`: printable strings from raw bytes and payloads.
- `search`: string search.
- `files`: magic-byte file signature detection.
- `artifacts`: artifact manager view.
- `extract`: artifact extraction and manifest writing.
- `suspicious`: suspicious artifact ranking.
- `hunt`: CTF-oriented hunt.
- `doctor`: environment and dependency check.

Every command supports `--json`.

## Dependency Model

Required:

- Python 3.10+.
- TShark from Wireshark.

Optional:

- `capinfos` for richer capture metadata.
- `file` for extracted artifact type labels.
- `7z` for environment awareness and future archive workflows.
- `scikit-learn` for optional ML anomaly scoring.
- Zeek and Suricata are checked by `doctor` but are not required for the V2 baseline.

## Security And Privacy Model

PCAT reads PCAPs and writes local files. It does not intentionally send data to external services.

Important privacy rules:

- No redaction by default.
- Reports can contain sensitive captured data.
- Generated output folders are git-ignored by default.
- Users should not publish PCAPs or generated reports without checking contents.

Artifact extraction is best-effort. Extracted files may be malicious. Users should inspect them with normal malware-handling caution.

## Current Limitations

Implemented PCAT still has boundaries:

- It requires TShark for packet parsing.
- It does not perform live capture.
- It does not provide a GUI.
- It does not reassemble full streams as a first-class workflow.
- Timeline events are basic.
- HTML output is readable but simple.
- Zeek and Suricata are detected but not orchestrated yet.
- Raw artifact hits can be noisy.
- Some protocol fields depend on what TShark exposes for that capture.
- The tool can miss data hidden in protocols or encodings it does not parse yet.

## Planned Features

Planned work should remain separate from implemented behavior in documentation and reports.

### Later Integration Layer

Planned:

- Run Zeek against a PCAP.
- Ingest existing Zeek log directories.
- Import `conn.log`, `dns.log`, `http.log`, and `files.log`.
- Later import `ssl.log`, `x509.log`, and `weird.log`.
- Run Suricata offline against a PCAP.
- Ingest Suricata `eve.json`.
- Map Suricata alerts, DNS, HTTP, fileinfo, and anomaly events into PCAT findings.
- Correlate PCAT flows, streams, hosts, artifacts, Zeek UIDs, and Suricata alerts.
- Preserve external signature and log metadata.

### Workflow Automation

Planned:

- `commands.md` with reproducible PCAT, TShark, Zeek, Suricata, and tcpdump commands.
- Batch analysis for many PCAPs.
- Directory analysis.
- Shortcut command aliases.
- Optional reduced PCAP generation for high-priority findings.
- Better Wireshark, TShark, tcpdump, Arkime, and Zui handoff bundles.

### Analysis Improvements

Planned:

- Full stream reassembly workflow.
- More complete decoder engine.
- XOR, gzip, zlib, deflate, brotli, recursive archive/content decoding, and JWT parsing.
- Deeper TLS analysis.
- More advanced ICMP covert-channel detection.
- Better cross-evidence correlation rules.
- More complete protocol artifact extraction for SMTP, FTP, SMB, and reassembled streams.

### Reporting Improvements

Planned:

- Better HTML report layout.
- Rich/colorized terminal output.
- More complete raw packet evidence sections.
- Redaction profiles.
- Sample/demo reports once sample data is stable.
- Optional LLM summarization as a later add-on, not a core requirement.

## Contribution Model

Contributors should preserve PCAT's evidence-first shape.

Good contributions:

- Add a parser or detector that produces structured evidence.
- Link findings to evidence IDs.
- Add clear handoff filters or commands.
- Keep reports and JSON stable.
- Add tests for new behavior.
- Keep optional dependencies optional.
- Update both architecture and technical docs when behavior changes.

Contributors should avoid:

- Adding opaque findings with no evidence.
- Silently requiring new external tools.
- Making raw extraction noisier by default.
- Adding AI or network calls into the core pipeline.
- Committing generated reports or artifact folders.
- Turning PCAT into a replacement for tools it should integrate with.

## Architectural North Star

PCAT should become a small, reliable integration layer for PCAP triage. The strongest version is not the one with the most detectors. The strongest version is the one that gives analysts a clean path from capture to evidence to next action, while preserving enough structure for automation and enough context for human judgment.
