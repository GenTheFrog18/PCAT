# PCAT V2 Manual

PCAT means **PCAP Assistant for Triage**. It is an offline command-line tool for first-pass PCAP analysis, CTF-style artifact hunting, and basic network forensics triage.

This manual is written so V2 can be tested systematically.

## Requirements

Required:

- Python 3.10+
- `tshark`

Optional:

- `scikit-learn` for ML anomaly scoring.
- `pytest` for running the test suite.

Install locally from the repository root:

```bash
python3 -m pip install -e .
```

Run without installing:

```bash
PYTHONPATH=src python3 -m pcat --help
```

## Global Behavior

PCAT accepts capture files that TShark/Wireshark can parse. Common supported inputs include `.pcap`, `.pcapng`, `.cap`, `.pcap.gz`, and valid captures with unusual extensions.

Archives are not unpacked automatically. Extract `.zip`, `.7z`, `.rar`, `.tar`, and similar files first, then run PCAT on the contained capture.

If a file looks like HTML, PCAT reports it as a likely failed download or placeholder page. Download the raw capture and retry.

Input can be passed with `-i`:

```bash
pcat analyze -i capture.pcap
```

Most commands also accept positional input:

```bash
pcat analyze capture.pcap
```

Do not use both at the same time. This should fail:

```bash
pcat analyze capture.pcap -i capture.pcap
```

Generated output is written under the selected output folder. If output is requested without `-o`, PCAT uses:

```text
<pcap-file-name>-pcat/<pcap-stem>/
```

For example, `chall2.pcapng` writes to `chall2.pcapng-pcat/chall2/`.

If the output folder already exists, PCAT should fail unless `--force` is used.

PCAT does not redact by default. Generated reports may contain passwords, tokens, cookies, private URLs, internal hostnames, uploaded files, or other sensitive data.

V2 adds evidence-first output and safer workspace behavior:

- Every command supports `--json`.
- `report.json` contains a schema version, capture metadata, tools, summary, briefing, stories, hosts, conversations, streams, evidence, artifacts, findings, timeline, handoff, warnings, and errors.
- `evidence.json` contains normalized evidence records with stable IDs, confidence, frame/stream anchors, previews, and handoff filters.
- `stories.json` contains grouped evidence stories for analyst-first review.
- CSV export writes `flows.csv`, `hosts.csv`, `dns.csv`, `http.csv`, `tftp.csv`, `artifacts.csv`, and `findings.csv`.
- Artifact extraction writes `artifacts/manifest.json`.
- Raw PCAP byte carving is opt-in for extraction because it is noisy; payload artifacts remain the default extraction target.
- Large TShark fields should not crash normal parsing.
- TCP/UDP payload strings are parsed directly when available.
- Artifact hits include certainty: `confirmed`, `candidate`, or `rejected`, plus the technical validation state.
- `extract --limit N` limits how many artifacts are actually written.
- Invalid, truncated, incomplete, and source-missing artifacts are not selected for extraction.
- The outer gzip wrapper of a `.pcap.gz` input is not treated as an embedded artifact.
- Generated next-step commands quote paths that contain spaces.

## Exit Codes

Expected exit codes:

- `0`: success.
- `1`: analysis failed.
- `2`: invalid arguments.
- `3`: missing dependency.
- `4`: input file error.
- `5`: report writing error.

## Commands Overview

```bash
pcat analyze     # Full triage analysis
pcat summary     # Quick capture summary
pcat streams     # Ranked TCP streams and UDP conversations
pcat dns         # DNS-focused view
pcat http        # HTTP-focused view
pcat evidence    # Structured V2 evidence records
pcat timeline    # Chronological findings/evidence view
pcat strings     # Extract printable strings
pcat search      # Search strings, decoded values, protocols, evidence, findings, and artifacts
pcat artifacts   # Artifact manager view
pcat extract     # Carve artifacts and export HTTP/TFTP objects
pcat hunt        # CTF-oriented automatic hunt
pcat doctor      # Dependency and environment check
```

Hidden compatibility aliases remain callable for older scripts: `pcat files`, `pcat suspicious`, and `pcat tftp`. They are intentionally not part of the normal help workflow.

Help is available globally and per command:

```bash
pcat -h
pcat analyze -h
pcat -h analyze
pcat help analyze
pcat --help-simple
pcat extract --help-simple
```

## `pcat analyze`

Runs the full PCAP triage pipeline.

Basic:

```bash
pcat analyze -i capture.pcap
```

CTF mode:

```bash
pcat analyze -i capture.pcap --ctf
```

Explicit triage mode:

```bash
pcat analyze -i capture.pcap -m triage
```

Generate reports:

```bash
pcat analyze -i capture.pcap -o pcat/test-run
```

Generate selected formats:

```bash
pcat analyze -i capture.pcap -o pcat/test-run -f html,json,csv,md,txt
```

Extract artifacts during analysis:

```bash
pcat analyze -i capture.pcap --ctf --extract -o pcat/test-run
```

Useful options:

- `-m, --mode triage|ctf`: choose analysis mode.
- `--ctf`: shortcut for CTF mode.
- `--triage`: shortcut for triage mode.
- `-o, --out PATH`: output folder.
- `--force`: allow writing to existing output folder.
- `-f, --format`: comma-separated output formats.
- `--no-terminal`: do not print terminal report.
- `--top N`: number of terminal results, default `10`.
- `--min-risk N`: minimum risk score, default `10`.
- `--extract`: extract artifacts.
- `--extract-limit N`: maximum artifacts to write when `--extract` is used, default `50`.
- `--include-raw-artifacts`: include noisy raw PCAP byte hits during extraction.
- `--no-ml`: disable ML anomaly scoring.
- `--ctf-flag "FORMAT{<flag>}"`: custom CTF flag format.
- `--json`: print full structured report JSON to stdout.
- `--debug`: show traceback on errors.

Expected terminal sections:

- Capture summary.
- Protocols.
- Top hosts.
- Top ports.
- Top DNS queries, if any.
- Top HTTP hosts, if any.
- Investigation queue.
- Evidence highlights.
- Top findings.
- Tool handoff hints.
- Warnings from optional metadata/tool stages.
- Skipped capabilities.
- Notes.

Expected default report files when `-o` is provided without `-f`:

```text
report.html
report.json
evidence.json
stories.json
findings.json
flows.csv
hosts.csv
dns.csv
http.csv
tftp.csv
artifacts.csv
findings.csv
```

Expected files when `-f html,json,csv,md,txt` is used:

```text
report.html
report.md
report.txt
report.json
evidence.json
stories.json
findings.json
flows.csv
hosts.csv
dns.csv
http.csv
tftp.csv
artifacts.csv
findings.csv
```

Things to test:

- Valid PCAP.
- Invalid/corrupt PCAP.
- Existing output folder with and without `--force`.
- `--no-ml`.
- `--ctf`.
- `--ctf-flag`.
- `--extract`.
- `--no-terminal`.

## `pcat summary`

Shows a quick overview of the capture.

```bash
pcat summary -i capture.pcap
```

Expected output:

- File path.
- Size.
- Packet count.
- Duration.
- Protocol counts.
- Top hosts.
- Top ports.

Useful option:

- `--top N`: controls number of listed items.

Things to test:

- Normal PCAP.
- Small PCAP.
- PCAP with multiple hosts.
- PCAP with DNS/HTTP traffic.

## `pcat streams`

Shows ranked TCP streams and UDP conversations. TCP rows use `tcp.stream` IDs when TShark exposes them. UDP rows are grouped by normalized endpoints and protocol so UDP-heavy captures, including DNS and TFTP, are no longer invisible in the stream view.

```bash
pcat streams -i capture.pcap
```

Expected output:

- `tcp.stream` ID or UDP conversation ID.
- Source and destination.
- Protocol.
- Packet count.
- Byte count.
- Interest score.

Useful option:

- `--top N`

Things to test:

- PCAP with TCP streams.
- PCAP with few/no TCP streams but UDP traffic.
- Large stream/file download traffic.

## `pcat dns`

Shows DNS-focused information.

```bash
pcat dns -i capture.pcap
```

Expected output:

- Top DNS queries.
- DNS records with frame number, source, destination, query, answer, and response code.

Useful option:

- `--top N`

Things to test:

- DNS-heavy PCAP.
- PCAP with no DNS.
- Long/random-looking domains.
- NXDOMAIN or failed DNS responses.

## `pcat http`

Shows HTTP-focused information.

```bash
pcat http -i capture.pcap
```

Expected output:

- Top HTTP hosts.
- HTTP records with frame number, stream ID, method, host/URI, status, content type, and content length when available.
- HTTP file-transfer candidates in `analyze`/`hunt` when responses look like downloads or large uploads.

Useful option:

- `--top N`

Things to test:

- PCAP with HTTP GET.
- PCAP with HTTP POST.
- PCAP with file downloads.
- PCAP with no HTTP.

## TFTP Workflow

TFTP is handled through the evidence and extraction commands instead of a dedicated public mode. This keeps protocol object export together with other extraction workflows.

```bash
pcat evidence -i capture.pcap --type tftp_transfer --json
pcat extract -i capture.pcap --tftp -o case-output
pcat extract -i capture.pcap --tftp --include-incomplete-tftp -o case-output
```

Useful options on `pcat extract`:

- `--tftp`: write recoverable complete TFTP objects to `<out>/tftp_objects/`.
- `--include-incomplete-tftp`: export transfers with bytes even when completeness is `unknown`, `incomplete`, or `error`.
- `--limit N`, `--top N`: artifact and TFTP export limit, default `50`.
- `-o, --out PATH`: output folder.
- `--force`: allow existing output folder.
- `--json`: emit extraction metadata, including the TFTP export summary.

Expected output:

- Transfer ID.
- Filename when present in RRQ/WRQ metadata.
- Direction: `download`, `upload`, or `unknown`.
- Client and server IP.
- Request frame.
- Block count.
- Byte count.
- Completeness: `complete`, `unknown`, `incomplete`, `metadata_only`, or `error`.
- Export path and SHA256 when `extract --tftp` writes a file.

Things to test:

- TFTP read request with a complete transfer.
- TFTP transfer where data is present but no final short block is visible.
- TFTP error packet.
- `extract --tftp` with and without `--include-incomplete-tftp`.

## `pcat evidence`

Shows normalized V2 evidence records.

```bash
pcat evidence -i capture.pcap
pcat evidence -i capture.pcap --type http_request --top 50
pcat evidence -i capture.pcap --json
```

Expected output:

- Stable evidence ID.
- Evidence type, such as `flow`, `stream`, `udp_conversation`, `dns_query`, `http_request`, `smtp_auth_credential`, `tftp_transfer`, `artifact_signature`, `payload_string`, or `syn_payload`.
- Confidence level.
- Frame or stream anchor when available.
- Preview text.
- Handoff filters for tools such as Wireshark/TShark.

Useful options:

- `--type TYPE`: filter by evidence type.
- `--top N`: display limit.
- `--json`: emit machine-readable evidence records.

## `pcat timeline`

Shows chronological events from findings. PCAT uses linked evidence timestamps when available and prints `unknown` when an event has no trustworthy timestamp. If no findings timeline exists, PCAT falls back to timestamped evidence records sorted chronologically.

```bash
pcat timeline -i capture.pcap
pcat timeline -i capture.pcap --top 100 --json
```

Useful options:

- `--top N`: display limit.
- `--json`: emit machine-readable timeline records.

## `pcat strings`

Extracts printable strings from raw PCAP bytes and packet payloads.

Basic:

```bash
pcat strings -i capture.pcap
```

Search while extracting:

```bash
pcat strings -i capture.pcap --grep flag --ignore-case
pcat strings -i capture.pcap --source packet --grep flag
```

Write strings to a file:

```bash
pcat strings -i capture.pcap --output strings.txt
```

Useful options:

- `--min N`: minimum string length, default `5`.
- `--grep PATTERN`: regex/string filter.
- `--ignore-case`: case-insensitive match.
- `--output PATH`: write output to file.
- `--limit N`: display limit, default `200`.
- `--source all|raw|packet`: choose the string source.
- `--no-raw`: skip raw PCAP byte scanning.
- `--no-payloads`: skip packet payload scanning.

Things to test:

- Search for `flag`.
- Search for `password`.
- Save to a text file.
- Compare with `--no-raw`.
- Compare with `--no-payloads`.
- Invalid regex should fail with exit code `2` and a concise parser message.

## `pcat search`

Searches PCAT's evidence index by keyword or regex. The default scope is `all`, which searches strings, decoded values, protocol records, evidence records, findings, and artifacts. Use a narrower `--scope` when you want faster or more targeted output.

Keyword search:

```bash
pcat search -i capture.pcap password
```

Regex search:

```bash
pcat search -i capture.pcap "flag\\{.*\\}" --regex
```

Protocol-only search:

```bash
pcat search -i capture.pcap firmware --scope protocols
```

Useful options:

- `--regex`: treat keyword as regex.
- `--ignore-case`: case-insensitive match.
- `--scope all|strings|decoded|evidence|protocols|artifacts|findings`: choose search scope.
- `--min N`: minimum string length.
- `--limit N`: display limit.
- `--source all|raw|packet`: choose source behavior for string-backed scopes.
- `--no-raw`: skip raw PCAP byte scanning.
- `--no-payloads`: skip packet payload scanning.

Things to test:

- Literal keyword that exists.
- Literal keyword that does not exist.
- Regex match.
- Protocol metadata match, for example TFTP filename or HTTP host.
- Invalid regex behavior.
- Invalid regex should fail with exit code `2`.

## `pcat files`

Hidden deprecated compatibility alias for artifact listing. It detects embedded file signatures using magic bytes and keeps the older raw-scan default for scripts, but new workflows should use `pcat artifacts`.

```bash
pcat files -i capture.pcap
```

Useful options:

- `--no-raw`: skip raw PCAP byte scanning.
- `--no-payloads`: skip payload scanning.
- `--limit N`, `--top N`: display limit, default `200`.

Detected signatures in V2:

- PNG.
- JPEG.
- GIF.
- PDF.
- ZIP.
- gzip.
- RAR.
- 7z.
- ELF.
- PE/MZ.
- BMP.
- SQLite.

Expected output:

- File type.
- Source, such as `raw-file` or `packet:<number>`.
- Offset.
- Suspicion score.
- Certainty, such as `confirmed`, `candidate`, or `rejected`.
- Validation state.
- Tags, such as `validated`, `signature_only`, `invalid`, `encrypted`, or `office-macro`.
- Reason.

Things to test:

- PCAP with downloaded files.
- CTF PCAP with embedded ZIP/PDF/image.
- False positives from raw PCAP bytes.

## `pcat artifacts`

Shows the consolidated artifact manager view without writing files.

```bash
pcat artifacts -i capture.pcap
pcat artifacts -i capture.pcap --include-raw --top 100
pcat artifacts -i capture.pcap --type pe,zip --min-score 40
pcat artifacts -i capture.pcap --suspicious --extractable
pcat artifacts -i capture.pcap --json
```

By default this command prioritizes packet payload artifacts. Use `--include-raw` when you want the noisier raw PCAP scan too.

Useful options:

- `--include-raw`: include raw PCAP byte hits.
- `--no-payloads`: skip packet payload scanning.
- `--type LIST`: comma-separated artifact types such as `pe,zip,pdf`.
- `--min-score N`: minimum artifact score.
- `--extractable`: only show artifacts PCAT would select for extraction.
- `--show-rejected`: include rejected hits in text output.
- `--suspicious`: apply suspicious-artifact ranking defaults.
- `--limit N`, `--top N`: display limit.
- `--json`: emit machine-readable artifact records.

## `pcat extract`

Carves detected artifacts and exports supported protocol objects into an output folder.

```bash
pcat extract -i capture.pcap
pcat extract -i capture.pcap --http --tftp -o case-output
```

Useful options:

- `-o, --out PATH`: output folder.
- `--force`: allow existing output folder.
- `--http`: export HTTP objects with `tshark` when possible.
- `--tftp`: export complete TFTP transfer objects to `<out>/tftp_objects/`.
- `--include-incomplete-tftp`: export incomplete or unknown-completeness TFTP transfers when bytes are available.
- `--include-raw`: include raw PCAP byte carving. This is disabled by default.
- `--no-raw`: legacy alias; raw carving is already disabled unless `--include-raw` is used.
- `--no-payloads`: skip payload carving.
- `--limit N`, `--top N`: maximum artifacts to extract, default `50`.
- `--json`: emit extraction metadata.

Expected output folder:

```text
<out>/artifacts/
<out>/artifacts/manifest.json
<out>/http_objects/        # only when --http exports objects
<out>/tftp_objects/        # only when --tftp exports objects
```

Expected metadata:

- Number of artifacts found, selected, and extracted.
- Selected certainty counts for confirmed, candidate, and rejected hits.
- Unextractable rejected/incomplete hit counts.
- Counts for skipped raw-disabled, validation-failed, incomplete, and missing-source artifacts.
- HTTP object export count/status when `--http` is used.
- TFTP transfer found/exported/skipped counts when `--tftp` is used.
- Extracted path.
- SHA256 hash.
- Certainty label.
- Validation state.
- Completeness, truncation, source scope, and skip reason in JSON/manifest records.
- Manifest entry.

Things to test:

- Extract from PCAP with embedded ZIP/PDF/image.
- Existing output folder without `--force`.
- Existing output folder with `--force`.
- `--http` on HTTP PCAP.
- `--tftp` on TFTP PCAP.

## `pcat suspicious`

Hidden deprecated compatibility alias for `pcat artifacts --suspicious`. It ranks detected artifact/file signatures by investigation value and keeps the older option names for scripts, but new workflows should use `pcat artifacts --suspicious`.

```bash
pcat suspicious -i capture.pcap
```

Useful options:

- `--type zip,pdf,png`: filter by type.
- `--min-risk N`: minimum score, default `20`.
- `--limit N`, `--top N`: display limit.
- `--no-raw`
- `--no-payloads`

Expected output:

- Score.
- File type.
- Source.
- Offset.
- Validation state and tags.
- Reason.
- Suggested next steps.

Things to test:

- PCAP with multiple artifact types.
- Type filter.
- Different `--min-risk` values.

## `pcat hunt`

Runs a CTF-oriented hunt workflow.

```bash
pcat hunt -i capture.pcap
```

Custom flag format:

```bash
pcat hunt -i capture.pcap --ctf-flag "CTF101{<flag>}"
```

Useful options:

- `--min N`: minimum string length.
- `--limit N`: display limit per section.
- `--ctf-flag FORMAT`: custom flag format.

Expected sections:

- Possible flags, including spaced flags that can be normalized safely.
- Possible credentials/secrets, including decoded SMTP AUTH values when TShark exposes them.
- Possible email clues.
- Possible clue strings.
- Decoded-looking strings.
- HTTP object / transfer clues.
- SMTP records.
- MQTT records.
- TFTP transfers.
- ICMP payload clues.
- SYN payload candidates.
- Detected files.
- Recommended next steps.

Things to test:

- CTF PCAP with flag.
- PCAP with credentials.
- PCAP with base64/hex-looking strings.
- PCAP with short base64 fragments split across packets.
- PCAP with TCP SYN packets carrying payload.
- PCAP with SMTP or MQTT traffic.
- PCAP with TFTP traffic.
- PCAP with embedded files.
- PCAP with no obvious CTF evidence.

## `pcat doctor`

Checks local dependencies and optional integration tools.

```bash
pcat doctor
pcat doctor --json
```

Expected output:

- PCAT version.
- Python version.
- Tool availability for `tshark`, `capinfos`, `file`, `7z`, `zeek`, and `suricata`.
- Optional `scikit-learn` status.

## Systematic Test Matrix

Use different PCAPs if available:

| PCAP Type | Commands To Run | Expected Result |
| --- | --- | --- |
| Small valid PCAP | `summary`, `analyze` | No crash, basic summary |
| DNS traffic | `dns`, `analyze` | DNS queries appear |
| HTTP traffic | `http`, `analyze` | HTTP hosts/paths appear |
| HTTP POST | `http`, `analyze` | HTTP POST finding |
| SMTP email | `hunt`, `search` | Email clues, URLs, or password-like lines appear |
| MQTT traffic | `hunt`, `analyze` | MQTT topics/messages appear |
| TFTP transfer | `evidence --type tftp_transfer`, `extract --tftp`, `streams`, `hunt`, `analyze` | TFTP transfer metadata appears; export writes recoverable complete objects |
| SYN payloads | `hunt`, `analyze` | SYN payload candidate appears |
| Port scan | `analyze` | Scan/recon finding |
| CTF flag | `strings`, `search`, `hunt` | Flag-like string appears |
| Credentials | `strings`, `hunt`, `analyze` | Credential-like finding |
| Embedded file | `artifacts`, `extract` | File signature and extracted artifact |
| Evidence output | `evidence --json`, `analyze --json` | Stable evidence IDs and schema version appear |
| Artifact manifest | `extract` | `artifacts/manifest.json` is written |
| Large HTTP/multipart | `summary`, `http`, `hunt`, `analyze` | No CSV field-size crash |
| Encoded text | `hunt`, `analyze` | Decoded-looking string |
| Invalid file | any command | Friendly error, exit code 4 |
| Existing output folder without `--force` | `analyze -o`, `extract -o` | Friendly error, exit code 5 |
| Invalid regex | `strings --grep`, `search --regex` | Friendly error, exit code 2 |
| Missing `tshark` | `analyze` | Friendly error, exit code 3 |

## Suggested First Test Session

Replace `sample.pcap` with your own file:

```bash
pcat summary -i sample.pcap
pcat analyze -i sample.pcap --no-ml
pcat evidence -i sample.pcap --json
pcat timeline -i sample.pcap
pcat strings -i sample.pcap --grep flag --ignore-case
pcat search -i sample.pcap password --ignore-case
pcat artifacts -i sample.pcap
pcat artifacts -i sample.pcap --suspicious
pcat evidence -i sample.pcap --type tftp_transfer --json
pcat extract -i sample.pcap --tftp -o sample-output
pcat hunt -i sample.pcap
pcat analyze -i sample.pcap --ctf --extract -f html,json,csv,md,txt
```

Check:

```bash
find sample.pcap-pcat/sample -maxdepth 2 -type f | sort
```

## Known V2 Limitations

- PCAT requires `tshark`.
- PCAT lets TShark decide capture parseability; if TShark cannot parse a file, PCAT reports guidance based on the detected input type.
- ML scoring is skipped if `scikit-learn` is missing.
- Artifact carving is best-effort and can produce false positives.
- Artifact `candidate` records are leads; check completeness/truncation/source-scope fields before trusting them.
- Raw-file artifact hits are noisier than packet-payload hits; check validation before trusting them.
- Timeline events without linked timestamps are explicitly shown as unknown.
- Full TCP stream reassembly, MQTT payload export, USB HID decoding, and deeper CTF decoder hints are planned improvements.
- Some protocol fields may not appear depending on the PCAP and `tshark` version.
- Zeek and Suricata orchestration are planned for a later integration milestone, not required for the V2 baseline.
- No redaction by default.
- No live capture.
- No GUI.
- No LLM/API integration.
