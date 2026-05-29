# PCAT Technical Reference

This document is the technical reference for PCAT V2. It describes what PCAT can do, what data it reads, what data it writes, what commands exist, and what features are planned but not implemented yet.

For architectural goals and design philosophy, see `PCAT_ARCHITECTURE.md`.

## Version And Runtime

Current PCAT version:

```text
0.2.3
```

Current report schema version:

```text
0.2.3
```

Required runtime:

- Python 3.10 or newer.
- TShark from Wireshark.

Optional runtime tools:

- `capinfos`: richer capture metadata.
- `file`: extracted artifact type labels.
- `7z`: checked by `doctor`; reserved for richer archive workflows.
- `scikit-learn`: optional ML anomaly scoring.
- Zeek and Suricata: checked by `doctor`; planned for a later integration milestone.

## Installation

Install from the repository root:

```bash
python3 -m pip install -e .
```

Run without installing:

```bash
PYTHONPATH=src python3 -m pcat --help
```

Run tests:

```bash
pytest
```

## Input Rules

PCAT accepts files that TShark/Wireshark can parse. Common supported input forms:

- `.pcap`
- `.pcapng`
- `.cap`
- `.pcap.gz`
- valid capture files with unusual extensions

PCAT does not reject an input only because the extension is unusual. TShark/libwiretap is the parse authority.

Archive handling:

- `.zip`, `.7z`, `.rar`, `.tar`, and similar files are not unpacked automatically.
- Extract archives first, then run PCAT on the contained capture.

Failed-download handling:

- HTML-looking files are reported as likely placeholder pages or failed downloads.
- Download the raw capture and retry.

Input can be passed explicitly:

```bash
pcat analyze -i capture.pcap
```

Most commands also accept positional input:

```bash
pcat analyze capture.pcap
```

Do not pass both positional input and `-i/--input` in the same command. PCAT treats that as an invalid argument.

## Global Command Behavior

Common options on PCAP-reading commands:

- `PCAP`: optional positional input path.
- `-i, --input PCAP`: explicit input path.
- `-v, --verbose`: print concise progress details.
- `--quiet`: suppress normal terminal chatter.
- `--json`: print command output as JSON.
- `--debug`: show Python traceback on errors.

Help behavior:

```bash
pcat -h
pcat analyze -h
pcat -h analyze
pcat help analyze
```

Every command supports `--json`. For commands that can also write files, `--json` controls terminal output, not whether report files are written.

## Exit Codes

PCAT uses typed errors with these exit codes:

- `0`: success.
- `1`: generic analysis failure.
- `2`: invalid arguments.
- `3`: missing dependency.
- `4`: input file error.
- `5`: report writing error.
- `130`: interrupted by user.

## Analyst Briefing And Stories

V2.2 adds first-read guidance above raw evidence.

`briefing` appears in `report.json`, `summary --json`, and terminal output. It includes:

- capture type
- top hooks
- top risks
- limitations
- recommended next commands

`stories` appears in `report.json` and `stories.json`. Story records include:

- story ID
- kind
- title
- why it matters
- severity
- confidence
- supporting evidence IDs
- anchors
- recommended next command
- limitations

## Output Folder Rules

If output is requested and `-o/--out` is not provided, PCAT writes to:

```text
<pcap-file-name>-pcat/<pcap-stem>/
```

Example:

```text
chall2.pcapng -> chall2.pcapng-pcat/chall2/
```

Rules:

- `-o/--out DIR` overrides the default.
- Existing output folders require `--force`.
- Generated output folders matching `*-pcat/` are ignored by git.
- The legacy `/pcat/` output folder is also ignored by git.

## Report Files

When report generation is requested, PCAT can write:

- `report.json`: complete structured report.
- `evidence.json`: normalized evidence records only.
- `stories.json`: grouped evidence stories only.
- `findings.json`: findings only.
- `report.html`: simple HTML report.
- `report.md`: Markdown report.
- `report.txt`: full terminal-style text report.
- `flows.csv`: flow table.
- `hosts.csv`: host counts.
- `dns.csv`: DNS records.
- `http.csv`: HTTP records.
- `artifacts.csv`: artifact records.
- `findings.csv`: finding records.
- `artifacts/manifest.json`: extracted artifact manifest when extraction runs.

Default file formats when `-o` is used without `-f`:

```text
html,json,csv
```

Explicit formats:

```bash
pcat analyze -i capture.pcap -f html,json,csv,md,txt
```

Supported format aliases:

- `markdown` -> `md`
- `plaintext` -> `txt`
- `terminal` -> terminal output selector

## Capture Metadata

PCAT builds a `CaptureRecord` for full analysis and JSON summary output.

Fields:

- `path`
- `name`
- `stem`
- `size_bytes`
- `sha256`
- `file_type`
- `encapsulation`
- `interfaces`
- `packet_count`
- `start_time`
- `end_time`
- `duration`
- `strict_time_order`
- `capture_application`
- `protocol_hierarchy`

Sources:

- File stat and SHA256 hashing.
- `capinfos`, when available.
- `tshark -r <pcap> -q -z io,phs`, when available.

If optional metadata tools fail or are missing, PCAT records warnings instead of hiding the limitation.

## Packet Fields Parsed

PCAT calls TShark with `-T fields` and normalizes these fields:

- `frame.number`
- `frame.time_epoch`
- `frame.len`
- `frame.protocols`
- `_ws.col.Protocol`
- `ip.src`, `ip.dst`
- `ipv6.src`, `ipv6.dst`
- `tcp.srcport`, `tcp.dstport`
- `udp.srcport`, `udp.dstport`
- `tcp.flags`
- `tcp.len`
- `tcp.stream`
- `dns.qry.name`
- `dns.a`
- `dns.flags.rcode`
- `http.host`
- `http.request.method`
- `http.request.uri`
- `http.request.full_uri`
- `http.user_agent`
- `http.response.code`
- `http.content_type`
- `http.content_length_header`
- `http.content_length`
- `tls.handshake.extensions_server_name`
- `icmp.type`
- `data.data`
- `tcp.payload`
- `udp.payload`
- `smtp.req.command`
- `smtp.req.parameter`
- `smtp.response`
- `smtp.response.code`
- `smtp.message`
- `smtp.auth.username`
- `smtp.auth.password`
- `mqtt.msgtype`
- `mqtt.topic`
- `mqtt.msg_text`
- `mqtt.username`
- `mqtt.passwd`

PCAT raises the CSV field size limit before reading TShark output so large fields are less likely to crash parsing.

## Protocol Selection

PCAT chooses a display protocol from the TShark protocol stack and protocol column. Preferred protocol labels include:

- MQTT
- SMTP
- HTTP
- HTTP2
- TLS
- QUIC
- DNS
- MDNS
- LLMNR
- NBNS
- SSDP
- DHCP
- ICMP
- IGMP
- ARP
- USB
- USBHID

If no preferred protocol matches, PCAT falls back to the TShark protocol column or the last protocol in the stack.

## Internal Records

### `PacketRecord`

One parsed packet. It stores frame metadata, endpoint data, protocol data, payload hex, and protocol-specific fields.

### `FlowRecord`

A bidirectional summary keyed by endpoint pair and protocol. It tracks:

- source and destination endpoint
- protocol
- packet count
- byte count
- start/end time
- duration
- TCP stream IDs
- TCP flags
- tags
- optional anomaly score

### `StreamRecord`

A TCP stream/conversation summary when TShark exposes `tcp.stream`. It tracks:

- stream ID
- protocol
- source and destination endpoint
- packet count
- byte count
- start/end time
- duration
- preview
- tags
- interest score

### Protocol Records

PCAT has protocol-specific records for:

- DNS.
- HTTP.
- SMTP.
- MQTT.

These records are used by commands, reports, evidence generation, and findings.

### `ArtifactRecord`

Tracks detected and extracted file-like objects:

- artifact ID
- kind
- source
- source type
- source evidence ID
- declared type
- validated type
- filename
- size
- SHA256
- path
- certainty
- validation
- magic header validity
- structure validity
- complete-file validity
- truncation status
- source scope
- skip reason
- duplicate pointer
- encrypted flag
- member list
- manifest path
- extraction status
- tags
- score
- reasons

Artifact certainty values:

- `confirmed`: structure and complete-file validation succeeded.
- `candidate`: signature was observed, but PCAT cannot fully validate structure or completeness, or the type only supports signature-level validation.
- `rejected`: magic bytes matched, but structure validation failed; extraction is skipped.

Artifact validation values:

- `validated`: PCAT could validate both structure and completeness for the supported type.
- `signature_only`: PCAT found a known magic header, but the validator cannot prove a complete file.
- `truncated`: PCAT found a plausible header/structure but the available bytes are incomplete.
- `invalid`: the magic-byte hit failed structure validation.

Artifact source scopes:

- `packet_payload`: found in a parsed packet payload.
- `raw_capture`: found in raw capture bytes.
- `http_object`, `stream_reassembled`, and `tftp_object` are reserved for later object/reassembly features.

### `EvidenceRecord`

Central V2 evidence type. Fields include:

- evidence ID
- evidence type
- source tool
- source module
- protocol
- timestamp
- frame start/end
- stream ID
- source/destination endpoint
- structured fields
- preview
- confidence
- confidence score
- directly observed flag
- inferred flag
- related artifact IDs
- handoff filters

### `Finding`

Human-readable finding linked to evidence:

- finding ID
- title
- category
- risk score
- severity
- evidence IDs
- evidence summaries
- old-style evidence text
- explanation
- next step
- confidence
- direct/inferred flags
- source/destination
- related object
- handoff hints

## Evidence Types Implemented

PCAT currently generates these evidence types:

- `flow`
- `stream`
- `dns_query`
- `http_request`
- `http_upload`
- `http_download`
- `smtp_command`
- `smtp_message`
- `smtp_auth_credential`
- `mqtt_message`
- `syn_payload`
- `icmp_payload`
- `raw_string`
- `payload_string`
- `decoded_string`
- `artifact_signature`
- `artifact_extracted`

Evidence records may include Wireshark-style filters such as:

```text
frame.number == 42
tcp.stream == 7
ip.addr == 10.0.0.5 && ip.addr == 10.0.0.9
```

## Findings Implemented

PCAT currently detects or summarizes:

- Possible port scan.
- Many destination ports from one source.
- Heavy talker.
- HTTP POST request.
- HTTP response/download candidate.
- Large HTTP transfer.
- Large plaintext HTTP upload.
- Suspicious HTTP file extension.
- Possible credential in HTTP metadata.
- SMTP activity.
- Email-like clue strings.
- MQTT activity.
- MQTT credential-like data.
- Long or random-looking DNS queries.
- DNS response errors.
- CTF flag-like strings.
- Credential-like strings.
- Decoded base64/hex/base85-looking strings.
- Clue-like strings.
- Reconstructed base64 payload fragments.
- Embedded artifact/file signatures.
- Beacon-like regular timing.
- Unusual port usage.
- ICMP payload-bearing packets.
- TCP SYN packets with payload.
- USB/non-network capture note.

Findings are scored from `0` to `100`.

Severity mapping:

- `0`: `info`
- `1-24`: `low`
- `25-49`: `medium`
- `50-74`: `high`
- `75-100`: `critical`

## String And Decoder Features

PCAT can extract printable strings from:

- Raw PCAP bytes.
- TCP/UDP/data payload bytes parsed by TShark.

String features:

- Minimum length filter.
- Regex or literal search.
- Case-insensitive search.
- Output to text file.
- Flag detection.
- Custom CTF flag template through `--ctf-flag "FORMAT{<flag>}"`.
- Credential-like string detection.
- Clue-like terms such as password, pass, decode, archive, URL, mission, target, template, and flag.

Implemented decoders:

- Base64-like tokens.
- Hex-like tokens.
- Base85/ascii85-like tokens near hints.
- Short base64 payload fragment reconstruction from packet payloads.

Decoder output is heuristic. PCAT only keeps decoded values that look mostly printable/useful.

## Artifact Features

Supported signatures:

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

Validation behavior:

- PNG, JPG, GIF, PDF, gzip, BMP, SQLite, ELF, and ZIP receive basic structure validation.
- RAR and 7z are currently treated as signature-only.
- Invalid, truncated, incomplete, and source-missing artifacts are not selected for extraction.

Scoring behavior considers:

- File type value.
- Packet payload source versus raw PCAP source.
- Validation state.
- ZIP bonus.
- Encrypted archive tag.
- Macro-enabled Office indicators inside ZIP names.
- ELF and SQLite unusualness.

Extraction behavior:

- Writes to `<out>/artifacts/`.
- Uses ranked artifact order after filtering out rejected, truncated, incomplete, and source-missing hits.
- Honors `--limit` for extractable selections.
- Computes SHA256.
- Sets extracted file path, size, validation, type tag, and extraction status.
- Writes `artifacts/manifest.json`.
- Suppresses the outer gzip wrapper of `.pcap.gz` inputs so it is not reported as an embedded artifact.

Raw PCAP extraction is disabled by default for `extract` and `analyze --extract`. Use:

```bash
pcat extract -i capture.pcap --include-raw
pcat analyze -i capture.pcap --extract --include-raw-artifacts
```

## ML Anomaly Scoring

ML scoring is optional.

It is skipped when:

- `--no-ml` is set.
- There are not enough flows.
- `scikit-learn` is not installed.
- The ML step raises an exception.

When skipped, PCAT records the reason in `skipped`.

## Command Reference

### `pcat analyze`

Runs the full analysis pipeline.

Syntax:

```bash
pcat analyze [PCAP] -i PCAP [options]
```

Main options:

- `-m, --mode triage|ctf`: select mode.
- `--ctf`: shortcut for CTF mode.
- `--triage`: shortcut for triage mode.
- `-o, --out DIR`: output folder.
- `--force`: allow writing into an existing output folder.
- `-f, --format LIST`: comma-separated formats.
- `--no-terminal`: suppress terminal report.
- `--top N`: top terminal rows.
- `--min-risk N`: minimum risk score for finding ranking.
- `--extract`: extract detected artifacts.
- `--extract-limit N`: maximum extracted artifacts.
- `--include-raw-artifacts`: include raw PCAP byte hits during extraction.
- `--no-ml`: disable optional ML anomaly scoring.
- `--ctf-flag PATTERN`: custom CTF flag format.
- `--json`: print full report JSON.

Output:

- Terminal report unless disabled.
- Optional report files.
- Optional extracted artifacts and manifest.

### `pcat summary`

Prints a quick capture summary.

```bash
pcat summary -i capture.pcap
pcat summary capture.pcap --top 20
pcat summary -i capture.pcap --json
```

Shows:

- File.
- Size.
- Packet count.
- Duration.
- Protocol counts.
- Top hosts.
- Top ports.
- Analyst briefing.

JSON mode includes schema version, capture metadata, summary, briefing, stories, and warnings.

### `pcat streams`

Lists ranked TCP streams/conversations.

```bash
pcat streams -i capture.pcap
pcat streams capture.pcap --top 25
pcat streams -i capture.pcap --json
```

Shows:

- TCP stream ID.
- Endpoint pair.
- Packet count.
- Byte count.
- Interest score.

### `pcat dns`

Shows DNS-focused data.

```bash
pcat dns -i capture.pcap
pcat dns capture.pcap --top 50
pcat dns -i capture.pcap --json
```

Shows:

- Top DNS queries.
- DNS records with frame, source, destination, query, answer, and response code.

### `pcat http`

Shows HTTP-focused data.

```bash
pcat http -i capture.pcap
pcat http capture.pcap --top 50
pcat http -i capture.pcap --json
```

Shows:

- Top HTTP hosts.
- HTTP records with frame, stream, method, URI, status, content type, and content length.

### `pcat evidence`

Shows normalized evidence records.

```bash
pcat evidence -i capture.pcap
pcat evidence capture.pcap --type http_request --top 50
pcat evidence -i capture.pcap --json
```

Options:

- `--type TYPE`: filter by exact evidence type.
- `--top N`: display limit.

Shows:

- Evidence ID.
- Evidence type.
- Confidence.
- Frame and stream anchors.
- Handoff filters.
- Preview.

### `pcat timeline`

Shows timeline events.

```bash
pcat timeline -i capture.pcap
pcat timeline capture.pcap --top 100
pcat timeline -i capture.pcap --json
```

Behavior:

- Uses finding timeline when findings exist.
- Timeline events use linked evidence timestamps when available.
- Events without a known timestamp render as `unknown` and use `null` in JSON.
- Falls back to timestamped evidence when finding timeline is empty and sorts that evidence chronologically before applying `--top`.
- Low-context unknown-time decoder/clue events are hidden from the default timeline.

### `pcat strings`

Extracts printable strings.

```bash
pcat strings -i capture.pcap
pcat strings -i capture.pcap --grep flag --ignore-case
pcat strings -i capture.pcap --source packet --grep flag
pcat strings -i capture.pcap --output strings.txt
pcat strings -i capture.pcap --json
```

Options:

- `--min N`: minimum string length.
- `--grep PATTERN`: regex filter.
- `--ignore-case`: case-insensitive filter.
- `--output FILE`: write extracted strings to a file.
- `--limit N`, `--top N`: maximum printed rows.
- `--source all|raw|packet`: choose the string source. `all` uses enabled raw and packet-payload sources.
- `--no-raw`: skip raw PCAP byte scanning.
- `--no-payloads`: skip packet payload scanning.

Invalid regex patterns return invalid-argument exit code `2`.

### `pcat search`

Searches extracted strings.

```bash
pcat search -i capture.pcap password
pcat search -i capture.pcap "flag\\{.*\\}" --regex
pcat search capture.pcap token --ignore-case --limit 50
pcat search -i capture.pcap flag --source packet
pcat search -i capture.pcap password --json
```

Options:

- `keyword`: required search term or regex.
- `--regex`: treat keyword as regex.
- `--ignore-case`: case-insensitive search.
- `--min N`: minimum string length before search.
- `--limit N`, `--top N`: maximum printed rows.
- `--source all|raw|packet`: choose the same source index used by `strings`.
- `--no-raw`: skip raw PCAP byte scanning.
- `--no-payloads`: skip packet payload scanning.

Invalid regex patterns return invalid-argument exit code `2`.

### `pcat files`

Detects embedded file signatures.

```bash
pcat files -i capture.pcap
pcat files capture.pcap --no-raw
pcat files -i capture.pcap --json
```

Options:

- `--no-raw`: skip raw PCAP byte scanning.
- `--no-payloads`: skip packet payload scanning.
- `--limit N`, `--top N`: maximum rows.

Shows:

- File type.
- Source.
- Source scope.
- Offset.
- Score.
- Certainty.
- Validation.
- Completeness and truncation state.
- Tags.
- Reasons.
- Rejected hits grouped by type/reason in default stdout. Use `--verbose` or `--json` for individual rejected offsets.

### `pcat artifacts`

Shows the artifact manager view without writing files.

```bash
pcat artifacts -i capture.pcap
pcat artifacts capture.pcap --include-raw --top 100
pcat artifacts -i capture.pcap --json
```

Options:

- `--include-raw`: include raw PCAP byte scanning.
- `--no-payloads`: skip packet payload scanning.
- `--limit N`, `--top N`: maximum rows.

Default behavior focuses on packet payload artifacts.
Default stdout groups rejected artifacts by type/reason; JSON keeps individual records and all trust fields.

### `pcat extract`

Extracts/carves detected artifacts.

```bash
pcat extract -i capture.pcap
pcat extract -i capture.pcap --include-raw
pcat extract -i capture.pcap --http
pcat extract -i capture.pcap -o extracted-case --force --limit 10
pcat extract -i capture.pcap --json
```

Options:

- `-o, --out DIR`: output folder.
- `--force`: allow writing into existing folder.
- `--http`: export HTTP objects with TShark when possible.
- `--include-raw`: include raw PCAP byte carving.
- `--no-raw`: legacy alias; raw carving is already disabled unless `--include-raw` is set.
- `--no-payloads`: skip packet payload carving.
- `--limit N`, `--top N`: maximum extracted artifacts.

Writes:

- Extracted files under `<out>/artifacts/`.
- `<out>/artifacts/manifest.json`.
- HTTP-exported objects under `<out>/http_objects/` when `--http` is used and TShark exports objects.

Reports:

- Found, selected, extracted, unextractable rejected/incomplete, validation-failed, incomplete, missing-source, and raw-disabled counts.
- HTTP object export count and status separately from artifact carving.
- A `--include-raw` recommendation when useful artifacts were skipped because raw carving is disabled.

### `pcat suspicious`

Ranks suspicious artifact/file hits.

```bash
pcat suspicious -i capture.pcap
pcat suspicious capture.pcap --type zip,pdf,png --min-risk 30
pcat suspicious -i capture.pcap --json
```

Options:

- `--no-raw`: skip raw PCAP byte scanning.
- `--no-payloads`: skip packet payload scanning.
- `--type LIST`: comma-separated artifact type filter.
- `--min-risk N`: minimum artifact score.
- `--limit N`, `--top N`: maximum rows.

Shows:

- Score.
- Type.
- Source.
- Offset.
- Certainty.
- Validation.
- Tags.
- Reasons.
- Next-step extraction command.

### `pcat hunt`

Runs a CTF-oriented hunt.

```bash
pcat hunt -i capture.pcap
pcat hunt capture.pcap --ctf-flag "CTF101{<flag>}" --limit 50
pcat hunt -i capture.pcap --json
```

Options:

- `--min N`: minimum string length.
- `--limit N`, `--top N`: maximum rows per section.
- `--ctf-flag PATTERN`: custom flag pattern.

Sections:

- Possible flags, including spaced flag strings when they can be normalized safely.
- Possible credentials/secrets, including decoded SMTP AUTH values when TShark exposes them.
- Possible email clues.
- Possible clues.
- Decoded-looking strings.
- HTTP object/transfer clues.
- SMTP records.
- MQTT records.
- ICMP payload clues for obvious protocol banners.
- SYN payload candidates.
- Detected files.
- Recommended next steps.

### `pcat doctor`

Checks environment readiness.

```bash
pcat doctor
pcat doctor --json
```

Checks:

- PCAT version.
- Python version.
- `tshark`.
- `capinfos`.
- `file`.
- `7z`.
- `zeek`.
- `suricata`.
- `scikit-learn`.

Zeek and Suricata are not required for the current V2 baseline.

## JSON Report Structure

Top-level `report.json` fields:

- `summary`
- `schema_version`
- `capture`
- `tools`
- `hosts`
- `conversations`
- `evidence`
- `findings`
- `investigation_queue`
- `flows`
- `streams`
- `dns_records`
- `http_records`
- `smtp_records`
- `mqtt_records`
- `artifacts`
- `timeline`
- `handoff`
- `notes`
- `skipped`
- `warnings`
- `errors`
- `tool_versions`

`evidence.json` is the `evidence` list only.

`findings.json` is the `findings` list only.

## CSV Reference

### `flows.csv`

Columns:

- `flow_id`
- `src_ip`
- `src_port`
- `dst_ip`
- `dst_port`
- `protocol`
- `packets`
- `bytes`
- `duration`
- `tags`
- `anomaly_score`

### `hosts.csv`

Columns:

- `host`
- `count`

### `dns.csv`

Columns:

- `frame`
- `timestamp`
- `src_ip`
- `dst_ip`
- `query`
- `answer`
- `rcode`

### `http.csv`

Columns:

- `frame`
- `timestamp`
- `stream_id`
- `src_ip`
- `dst_ip`
- `host`
- `method`
- `uri`
- `status`
- `content_type`
- `content_length`
- `user_agent`

### `artifacts.csv`

Columns:

- `artifact_id`
- `kind`
- `source`
- `source_scope`
- `offset`
- `filename`
- `path`
- `size`
- `sha256`
- `certainty`
- `validation`
- `magic_header_valid`
- `structure_valid`
- `complete_file_valid`
- `truncated`
- `extraction_status`
- `skip_reason`
- `score`
- `tags`

### `findings.csv`

Columns:

- `finding_id`
- `title`
- `category`
- `severity`
- `risk_score`
- `confidence`
- `related`
- `evidence_ids`
- `next_step`

## Handoff Output

PCAT can generate handoff hints for:

- Wireshark display filters.
- tcpdump host filters.
- TCP stream filters.

Examples:

```text
ip.addr == 10.0.0.5 && ip.addr == 10.0.0.9
host 10.0.0.5 and host 10.0.0.9
tcp.stream == 4
```

Handoff filters are embedded in findings, evidence records, and terminal reports where applicable.

## Privacy And Safety

PCAT does not redact by default.

`pcat analyze --redact` is intentionally unsupported in this version and exits with code `2`. The hidden `--no-redact` compatibility flag is a no-op.

Reports may contain:

- Passwords.
- Tokens.
- Cookies.
- Internal hostnames.
- Private URLs.
- Email contents.
- File contents or metadata.
- CTF flags.

Extracted artifacts may be malicious. Treat extracted files as untrusted.

## Known Implemented Limitations

- TShark is required.
- No live capture.
- No GUI.
- No first-class full stream reassembly workflow.
- Simple HTML report only.
- Timeline depends on linked evidence; some events may legitimately have unknown time.
- Protocol extraction depends on TShark exposing fields.
- Raw file artifact hits are noisy.
- Artifact `candidate` records are leads; inspect completeness/truncation/source-scope fields before trusting them.
- Packet-local artifacts can be fragments of larger HTTP, TFTP, MQTT, or stream data.
- Redaction behavior is not implemented yet; the visible workflow is no-redaction by default.
- Zeek and Suricata are only checked by `doctor`, not orchestrated.

## Planned Features Not Yet Implemented

These are planned or proposed. They should not be described as implemented behavior.

### V2.4 Protocol Views And Reassembly

- DNS clustering, ranking, and encoded-label grouping.
- HTTP stream/object grouping and short-response ranking.
- MQTT topic/message/payload view and export.
- TFTP transfer grouping and object export with completeness metadata.
- UDP conversation ranking for non-TCP workflows.
- ICMP trail summaries with payload/covert-channel hints.

### External Tool Integrations

- Run Zeek on a PCAP.
- Ingest Zeek logs.
- Parse Zeek `conn.log`, `dns.log`, `http.log`, and `files.log`.
- Later parse Zeek `ssl.log`, `x509.log`, and `weird.log`.
- Run Suricata offline on a PCAP.
- Ingest Suricata `eve.json`.
- Convert Suricata alerts and protocol metadata into findings/evidence.
- Correlate Zeek, Suricata, and PCAT records.

### Command And Workflow Features

- `commands.md` with reproducible commands.
- Short command aliases.
- `pcat capture.pcap` as shorthand for analyze.
- Batch PCAP analysis.
- Directory analysis.
- PCAP input from stdin.
- Reduced PCAP generation from suspicious conversations.
- Richer handoff bundles for Wireshark, TShark, tcpdump, Zeek, Suricata, Arkime, and Zui.

### Analysis Features

- Full stream reassembly.
- TFTP object reassembly/export.
- MQTT message and payload export.
- DNS encoded-label grouping.
- USB/HID keyboard triage or precise handoff.
- Deeper TLS analysis.
- Advanced ICMP covert-channel detection.
- More flexible custom flag matching.
- More complete artifact extraction across SMTP, FTP, SMB, HTTP, and streams.
- Stronger archive/password correlation.
- Better rule engine for multi-evidence findings.

### Decoder Features

- CTF decoder hints before full auto-solving.
- ROT13 clue detection.
- Base64/base32/hex grouping for DNS labels.
- Base85 hints for MQTT or nearby clue text.
- XOR brute force.
- gzip/zlib/deflate/brotli decoding.
- Recursive archive/content decoding.
- JWT structured parsing.
- More complete URL, HTML entity, quoted-printable, and PowerShell UTF-16LE decoding.

### Reporting Features

- Rich/colorized terminal output.
- Better HTML report.
- More complete raw packet evidence sections.
- Redaction profiles.
- Committed sample/demo reports.
- Optional LLM summary add-on.

## Implementation Map

Main files:

- `src/pcat/cli.py`: CLI, command definitions, command handlers, JSON output.
- `src/pcat/analysis.py`: main pipeline, summaries, detectors, findings, investigation queue.
- `src/pcat/tshark_parser.py`: TShark field extraction and packet parsing.
- `src/pcat/capture.py`: file hash, capinfos parsing, protocol hierarchy.
- `src/pcat/evidence.py`: evidence generation and finding-to-evidence links.
- `src/pcat/artifacts.py`: signature detection, validation, scoring, extraction, manifest.
- `src/pcat/stringtools.py`: strings, search, flag detection, credential detection, decoders.
- `src/pcat/reports.py`: terminal, Markdown, HTML, JSON, CSV writers.
- `src/pcat/models.py`: dataclasses and schema.
- `src/pcat/utils.py`: input validation, file classification, parse guidance, dependency versions, output folder handling.
- `src/pcat/errors.py`: typed errors and exit codes.

Tests:

- `tests/test_artifacts.py`
- `tests/test_cli.py`
- `tests/test_models.py`
- `tests/test_stringtools.py`
- `tests/test_tshark_parser.py`
- `tests/test_utils.py`
- `tests/test_analysis_v21.py`
- `tests/test_v2_contract.py`

## Maintenance Checklist

When adding a feature:

- Add or update dataclasses if new structured output is needed.
- Emit evidence, not only terminal text.
- Link findings to evidence IDs.
- Add JSON fields deliberately.
- Keep optional dependencies optional.
- Add tests.
- Update this technical reference.
- Update `PCAT_ARCHITECTURE.md` if the design philosophy or architecture changes.
- Keep implemented and planned features separated.
