# PCAT Future CTF Update Plan

Date: 2026-05-22

This document captures CTF-oriented feedback from the PCAT `0.2.2` test cycle. It is intentionally separate from the V2.3 trust-hardening work, which now covers timeline, artifact, extraction, search, and output-noise issues in `0.2.3`. The CTF work below should happen later, after PCAT's general triage output is reliable.

## Product Position

PCAT should not become a full CTF solver.

The right CTF role is:

- identify likely challenge paths quickly
- group CTF-looking evidence by protocol/source
- suggest likely decoders
- run safe, simple decoders when confidence is high
- provide exact verification commands
- preserve evidence IDs and frame/stream anchors

PCAT should avoid:

- flooding output with speculative decodes
- ranking normal infrastructure as high-value CTF evidence
- claiming decoded answers without evidence context
- hiding the source of reconstructed strings

## CTF Update Goals

### Challenge Lead Summary

Add a compact CTF-first summary that lists the top 3-5 likely paths.

Example lead categories:

- SYN payload trail
- DNS encoded labels
- HTTP clue response
- MQTT topic/payload clue
- TFTP transferred file
- USB HID keyboard data
- suspicious artifact candidate

Each lead should include:

- why it is suspicious
- frame/stream/source anchors
- evidence IDs
- likely next command
- confidence
- whether it was decoded, partially decoded, or only hinted

### Decoder Hints Before Auto-Solving

Add decoder hints as evidence-backed suggestions. Auto-decode only when inputs are bounded and confidence is high.

Decoder hints from the latest test:

- ROT13-looking clues in HTTP/text responses.
- DNS labels that look like base64 chunks.
- MQTT payloads near text saying "decode with Python base85".
- USB HID keyboard packets.
- TFTP transferred firmware or binary payloads.

Potential commands or output sections:

- `pcat hunt --decode-hints`
- `pcat decode-candidates`
- `pcat dns --decode-labels`
- `pcat hunt --decode base85`
- `pcat hunt --hid-keyboard`

### DNS CTF Workflow

Needed behavior:

- Rank long, high-entropy, repeated, base64-like, and chunk-like labels above ordinary DNS.
- Group labels by suffix/domain and source host.
- Preserve original order options:
  - frame order
  - timestamp order
  - label sequence if visible
- Try safe base64/base32/hex decode on grouped labels.
- Report failures as candidates, not facts.

Useful output:

- domain group
- source host
- frame range
- label count
- entropy/readability
- decoded candidate preview
- exact TShark command

### MQTT CTF Workflow

Needed behavior:

- Add a clean MQTT table/view before deep decoder work.
- Show frame, stream, topic, message text, payload hex, username/password presence, and endpoints.
- Group messages by topic and stream.
- If nearby clue text says base85/base64/hex, try that decoder on topic/message payload chunks.
- Export MQTT payloads to a predictable folder/file format in a later protocol workflow release.

Useful output:

- `mqtt.csv`
- per-topic message groups
- payload text files
- decoder hint records
- command to inspect the TCP stream in Wireshark/TShark

### USB HID CTF Workflow

Needed behavior:

- Detect USB/HID keyboard-like captures.
- Summarize endpoints/interfaces where possible.
- Suggest exact handoff if PCAT cannot reconstruct keystrokes.
- Later, optionally reconstruct common HID keyboard reports.

Minimum useful behavior before full decoding:

- "This looks like USB HID keyboard data."
- frame range
- endpoint/interface hints
- command or script suggestion
- limitation language

### HTTP CTF Workflow

Needed behavior:

- Rank short unusual text responses higher than bulk traffic.
- Promote response bodies that contain decoder hints, flag-adjacent text, ROT13-looking strings, archive passwords, or challenge instructions.
- Keep decoy flag handling conservative: list decoys as evidence but avoid letting them bury stronger DNS/protocol clues.
- Improve HTTP object accounting so object export and artifact carving are not confused.

### TFTP CTF Workflow

Needed behavior:

- Detect TFTP read/write requests and filenames.
- Group DATA blocks by transfer.
- Reassemble/export transferred objects when blocks are complete enough.
- Mark completeness clearly.
- Suggest binwalk/file/strings commands for firmware-like objects.

### Noise Control

Default CTF output should suppress or downgrade:

- Let's Encrypt/OCSP/certificate infrastructure URLs
- SSDP/UPnP NOTIFY text
- normal telemetry hosts
- UUID-looking values
- ordinary mDNS/LLMNR noise
- unreadable base64/base85 garbage
- duplicate raw-file and packet-level copies of the same string

Speculative decodes should move to:

- `--verbose`
- `--show-decode-candidates`
- a separate decode-candidates command

## Acceptance Criteria For Future CTF Release

- CTF output still starts with a short lead summary.
- DNS base64 label captures produce grouped decode candidates.
- MQTT/base85 captures produce a clear MQTT lead and decoder hint.
- ROT13 clue text is identified or explicitly suggested.
- USB HID captures get an accurate HID handoff at minimum.
- TFTP firmware-style transfers are grouped and, when possible, exported with completeness metadata.
- Decoy HTTP flags do not bury stronger DNS/protocol evidence.
- Speculative junk decodes are hidden by default.

## Relationship To V2.3 And V2.4

V2.3 must happen first because CTF output needs trustworthy artifact, timeline, extraction, search, and ranking semantics.

V2.4 protocol views should happen before or alongside the CTF update because DNS/MQTT/TFTP/HTTP improvements are useful for both CTF and general triage.

The CTF update should reuse V2.3/V2.4 primitives instead of inventing a separate CTF-only pipeline.
