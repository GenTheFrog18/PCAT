# PCAT Roadmap And Decision Record

Date: 2026-05-22

This document records the current product decisions and roadmap after the first V2 test cycle. It is intentionally separate from the GitHub-facing technical docs because it includes planning context, testing interpretation, and future decisions.

## Current Situation

PCAT V2 has been pushed as a prototype/testing build. The first testing round shows that the core foundation is viable:

- Supported `.pcap` and `.pcapng` captures did not produce blocker/high reliability failures.
- Full reports, JSON, CSV files, evidence records, and artifact manifests are generated.
- Extraction limits are respected.
- Artifact extraction is bounded and does not execute files.
- Evidence-first architecture is still the right foundation.

The main weakness is not basic stability. The main weakness is that PCAT often produces facts without enough analyst judgment.

In practical terms:

- PCAT can say what it found.
- PCAT is not yet consistently good at saying what matters first, why it matters, what it cannot see, and what command the analyst should run next.

The next phase should therefore focus on reliability, triage judgment, grouping, and user trust before external integrations.

## Latest CTF-Oriented Test Read

A later PCAT `0.2.2` CTF-oriented test across `adikara.pcapng`, `arkav.pcapng`, `trace.pcap`, `shark1.pcapng`, `shark2.pcapng`, `vodka.uncompressed`, and `Trail.pcapng` confirmed the product direction but raised the bar for trust.

Critical interpretation:

- PCAT is useful as a 30-60 second scout, not as a replacement for Wireshark, TShark, NetworkMiner, Zeek, binwalk, CyberChef, or protocol scripts.
- The most urgent failures are not "more CTF tricks." They are trust failures: broken timelines, overconfident artifacts, wrong extraction recommendations, noisy stdout, and hidden useful records.
- CTF feedback is still valuable for general triage because CTF captures stress the same workflows: ranking, decoding hints, protocol views, object extraction, and honest handoff.
- V2.3 therefore became a trust/output hardening release. Deeper CTF decoding remains documented but deferred.

## Product Thesis

The strongest near-term identity for PCAT is:

> An offline five-minute PCAP briefing tool that turns an unknown capture into a defensible analyst starting point and a reusable evidence package.

PCAT should not try to become:

- Wireshark in CLI form.
- A replacement for TShark.
- A complete CTF solver.
- A malware sandbox.
- A full IDS.
- An AI-first summary product.
- A giant detector collection with no prioritization.

PCAT should instead focus on:

- Intake.
- Evidence.
- Analyst briefing.
- Evidence grouping.
- Handoff.
- Honest limitations.
- Structured case folders.

## Core Decisions

### Decision 1: Stabilization Comes Before Integrations

Decision:

External integrations such as Zeek and Suricata are pushed back to later versions.

Reason:

The first test cycle showed that PCAT does not need more raw inputs yet. It needs better interpretation of the data it already collects. Adding Zeek and Suricata now would likely increase the amount of output before PCAT has a mature grouping and briefing layer.

Impact:

- V2.1 focuses on stabilization, input handling, and parser reliability.
- V2.2 combines analyst briefing, limitation language, and evidence stories into one guidance milestone.
- Zeek/Suricata move to a later integration milestone.
- Integration design remains valid, but implementation waits until PCAT can group and explain evidence well.

### Decision 2: PCAT Should Optimize For First Read, Not Exhaustive Terminal Output

Decision:

Terminal output should start with a compact analyst briefing. Exhaustive detail belongs in JSON, CSV, Markdown, HTML, TXT, and artifact manifests.

Reason:

Test critique repeatedly shows that terminal output can become too long and flat. Analysts need decisions first, then details.

Impact:

- `summary` and `analyze` should start with a briefing section.
- The full report folder remains exhaustive.
- Terminal output should be aggressively edited.

### Decision 3: Evidence Records Are Foundation, Stories Are The Missing Layer

Decision:

PCAT should keep evidence records, but add grouped "stories" above them.

Reason:

Evidence records are good for automation, JSON, and provenance. They are weak as the main human interface when there are hundreds or thousands of records. Humans need grouped narratives.

Impact:

V2.2 should introduce grouped story objects such as:

- `http_transfer_story`
- `dns_anomaly_story`
- `artifact_story`
- `icmp_trail_story`
- `mqtt_topic_story`
- `syn_payload_story`
- `non_ip_capture_story`
- `encrypted_metadata_story`

`ctf_clue_story` should be considered later with the held CTF triage work unless it can be added as a thin wrapper around existing `hunt` evidence without expanding CTF scope.

Each story should include:

- title
- why it matters
- confidence
- supporting evidence IDs
- anchors such as frames, streams, domains, topics, artifacts, and hosts
- recommended next command
- limitation notes when relevant

### Decision 4: Intake Should Follow Analyst Reality, Not File Extension Purity

Decision:

PCAT should accept or clearly explain common capture-like inputs:

- `.pcap`
- `.pcapng`
- `.cap`
- magic-valid captures with odd extensions
- `.pcap.gz`
- archives that contain captures
- invalid or HTML-placeholder files

Reason:

Analysts think in terms of "can TShark/Wireshark parse this?", not "does this extension match PCAT's allowlist?"

Impact:

- Extension-only validation should be replaced or softened.
- TShark/libwiretap validation should become the real parse authority.
- Rejection messages should be format-specific and actionable.

### Decision 5: CTF Mode Needs Normalization, Not Puzzle Solving

Decision:

PCAT should not become a CTF solver, but CTF mode should eventually catch common low-effort clue obfuscations.

Reason:

The test found a spaced `p i c o C T F` flag that PCAT missed. This is exactly the kind of pattern users expect a CTF-aware triage tool to surface.

Impact:

The CTF work is held for a later V2.x milestone because it needs careful scope control. It should not distract from the immediate need to make PCAT reliable, readable, and useful as a general triage tool.

When resumed, CTF mode should normalize:

- spaced flag text
- null-separated flag text
- braced strings with separators
- mixed-case flag keywords
- obvious hashes
- CVE patterns
- suspicious URLs
- tunnel/tool keywords
- base64/hex-looking fragments

### Decision 6: Severity Means Analyst Priority

Decision:

Severity should represent analyst priority and confidence, not detector excitement.

Reason:

Repeated duplicate "critical" findings reduce trust. A valid signature is not automatically a critical artifact.

Impact:

- Duplicate and raw-carved artifacts should usually be lower priority.
- High/critical findings should require strong context or clear user value.
- Repeated findings should be grouped before severity is assigned.

### Decision 7: Limitations Are A Feature

Decision:

PCAT should explicitly say when a capture is outside its strongest workflow.

Reason:

For USB/HID, Bluetooth, QUIC/TLS-heavy, mixed encapsulation, malformed DNS, tiny captures, or unsupported link types, silence is confusing. Honest limitation language increases trust.

Impact:

PCAT should produce explicit limitation findings and handoff suggestions for:

- USB/HID captures
- Bluetooth/A2DP/SBC captures
- QUIC/TLS-heavy captures
- malformed or weak DNS extraction
- tiny captures with too little context
- raw IPv4 oddities
- unsupported or mixed encapsulations

### Decision 8: Case Caching Is Important But Not First

Decision:

Case caching or session workflow is important, but comes after reliability and briefing.

Reason:

Performance is acceptable for one-off reports, but repeated commands on medium captures are slow because PCAT reparses the same file. However, cache design is a larger workflow decision and should follow the case folder/story design.

Impact:

Caching is planned for a later V2.x milestone, not the first stabilization patch.

### Decision 9: V2.3 Is Trust Hardening Before More Capability

Decision:

V2.3 prioritizes timeline correctness, artifact completeness semantics, extraction accounting, stdout grouping, search consistency, and noise reduction.

Reason:

The latest test showed that misleading confidence is more damaging than missing a decoder. A user can work around a missing TFTP/MQTT/DNS decoder if PCAT gives an honest lead and command. A user loses trust when PCAT says a timeline event happened at `0.000000`, calls a truncated packet-local object confirmed, or recommends an extraction command that cannot extract the artifact it just promoted.

Impact:

- V2.3 expands beyond the earlier artifact-only scope.
- Artifact work remains central, but timeline, extraction UX, search consistency, and stdout grouping are part of the same trust release.
- Protocol reassembly and CTF decoder expansion move after trust hardening.

### Decision 10: Protocol Reassembly Is V2.4, Not V2.3

Decision:

TFTP export, MQTT payload views, DNS tunnel/base64 grouping, HTTP object ranking, and UDP stream/conversation handling should be treated as V2.4 protocol workflow work.

Reason:

Those features are valuable and came directly from testing, but they add new protocol-specific behavior. They should build on the V2.3 trust model so extracted/reassembled objects can report source scope, completeness, skipped reasons, and verification commands consistently.

Impact:

- V2.4 is renamed from generic protocol views to protocol views and reassembly.
- TFTP and MQTT are promoted into the V2.4 plan.
- V2.3 prepares the metadata fields and output language that V2.4 protocol exporters will reuse.

## Roadmap Overview

### V2.0: Evidence-First Prototype

Status: implemented and sent for testing.

Scope:

- CLI commands.
- Capture metadata.
- Evidence records.
- Report JSON.
- Evidence JSON.
- CSV exports.
- Artifact detection/extraction.
- Artifact manifests.
- Basic findings.
- CTF hunt.
- Documentation.

Known state:

- Stable enough for staged testing.
- Not yet sharp enough as an analyst guide.

### V2.1: Stabilization And Input Reliability

Goal:

Make PCAT feel reliable and mature on real analyst inputs before adding new product surface area.

V2.1 is a patch/consolidation release. Its job is not to make PCAT broader. Its job is to remove the rough edges that make testers question whether the tool can be trusted.

In scope:

- Input acceptance and rejection behavior.
- Exit codes and argument error handling.
- DNS extraction reliability.
- Clearer error messages.
- Regression tests for every confirmed bug class.
- Small documentation updates that explain changed behavior.

Out of scope:

- New integration systems.
- AI/LLM features.
- MCP features.
- New major command families.
- Large CTF clue expansion.
- Case caching.
- Major report redesign beyond bug-driven clarity fixes.

Primary work:

#### Input Acceptance

PCAT should treat TShark/libwiretap as the real parse authority where possible.

Work items:

- Accept `.cap` captures when TShark can parse them.
- Accept magic-valid PCAP/PCAPNG files with nonstandard extensions when TShark can parse them.
- Test whether `.pcap.gz` can be handled directly through TShark in the current implementation path.
- If `.pcap.gz` cannot be handled safely, return exact decompression guidance instead of generic extension rejection.
- Keep archive extraction out of scope for V2.1. Archives should be rejected with archive-specific guidance.
- Detect HTML placeholder/download-error files and explain that the input is likely not the real capture.

Acceptance rule:

- If TShark can parse the file and PCAT can process the resulting fields safely, PCAT should accept it even if the extension is unusual.
- If TShark cannot parse it, PCAT should explain the likely input class and next action.
- If the file is an archive, PCAT should not recursively unpack it in V2.1.

#### Regex And CLI Error Handling

Invalid user-supplied regex should be treated as an argument error, not a runtime failure.

Work items:

- Catch regex parser errors.
- Return invalid-argument exit code `2`.
- Show the regex parser message without a traceback.
- Add CLI tests for bad regex in every command path that accepts regex-like filters.

#### DNS Extraction Reliability

The first test showed cases where DNS appears in protocol counts but `dns_records` is empty or weak. That damages trust because the user can see that DNS exists but PCAT does not explain it.

Work items:

- Broaden DNS field extraction.
- Preserve the existing report schema where practical.
- Improve extraction for query names, response names, A records, AAAA records, CNAME records, PTR names, NS records, MX records, TXT records, and response codes where TShark exposes them.
- Distinguish "DNS present but malformed/unsupported" from "no DNS records found."
- Add a limitation/finding when DNS is visible in protocol counts but useful DNS records cannot be extracted.

#### Error Message Quality

PCAT should avoid generic "unsupported extension" messages when it can infer a better explanation.

Work items:

- Add input-class-specific guidance for archives.
- Add input-class-specific guidance for HTML files or failed downloads.
- Add parse-failure guidance that mentions Wireshark/TShark validation.
- Keep messages concise enough for CLI use.

#### V2.1 Tests

Regression tests should be added for:

- `.cap` acceptance or exact parse guidance.
- `.pcap.gz` support or exact decompression guidance.
- magic-valid PCAP/PCAPNG with odd extension.
- archive-specific rejection.
- HTML-placeholder rejection.
- invalid regex exit code `2`.
- DNS-present but weak-record extraction.
- DNS malformed/unsupported limitation text.

Why this matters:

First contact matters. A triage tool that rejects common capture formats feels brittle even if the core parser works.

Exit criteria:

- `.cap` fixture works or gives precise parse guidance.
- `.pcap.gz` fixture works or gives precise decompression guidance.
- nonstandard-extension PCAPNG fixture works or gives precise guidance.
- archive-like input gives archive-specific guidance.
- invalid regex returns exit code `2`.
- DNS parser gap has a regression test.
- Documentation mentions the supported/rejected input behavior accurately.
- No new major feature is introduced without a direct connection to the V2.1 bug list.

### V2.2: Analyst Briefing And Evidence Stories

Goal:

Make PCAT's first screen answer what matters, why it matters, what PCAT cannot see, and what the analyst should do next.

This combines the old V2.2 briefing milestone and the old V2.3 evidence-story milestone. These should be designed together because a useful briefing needs grouped evidence underneath it, and useful stories need a clear place in the analyst workflow.

Primary work:

- Add an `Analyst Briefing` section to `summary`.
- Add an `Analyst Briefing` section to `analyze`.
- Include capture type, top hooks, top risks, limitations, and next commands.
- Add story records above raw evidence.
- Link stories to supporting evidence IDs.
- Render top stories in terminal output and full stories in reports.
- Add explicit limitation findings for USB/HID.
- Add explicit limitation findings for Bluetooth/mixed encapsulation.
- Add explicit limitation findings for encrypted-heavy QUIC/TLS captures.
- Add explicit limitation findings for malformed DNS or unsupported parser cases.
- Make tiny CTF captures produce compact first-read summaries.
- Reduce duplicate terminal noise by grouping related findings before display.

Why this matters:

The critique says PCAT is too flat. A briefing turns facts into first-pass direction, and stories make the evidence readable without losing provenance.

Proposed briefing shape:

```text
Analyst Briefing
Capture type: mostly IPv4 HTTP/DNS with MQTT present
Top hooks:
  1. MQTT topic Shinen-8ff3ed-Operation on stream 11
  2. HTTP object candidates on streams 4, 7, 12
  3. DNS failures clustered under example.com
Limits:
  - TLS payloads are encrypted; PCAT can inspect metadata only.
Recommended next:
  - pcat mqtt -i file --topics
  - pcat http -i file --objects
  - pcat dns -i file --clusters
```

Story model:

Each story should include:

- `id`
- `kind`
- `title`
- `why_it_matters`
- `confidence`
- `severity`
- `supporting_evidence_ids`
- `anchors`
- `recommended_next_command`
- `limitations`

Initial story kinds:

- `artifact_story`
- `http_transfer_story`
- `dns_anomaly_story`
- `icmp_trail_story`
- `mqtt_topic_story`
- `syn_payload_story`
- `non_ip_capture_story`
- `encrypted_metadata_story`

Exit criteria:

- Terminal output starts with a concise briefing.
- `report.json` contains story records.
- Terminal output shows top stories before raw evidence.
- Stories include evidence IDs and handoff commands.
- Duplicate findings are reduced through grouping.
- USB/HID captures show a clear non-network handoff.
- Bluetooth captures show mixed/non-network handoff.
- QUIC/TLS-heavy captures explain visibility limits.
- Briefing recommends concrete next commands.

### V2.3: Trust, Timeline, Artifacts, And Output Noise

Goal:

Make PCAT's output trustworthy enough that users can follow its first-pass guidance without being misled.

Status:

Implemented in schema/tool version `0.2.3`.

Primary work:

- Fix timeline timestamps:
  - Stop rendering meaningful events at `0.000000` unless the packet really has timestamp `0`.
  - Prefer packet/evidence timestamps where available.
  - Mark unknown timestamps explicitly instead of pretending they are time zero.
  - Add regression coverage using captures or mocked records with nonzero timestamps.
- Improve artifact completeness semantics:
  - Separate `magic_header_valid`, `structure_valid`, and `complete_file_valid`.
  - Add `truncated: true/false/unknown`.
  - Add `source_scope` values such as `packet_payload`, `stream_reassembled`, `raw_capture`, `http_object`, and future `tftp_object`.
  - Do not call packet-local fragments complete without a warning.
  - Reduce confidence when validators cannot fully decode/open the object.
- Improve extraction accounting:
  - Count extracted, rejected, skipped because raw carving is disabled, skipped because source data is missing, skipped because validation failed, and HTTP objects exported separately.
  - If a recommendation requires raw carving, recommend the exact `--include-raw` command.
  - If HTTP export writes files, do not summarize the run as "Artifacts extracted: 0" without explaining HTTP object output.
- Group and deduplicate artifact output:
  - Group rejected artifacts by type and reason in default stdout.
  - Show individual rejected offsets only in `--verbose` or JSON.
  - Group overlapping candidates and mark canonical/sibling records.
  - Prevent repeated high/critical findings from one duplicate object.
- Make search behavior consistent:
  - `search` and `strings --grep` use the same source loading behavior.
  - Implemented source filters: `raw`, `packet`, and `all`.
  - Protocol-specific source filters such as `http`, `dns`, `mqtt`, and `reassembled` remain V2.4+ work.
- Reduce speculative decode and infrastructure noise:
  - Penalize common infrastructure strings such as OCSP URLs, SSDP/UPnP NOTIFY, telemetry hosts, UUIDs, and ordinary mDNS.
  - Require decoded-looking strings to pass stronger readability checks.
  - Move speculative decodes to `--verbose` or a later decoder-focused command.
- Keep default terminal output concise:
  - Default stdout should show grouped analyst-facing summaries.
  - Exhaustive evidence remains in JSON/CSV/report files.

Why this matters:

The latest tests showed that PCAT is already useful as a scout, but trust breaks when timestamps are wrong, artifacts are overclaimed, or recommended commands do not match extraction defaults.

Exit criteria:

- Timeline output uses real event timestamps or explicit unknown timestamps.
- A truncated packet-local gzip/JPG is not reported as a complete confirmed artifact.
- Raw-file artifacts produce extraction recommendations with `--include-raw`.
- HTTP object export reports object output separately from artifact carving.
- Rejected artifacts are grouped by type/reason in default stdout.
- `search` and `strings --grep` produce consistent results for the same source settings.
- Speculative decoded junk is reduced in default `hunt` output.
- Report JSON/manifest contains enough fields to explain artifact certainty, completeness, source scope, and skipped reasons.

Implementation notes:

- Timeline events now use linked evidence timestamps where possible and render unknown timestamps explicitly.
- Artifact records now include `magic_header_valid`, `structure_valid`, `complete_file_valid`, `truncated`, `source_scope`, `skip_reason`, and `duplicate_of`.
- Extraction output now reports raw-disabled skips, validation failures, incomplete artifacts, missing source data, and HTTP object export status separately.
- Default artifact stdout groups rejected records by type/reason; JSON and verbose output keep individual records.
- Default decoding/clue output filters common infrastructure noise more aggressively.

### V2.3.1: Trust Patch From 2026-05-29 Testing

Status:

Implemented as a patch under the existing `0.2.3` tool/schema version.

Primary work:

- Quote generated next-step commands everywhere so paths with spaces are copy-paste safe.
- Hide misleading redaction help; `--redact` exits with code `2` because redaction is not implemented.
- Return output/report error code `5` for existing output folders instead of input error code `4`.
- Suppress raw offset-0 gzip hits that are only the input `.pcap.gz` wrapper.
- Select only extractable artifacts for extraction while preserving rejected/incomplete metadata for review.
- Sort fallback timeline evidence chronologically and suppress low-context unknown-time decoder/clue noise.
- Add explicit empty-state messages for `http`, `dns`, and `streams`.
- Detect normalized spaced flag strings, promote decoded SMTP AUTH credentials, and promote obvious protocol banners inside ICMP payloads.
- Cap ordinary media artifact scores below critical unless future contextual scoring raises them.

Deferred from this patch:

- HTTP exploit-chain/story ranking.
- MIME/TNEF attachment export.
- MQTT payload export.
- DNS clustering and encoded-label grouping.

### V2.4: Command Consolidation And TFTP/UDP Protocol Workflow

Goal:

Reduce confusing command overlap, make search work across PCAT's evidence model, and fix the most painful UDP/TFTP workflow gaps without turning this release into a full protocol-reassembly project.

Status:

Implemented in schema version `0.2.4` and tool version `0.2.4`; CLI cleanup shipped as tool version `0.2.4.1`.

Primary work:

- Consolidate artifact-facing commands:
  - Keep `artifacts` as the main command.
  - Keep `files` and `suspicious` as compatibility aliases with deprecation warnings.
  - Add artifact filters for type, score, extractability, rejected-hit visibility, and suspicious ranking.
- Make `search` a global evidence search:
  - Search strings.
  - Search decoded values.
  - Search protocol records.
  - Search evidence records.
  - Search findings.
  - Search artifact records.
  - Keep string-source controls for raw/packet/all where they still apply.
- Add UDP conversation handling to `streams`:
  - Preserve TCP stream rows.
  - Add UDP conversation rows for non-TCP workflows.
  - Include frame bounds, protocol labels, packet counts, byte counts, and interest score.
- Add TFTP support:
  - Parse TFTP request/data/error fields from TShark.
  - Build packet-level TFTP records.
  - Group TFTP transfers with filename, direction, client/server, request frame, data frames, byte count, block count, and completeness.
  - Export complete transferred objects to `<out>/tftp_objects/` through `pcat extract --tftp`.
  - Allow explicit export of incomplete/unknown transfers with `--include-incomplete-tftp`.
  - Add TFTP evidence, stories, findings, CSV output, hunt output, and a hidden `pcat tftp` compatibility alias.
- Add PE/MZ artifact support:
  - Detect PE/MZ signatures.
  - Parse PE section metadata well enough to avoid arbitrary max-size carving when a file end can be inferred.
  - Score PE artifacts as high-value executable leads.

Why this matters:

Tester feedback showed that `files`, `suspicious`, and `artifacts` overlapped too much; `search` was too string-shaped for a tool that now has evidence records; `streams` was weak on UDP-only captures; and TFTP was a real CTF/general workflow gap. This release focuses on those concrete workflow failures.

Exit criteria:

- `artifacts` can replace normal use of `files` and `suspicious`.
- Deprecated aliases still work and tell users what command to move to.
- `search --scope` can find protocol/evidence/artifact/finding text, not only raw strings.
- UDP conversations appear in `pcat streams`.
- TFTP transferred objects can be reassembled/exported with completeness metadata.
- PE/MZ artifact candidates are detected and ranked.

### V2.4.1: CLI And Help Cleanup

Goal:

Reduce visible command clutter after the V2.4 consolidation without breaking scripts that already use the old command names.

Status:

Implemented in tool version `0.2.4.1`. Report schema remains `0.2.4` because the structured report shape did not change.

Decisions:

- Keep `--help` as the complete public help surface.
- Add `--help-short` for workflow-oriented help:
  - `pcat --help-short`
  - `pcat <command> --help-short`
  - `pcat --help-short <command>`
  - `pcat help-short <command>`
- Hide compatibility aliases from normal global help:
  - `pcat files`
  - `pcat suspicious`
  - `pcat tftp`
- Keep hidden aliases callable with deprecation warnings so older teammate scripts do not break immediately.
- Move normal TFTP export to `pcat extract --tftp`.
- Use `pcat evidence --type tftp_transfer --json` for TFTP metadata inspection.
- Keep incomplete TFTP export as an explicit opt-in with `--include-incomplete-tftp`.

Deferred from the original broad V2.4 idea:

- DNS clustering, encoded-label grouping, and tunneling summaries.
- HTTP stream/object grouping beyond the existing HTTP view and `extract --http`.
- MQTT topic/message payload view and export.
- ICMP trail summaries beyond existing ICMP payload/banner findings.
- Full TCP stream reassembly.

### V2.5: Case Cache And Workflow Reuse

Goal:

Avoid repeated expensive parsing during interactive exploration.

Primary work:

- Store reusable parsed case data in the output folder.
- Allow subcommands to read from an existing case folder.
- Consider `pcat case` command family.
- Keep cache format explicit and versioned.

Possible workflow:

```bash
pcat analyze -i capture.pcapng -o case-dir
pcat dns --case case-dir
pcat http --case case-dir
pcat evidence --case case-dir
```

Why this matters:

On medium captures, repeated commands can take 20-40 seconds each because PCAT reparses the file. A case cache would make PCAT feel like an analyst workflow instead of a batch report generator.

Exit criteria:

- Repeated common views can reuse prior analysis output.
- Cache invalidates safely when schema changes.
- Commands still work without cache.

### Held V2.x: CTF Triage Improvements

Goal:

Make CTF mode catch common clue formats without pretending to solve challenges.

Status:

Held for later design.

Reason:

CTF improvements are useful, but this area can grow too quickly and become a vague detector collection. PCAT should first consolidate its core value: reliable intake, clear briefing, grouped evidence, and honest handoff. Basic spaced flag normalization was added in V2.3.1; deeper CTF logic remains held.

Detailed future CTF planning lives in `PCAT_FUTURE_CTF_UPDATE.md`.

Primary work:

- Detect null-separated flag strings.
- Detect braced strings with separators.
- Detect CVE patterns.
- Detect MD5/SHA1/SHA256-looking hashes.
- Detect suspicious exploit/tool/tunnel keywords such as `ptunnel`.
- Promote suspicious URLs and exploit-looking paths.
- Improve short payload reconstruction summaries.

Why this matters:

CTF users will not trust a CTF mode that misses obvious low-effort obfuscation.

Exit criteria:

- Spaced `p i c o C T F` style fixture is detected.
- Null-separated flag fixture is detected.
- CVE/hash/tunnel keyword tests exist.
- `hunt` output is concise and clue-focused.

### V3.0: External Integration Layer

Goal:

Integrate external tools after PCAT can brief, group, and explain its own evidence well.

Primary work:

- Zeek orchestration.
- Zeek log ingestion.
- Suricata offline orchestration.
- Suricata `eve.json` ingestion.
- Correlate Zeek/Suricata records with PCAT flows, hosts, evidence, artifacts, and stories.
- Write `commands.md` with reproducible external commands.
- Add integration-aware stories and handoff.

Why this is later:

External integrations add more facts. PCAT first needs better story grouping and prioritization so those facts do not become more noise.

Exit criteria:

- Zeek and Suricata output becomes evidence/stories, not just copied logs.
- Integration failures degrade clearly.
- External tool commands are reproducible.

## Bug Fix Backlog From V2 Tests

### Input Handling

- `.cap` rejected despite valid capture data.
- `.pcap.gz` rejected without decompression guidance.
- PCAPNG-by-magic file rejected because extension is nonstandard.
- Archives rejected with generic extension guidance.
- HTML placeholder/download files need clearer rejection.

### Regex Handling

- Invalid regex returns generic error code `1`.
- Should return invalid argument exit code `2`.
- Should show regex parser message without traceback.

### DNS Handling

- DNS can appear in protocol summary while `dns_records` is empty or weak.
- Need broader DNS field extraction and better explanation for malformed/unsupported DNS.

### CTF Coverage

- Spaced flag text missed.
- HackEire-style exploit URI, hash, CVE, port/tool, shell, and tunnel clues not surfaced well.
- Full CTF expansion is intentionally held until the core briefing/story workflow is stronger.

### Artifact Handling

- Overlapping ZIP-like candidates produce repeated high-priority findings.
- Raw-carved hits need clearer lower-confidence labeling.
- `confirmed/validated` can still be misleading when a packet-local fragment has a valid header but is truncated or unusable.

### Product UX

- Terminal report too long and flat.
- Evidence output too voluminous for humans.
- MQTT topic evidence buried too deep.
- ICMP traffic not summarized into actionable trail.
- USB/Bluetooth/mixed captures lack clear handoff language.
- Default `dns`/`http` limits can hide the useful records unless users raise `--top` dramatically.
- Speculative decoded-looking strings can dominate `hunt`.

### Protocol Workflow Gaps

- MQTT topics can be surfaced, but messages and payload chunks need a clean protocol view/export.
- DNS labels that look encoded are not grouped/ranked/decoded.
- USB/HID captures need explicit keyboard/interface triage or a precise handoff.

## Testing Decisions

### Decision: Product Behavior Tests Are Required

Unit tests are not enough. PCAT needs regression tests for behavior that affects analyst trust.

Required future tests:

Immediate V2.1 tests:

- `.cap` acceptance or specific guidance.
- `.pcap.gz` support or decompression guidance.
- nonstandard extension PCAPNG support/guidance.
- archive-specific rejection guidance.
- invalid regex exit code.
- DNS-present but weak-record extraction.

V2.2 guidance tests:

- MQTT topic promoted in briefing/story.
- USB/HID limitation and handoff.
- Bluetooth/mixed encapsulation limitation and handoff.
- QUIC/TLS limitation message.

Later V2.x tests:

- broader separated-flag detection beyond the basic V2.3.1 spaced flag normalization.
- null-separated flag detection.
- overlapping artifact grouping.
- timeline timestamps with nonzero packet/evidence times.
- truncated gzip/JPG artifact completeness downgrade.
- raw artifact recommendation includes `--include-raw`.
- HTTP object export reports written objects separately from artifact carving.
- rejected artifact grouping in stdout.
- DNS cluster summary.
- HTTP object/stream grouping.
- MQTT payload table/export.
- TFTP incomplete-transfer fixture coverage beyond unit-level grouping/export tests.

### Decision: Regression Tests Should Follow Real Reports

Every confirmed tester bug should become either:

- a unit test,
- a CLI behavior test,
- a fixture/corpus test,
- or a documented limitation if intentionally deferred.

## Documentation Decisions

### Decision: Keep Implemented And Planned Features Separate

Docs must not imply planned features are already implemented.

Current docs should use:

- "Implemented" for current command/data behavior.
- "Planned" for roadmap items.
- "Known limitation" for unsupported areas.

### Decision: Documentation Should Teach Workflow

Docs should not only list commands. They should explain:

- when to use PCAT
- when to switch to Wireshark/TShark
- what PCAT is good at
- what PCAT is not good at
- how to move from briefing to evidence to manual analysis
- how to cite evidence
- how to handle unsupported inputs
- how to treat artifacts safely

Future documentation should include workflow examples:

- unknown capture first five minutes
- CTF flag hunt
- HTTP object triage
- DNS anomaly triage
- MQTT capture triage
- encrypted traffic metadata triage
- USB/HID handoff
- artifact extraction and validation

## Deferred Or Rejected For Now

### Zeek And Suricata Integration

Deferred.

Reason:

Valuable, but premature. PCAT needs briefing/story logic first.

### AI Summarization

Deferred.

Reason:

AI prose could hide weak evidence logic. PCAT should first make evidence, stories, and limitations explicit.

### Expanded CTF Triage

Held.

Reason:

Useful, but it needs more product design. PCAT should not become a grab bag of puzzle detectors before its general-purpose triage workflow is stable.

### Full Malware Analysis

Rejected as a core goal.

Reason:

PCAT can support PCAP intake and artifact extraction, but should not become a malware sandbox or execute artifacts.

### Live Capture

Deferred or out of scope.

Reason:

PCAT's current niche is offline case triage.

### GUI

Deferred.

Reason:

The CLI and structured case folder are the current product. A GUI would add surface area before the analysis workflow is mature.

## Current Priority Order

1. V2.1 intake, parser, DNS, and CLI error fixes.
2. V2.2 analyst briefing, limitation language, and evidence stories.
3. V2.3 trust hardening: timeline, artifact completeness, extraction accounting, stdout grouping, search consistency, and noise reduction.
4. V2.4 command consolidation and TFTP/UDP workflow: implemented in `0.2.4`, with CLI/help cleanup in `0.2.4.1`.
5. Remaining protocol workflow: DNS ranking, HTTP object/story clarity, MQTT payloads, and ICMP trails.
6. Case caching and workflow reuse.
7. Expanded CTF clue normalization after the core workflow is stronger.
8. External integrations.

## Guiding Rule

When choosing between adding more output and making existing output more useful, choose usefulness.

PCAT should become sharper, more honest, and more selective before it becomes broader.
