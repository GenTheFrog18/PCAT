# PCAT Roadmap And Decision Record

Date: 2026-05-30

This document records the current product decisions and roadmap after the first V2 prototype/report cycle. It is intentionally separate from the GitHub-facing technical docs because it includes planning context, testing interpretation, and future decisions.

## Current Situation

PCAT V2 has been consolidated through tool version `0.2.4.1` and report schema version `0.2.4`. The first prototype report has been submitted, and the current repository now has a stronger README, reference documentation, and a GitHub Pages source under `docs/`.

Completed baseline:

- V2.1 fixed intake, parser, DNS, and CLI error reliability issues.
- V2.2 added analyst briefing, evidence stories, and clearer limitation language.
- V2.3 and V2.3.1 hardened timeline behavior, artifact certainty, extraction accounting, stdout grouping, and trust language.
- V2.4 consolidated artifact-facing commands, expanded evidence search, added UDP conversation visibility, added PE/MZ artifact support, and added TFTP grouping/export.
- V2.4.1 cleaned up the CLI/help surface, moved normal TFTP export under `pcat extract --tftp`, hid old compatibility aliases, and added `--help-short`.

The testing cycle shows that the core foundation is viable:

- Supported `.pcap` and `.pcapng` captures did not produce blocker/high reliability failures.
- Full reports, JSON, CSV files, evidence records, and artifact manifests are generated.
- Extraction limits are respected.
- Artifact extraction is bounded and does not execute files.
- Evidence-first architecture is still the right foundation.
- Public-facing documentation is good enough for teammate/mentor review, but the GitHub Pages visual design still needs a separate pass before it should be treated as the project's polished public face.

The main weakness is not basic stability. The main weakness is that PCAT often produces facts without enough analyst judgment.

In practical terms:

- PCAT can say what it found.
- PCAT is not yet consistently good at saying what matters first, why it matters, what it cannot see, and what command the analyst should run next.

The next phase should therefore focus on post-prototype bug reports, documentation/release hygiene, remaining protocol workflow, and user trust before external integrations.

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
- TFTP is promoted into the V2.4 plan; MQTT remains in the next protocol workflow milestone.
- V2.3 prepares the metadata fields and output language that V2.4 protocol exporters will reuse.

### Decision 11: Public Project Material Should Stay Truthful To The Prototype

Decision:

The README, reference docs, and future GitHub Pages site should present PCAT as an active offline triage prototype, not as a finished security platform.

Reason:

After the prototype report, the project needs to be understandable to teammates, mentors, and testers. That does not mean the project needs marketing polish or broad claims. Overstating maturity would create the same trust problem the tool is designed to avoid.

Impact:

- The main README is the primary public project surface for now.
- GitHub Pages can exist as a deployment target, but its visual design should be revisited before being treated as final.
- Documentation should keep implemented behavior, known limits, and planned features separate.
- The roadmap should explicitly record documentation, release hygiene, and public presentation work instead of treating it as unrelated housekeeping.

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

### V2.4.2: Post-Prototype Repo And Release Hygiene

Goal:

Make the repository easier to review, test, and hand off after the prototype report without changing the analysis model.

Status:

Partially implemented. The main README has been rewritten as a project-facing document, the documentation index has GitHub Pages publishing notes, and a first GitHub Pages source exists. The page design itself is not considered final.

Primary work:

- Keep the README as the most reliable public entry point.
- Keep English and Indonesian overview docs reasonably aligned.
- Add or decide on a project license before encouraging broader reuse.
- Add package metadata that helps repository viewers and future package users:
  - project URLs
  - classifiers
  - license metadata after a license is chosen
- Add a lightweight changelog or release notes file before tagging public milestones.
- Revisit the GitHub Pages design:
  - avoid visual overlap and oversized screenshot composition
  - keep the first viewport focused on PCAT's actual purpose
  - link to the manual, technical reference, and architecture docs
- Add issue/report templates only if tester feedback becomes hard to track informally.

Why this matters:

The project has moved from private prototype work into teammate and mentor review. The repository should explain the tool accurately before larger features or integrations make the surface area harder to understand.

Exit criteria:

- README explains purpose, install, quickstart, output structure, limits, docs, and contribution expectations.
- Docs clearly mark implemented, planned, and known-limitation behavior.
- GitHub Pages can be enabled from `/docs` without misleading users.
- License status is explicit.
- Release notes summarize the current prototype build.

### V2.5: Remaining Protocol Workflow

Goal:

Make the most common protocol-specific follow-up paths more useful without turning PCAT into a full reassembly engine.

Research basis:

The V2.5 plan is based on tester feedback plus public protocol-analysis workflows, tutorials, forum questions, and PCAP writeups. The recurring theme is that analysts do not only need more decoded fields. They need grouped protocol stories, extraction confidence, and precise handoff commands.

Research signals:

- General PCAP triage workflows commonly start with protocol/host/conversation summaries, then move into targeted TShark field extraction and object export. This matches PCAT's role as a fast briefing layer before deeper Wireshark/TShark work. Reference: [PCAP Analysis with Wireshark and Tshark](https://www.amirootyet.com/post/pcap-analysis-with-wireshark-tshark/).
- HTTP investigations often involve unencrypted malware downloads, fake login pages, email objects, FTP/SMB object extraction, misleading content types, and manual object export from Wireshark. Reference: [Unit 42 Wireshark Tutorial: Exporting Objects From a Pcap](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/).
- Forum questions around HTTP export frequently come from users seeing requests but getting no exportable object, missing reassembly settings, chunked responses, partial captures, or TLS-encrypted payloads. PCAT should explain these failure modes instead of only saying "0 exported." Example forum signals: [Export Objects HTTP returns nothing](https://www.reddit.com/r/wireshark/comments/l1bvvm), [HTTP chunks/image extraction confusion](https://www.reddit.com/r/wireshark/comments/kcdzhm).
- DNS analysis cases often depend on grouping related questions, failed answers, query types, long labels, encoded-looking labels, TXT data, and suspicious base domains. References: [PacketSafari DNS case studies](https://www.packetsafari.com/blog/2022/02/23/analyzing-dns-in-wireshark/) and [Infoblox DNS tunneling tool analysis](https://www.infoblox.com/blog/community/analysis-on-popular-dns-tunneling-tools/).
- DNS tunneling examples frequently use high-volume labels, TXT records, and base64-like text in queries/responses. PCAT should flag these as leads and preserve exact labels for manual decoding, not claim decoded content unless decoding is successful and reversible. Forum signal: [DNS encoding/exfiltration confusion](https://www.reddit.com/r/wireshark/comments/xrb64g).
- MQTT workflows need topic, client ID, CONNECT, SUBSCRIBE, PUBLISH, QoS, retain, keepalive, username/password presence, payload preview, and TLS limitation handling. References: [EMQX MQTT Wireshark guide](https://www.emqx.com/en/blog/mastering-mqtt-analysis-with-wireshark), [Cedalo MQTT Wireshark guide](https://cedalo.com/blog/wireshark-mqtt-guide/), and [SCADA Protocols MQTT traffic guide](https://scadaprotocols.com/wireshark-mqtt-industrial-iot-guide/).
- ICMP is not only connectivity noise. Real investigations and training material treat payload size, frequency, destinations, and embedded payload data as possible exfiltration or C2 clues. Reference: [IMP Solutions ICMP exfiltration discussion](https://www.impsolutions.com/insights/subtle-data-exfilltration).
- USB/HID captures show up in CTF and forensics workflows where the first useful action is to identify that the capture is USB/HID, extract `usb.capdata` or `usbhid.data`, and hand off to a keyboard/mouse parser or script. References: [HackTricks USB keystrokes](https://book.hacktricks.wiki/generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/usb-keystrokes.html), [Dissecting USB PCAP Traffic](https://05t3.github.io/posts/Dissecting-USB-Traffic/), and [OtterCTF USB tablet writeup](https://www.petermstewart.net/otterctf-2018-network-challenges-look-at-me-write-up/).

Primary work:

#### DNS Workflow

Problem:

DNS is useful both for normal triage and for CTF/exfiltration cases, but raw DNS rows are not enough. Analysts need to know which query groups are unusual, which base domains dominate, which labels look encoded, and whether parser limitations hide useful details.

Planned output:

- `pcat dns` remains the human DNS view, but gains grouped sections:
  - top queried names
  - top base domains
  - repeated NXDOMAIN/failure groups
  - unusual query types such as TXT, NULL, long CNAME chains, and uncommon record types
  - long-label and high-entropy-label candidates
  - encoded-looking label candidates
  - high-volume client-to-domain pairs
- JSON output includes `dns_groups`, not only flat `dns_records`.
- Findings/stories explain why a DNS group matters and what filter to run next.

Planned evidence additions:

- `dns_query_group`
- `dns_encoded_label_candidate`
- `dns_tunnel_candidate`
- `dns_failure_pattern`
- `dns_txt_payload_candidate`

Important constraints:

- Do not call an encoded-looking label decoded unless PCAT actually decodes it.
- Keep raw labels and decoded attempts side by side.
- Report entropy/length as signals, not proof.
- Do not let DNS tunnel candidates dominate `hunt` unless the confidence is high or the user asks for verbose output.

Example next-step commands:

```bash
pcat dns -i capture.pcap --json
pcat search -i capture.pcap suspicious-domain.example --scope protocols
tshark -r capture.pcap -Y "dns" -T fields -e frame.number -e ip.src -e dns.qry.name -e dns.qry.type
```

#### HTTP Workflow

Problem:

HTTP workflows often revolve around objects, uploads, redirects, credentials, user agents, suspicious paths, and extraction failure. Users are confused when HTTP requests exist but `Export Objects` or `extract --http` writes nothing.

Planned output:

- `pcat http` gains transfer grouping:
  - request/response pairs where frame/stream data is available
  - download-looking responses
  - upload-looking requests
  - large transfers
  - suspicious extensions and paths
  - content-type versus filename mismatch
  - user-agent grouping
  - host/path/status summaries
- `pcat extract --http` keeps object-export accounting separate from artifact carving and explains common failure states:
  - no HTTP objects found
  - encrypted/TLS traffic
  - partial capture or missing response body
  - unsupported transfer/reassembly condition
  - TShark export failure
- JSON includes an HTTP export detail table with frame/stream/source hints when TShark provides enough data.

Planned evidence additions:

- `http_transfer_group`
- `http_download_candidate`
- `http_upload_candidate`
- `http_content_type_mismatch`
- `http_export_failure_reason`
- `http_suspicious_path`

Important constraints:

- Exported HTTP objects are not automatically safe.
- Content type from the server is metadata, not proof of file type.
- If export writes files, stdout must not summarize the run as only "Artifacts extracted: 0."
- If export writes nothing, PCAT should point to likely reasons and next filters.

Example next-step commands:

```bash
pcat http -i capture.pcap --json
pcat extract -i capture.pcap --http -o case-output
tshark -r capture.pcap --export-object http,case-output/http_objects
tshark -r capture.pcap -Y "http.request or http.response" -T fields -e frame.number -e tcp.stream -e http.host -e http.request.uri -e http.response.code -e http.content_type
```

#### MQTT Workflow

Problem:

MQTT appears in IoT and industrial captures, and the useful evidence is usually not "MQTT exists." Analysts need client IDs, broker endpoints, CONNECT metadata, subscriptions, publish topics, QoS/retain behavior, payload previews, and whether traffic is encrypted on MQTT-over-TLS.

Planned output:

- Add or expand an MQTT-focused view:
  - broker endpoints
  - client IDs
  - CONNECT/SUBSCRIBE/PUBLISH/DISCONNECT counts
  - topics by frequency
  - publish payload previews when available
  - username/password presence and decoded values only when TShark exposes plaintext fields
  - QoS and retain flags
  - keepalive/session hints
  - MQTT-over-TLS limitation when only port/protocol metadata is visible
- `hunt` should surface high-signal MQTT leads without dumping every topic.
- JSON includes topic groups and message samples with frame anchors.

Planned evidence additions:

- `mqtt_client`
- `mqtt_topic_group`
- `mqtt_publish_sample`
- `mqtt_subscription`
- `mqtt_credential_observation`
- `mqtt_tls_limited_visibility`

Important constraints:

- Do not export binary MQTT payloads until source/completeness semantics are clear.
- Payload previews must be bounded and clearly truncated.
- Plaintext credentials should be marked sensitive but not redacted by default.
- Encrypted MQTT should produce metadata and limitation language, not empty silence.

Example next-step commands:

```bash
pcat search -i capture.pcap mqtt --scope protocols
pcat evidence -i capture.pcap --type mqtt_message --json
tshark -r capture.pcap -Y "mqtt" -T fields -e frame.number -e ip.src -e ip.dst -e mqtt.topic -e mqtt.msgtype -e mqtt.qos
```

#### ICMP Workflow

Problem:

ICMP can be normal diagnostics, but payload-bearing ICMP can also indicate covert channels, C2, exfiltration, or CTF clues. A flat packet list does not show whether there is a trail.

Planned output:

- Group ICMP activity by endpoint pair and type/code.
- Highlight payload-bearing echo requests/replies.
- Report payload size distribution and unusual repeated payload patterns.
- Detect printable, hex-looking, base64-looking, or protocol-banner-like payloads as candidates.
- Produce a compact ICMP trail story when multiple related payload packets exist.

Planned evidence additions:

- `icmp_endpoint_group`
- `icmp_payload_candidate`
- `icmp_payload_trail`
- `icmp_large_payload`
- `icmp_repeated_payload_pattern`

Important constraints:

- ICMP payload does not automatically mean malicious.
- Size/frequency/payload signals should be framed as leads.
- Reconstructed payloads should remain candidate data unless completeness is clear.

Example next-step commands:

```bash
pcat hunt -i capture.pcap --json
pcat evidence -i capture.pcap --type icmp_payload --json
tshark -r capture.pcap -Y "icmp and data" -T fields -e frame.number -e ip.src -e ip.dst -e data.len -e data.data
```

#### USB/HID And Unusual Capture Handoff

Problem:

Some PCAPs are not normal IP network captures. CTF and forensics cases may contain USB keyboard, mouse, tablet, Bluetooth, or mixed encapsulation traffic. PCAT should recognize these cases and give a precise handoff rather than producing weak network-centric output.

Planned output:

- Detect likely USB/HID captures from link type, protocol hierarchy, or TShark fields.
- Summarize:
  - USB device addresses
  - transfer types
  - presence of `usb.capdata`
  - presence of `usbhid.data`
  - keyboard-like 8-byte reports
  - mouse/tablet-like movement reports
- Provide handoff commands to extract HID fields.
- Do not attempt full keyboard/mouse reconstruction in this milestone unless the implementation can do it robustly across captured field variants.

Planned evidence additions:

- `usb_hid_capture`
- `usb_hid_keyboard_candidate`
- `usb_hid_pointer_candidate`
- `unsupported_capture_handoff`

Important constraints:

- USB/HID decoding is layout- and descriptor-sensitive.
- If report descriptors are missing, PCAT should say so.
- Treat decoded keystrokes, if added later, as sensitive output.

Example next-step commands:

```bash
tshark -r capture.pcapng -Y "usbhid.data or usb.capdata" -T fields -e frame.number -e usb.device_address -e usbhid.data -e usb.capdata
```

#### Encrypted And Mixed Traffic Handoff

Problem:

QUIC/TLS-heavy captures can look empty to beginners because payloads are encrypted. PCAT should explain what metadata remains useful.

Planned output:

- Identify TLS/QUIC-heavy captures.
- Summarize visible metadata:
  - SNI where available
  - ALPN where available
  - certificate subject/issuer where available
  - TLS versions/ciphers where available
  - UDP/443 QUIC endpoints
  - DNS correlation before encrypted connections
- Explain that payload extraction is not possible without keys or decrypted traffic.

Planned evidence additions:

- `encrypted_traffic_summary`
- `tls_metadata_group`
- `quic_metadata_group`
- `decryption_required_limitation`

Why this matters:

The prototype proved that PCAT is useful when it groups evidence into concrete next actions. Remaining protocol work should make common follow-up paths easier, not just add more rows.

Exit criteria:

- Protocol views produce a concise human answer and a JSON handoff.
- New protocol findings preserve confidence and limitations.
- `hunt` remains concise.
- New behavior has tests or documented limitations.
- Each workflow has at least one fixture or golden-output test.
- Empty states explain what was checked and why nothing actionable was found.

### V2.6: Case Cache And Workflow Reuse

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

### V2.7: AI/LLM Integration Readiness Without AI Integration

Goal:

Make PCAT's JSON output, case folders, command output, evidence structure, and documentation useful for teammates who want to integrate their own LLM or assistant layer later, without adding any AI model, AI API, prompt execution, or MCP server inside PCAT.

Non-goal:

V2.7 does not add AI summarization, LLM calls, cloud upload, chat UI, or automatic natural-language conclusions. PCAT remains the deterministic evidence producer. Any future AI layer must consume PCAT output and cite PCAT evidence.

Why this matters:

If an LLM integration is added by another teammate, it will only be useful if PCAT's output is stable, parseable, bounded, provenance-rich, and explicit about uncertainty. Otherwise the LLM layer will be forced to scrape terminal text or infer meaning from inconsistent JSON shapes, which creates brittle integrations and overconfident summaries.

Design principles:

- Model-agnostic: no OpenAI-specific, Anthropic-specific, local-model-specific, or MCP-specific assumptions in the core output.
- Local-first: PCAT should not send captures, reports, artifacts, or evidence to external services.
- Schema-first: JSON outputs should have documented contracts and versioning.
- Deterministic: the same capture and options should produce stable IDs and stable ordering where possible.
- Evidence-grounded: every summary, finding, story, recommendation, and extracted artifact should point back to frames, streams, evidence IDs, artifact IDs, or output files.
- Bounded context: large strings, payloads, and artifact previews must be bounded with explicit truncation metadata.
- No silent redaction by default: PCAT should preserve evidence by default, but mark sensitive fields so downstream tools can decide how to handle them.
- Human and machine parity: anything important printed in terminal output should be available in JSON.

Primary work:

#### JSON Envelope Standardization

Problem:

Different commands currently return different JSON shapes. That is acceptable for humans calling one command at a time, but brittle for downstream parsers and AI integrations.

Planned standard envelope for every `--json` command:

```json
{
  "schema_version": "0.2.x",
  "pcat_version": "0.2.x",
  "command": {
    "name": "analyze",
    "argv": ["pcat", "analyze", "-i", "capture.pcap"],
    "mode": "ctf"
  },
  "input": {
    "path": "capture.pcap",
    "sha256": "...",
    "size_bytes": 0
  },
  "case": {
    "case_id": "...",
    "output_dir": "..."
  },
  "generated_at": "...",
  "warnings": [],
  "limits": {
    "truncated": false,
    "max_items": null,
    "max_preview_bytes": null
  },
  "data": {}
}
```

Rules:

- `schema_version` describes the JSON contract.
- `pcat_version` describes the tool build.
- `data` contains the command-specific payload.
- Errors in JSON mode should be machine-readable when possible and still respect exit codes.
- Human progress logs must not pollute stdout when `--json` is used.

#### JSON Schema Files

Problem:

Downstream integrators need to know what fields exist, which fields are optional, and which fields are stable.

Planned work:

- Add JSON Schema documents under `docs/schema/` or `schemas/`.
- Cover at least:
  - command envelope
  - `AnalysisReport`
  - `EvidenceRecord`
  - `EvidenceStory`
  - `Finding`
  - `ArtifactRecord`
  - extraction summary
  - protocol workflow summaries
  - recommended command objects
- Add schema version history and compatibility rules.
- Add tests that validate generated fixture outputs against schemas.

#### Stable Evidence Graph

Problem:

LLM/assistant layers need references they can cite. Flat text summaries are not enough.

Planned work:

- Strengthen relationships between:
  - capture
  - packets/frames
  - flows/streams/conversations
  - evidence records
  - findings
  - stories
  - artifacts
  - extracted files
  - recommended commands
- Add explicit relationship fields where missing:
  - `related_evidence_ids`
  - `related_artifact_ids`
  - `related_flow_ids`
  - `related_stream_ids`
  - `frame_refs`
  - `source_refs`
- Keep IDs stable across repeated runs on the same capture where possible.
- Document which IDs are stable and which are best-effort.

#### Assistant-Handoff Bundle

Problem:

An LLM integrator should not need to call five commands and guess which outputs matter.

Planned work:

- Add a deterministic handoff bundle, not an AI feature.
- Possible command:

```bash
pcat handoff -i capture.pcap -o case-output --json
```

- Possible output file:

```text
case-output/
  handoff.json
```

Proposed `handoff.json` content:

- capture identity and limitations
- briefing
- top stories
- top findings
- evidence index summary
- artifact summary
- protocol workflow summaries
- recommended commands as structured argv arrays
- sensitive-field inventory
- truncation and omission notes
- links to full JSON files in the case folder

Important naming note:

Prefer `handoff.json` or `assistant_handoff.json` over `llm.json`. The file should be useful for humans, scripts, MCP servers, local agents, or LLM wrappers without implying PCAT itself is an AI tool.

#### Structured Recommended Commands

Problem:

PCAT currently emits copy-paste commands as strings in several places. Strings are good for humans but awkward for tool integrations.

Planned command object:

```json
{
  "command_id": "cmd:extract:tftp",
  "tool": "pcat",
  "argv": ["pcat", "extract", "-i", "capture.pcap", "--tftp", "-o", "case-output"],
  "purpose": "Export recoverable TFTP objects",
  "risk": "writes_files",
  "requires_confirmation": true,
  "related_evidence_ids": ["..."],
  "expected_outputs": ["case-output/tftp_objects/"]
}
```

Rules:

- Always include `argv` arrays in JSON.
- Keep display strings optional.
- Mark write/export/destructive potential explicitly.
- No recommended command should require shell parsing to understand.

#### Sensitivity And Safety Labels

Problem:

PCAPs often contain passwords, cookies, private URLs, internal hostnames, CTF flags, emails, and file contents. V2.7 should help downstream tools handle this responsibly without redacting by default.

Planned labels:

- `contains_credentials`
- `contains_cookie`
- `contains_token`
- `contains_private_url`
- `contains_internal_hostname`
- `contains_payload_bytes`
- `contains_extracted_file`
- `contains_ctf_flag_candidate`
- `malware_risk`

Rules:

- Labels are metadata, not redaction.
- Redaction remains explicit opt-in if implemented later.
- Terminal and JSON docs must warn that downstream AI integrations can leak sensitive data if they send PCAT output to external services.

#### Bounded Previews And Truncation Metadata

Problem:

LLM integrations fail or hallucinate when huge payloads are dumped into context without boundaries.

Planned work:

- Standardize preview fields:
  - `preview`
  - `preview_encoding`
  - `preview_bytes`
  - `preview_truncated`
  - `full_data_available`
  - `full_data_path`
- Use bounded previews for strings, payloads, MQTT messages, ICMP payloads, DNS decoded candidates, and artifact bytes.
- Never hide truncation.

#### NDJSON Or Pagination For Large Outputs

Problem:

Large captures can produce large evidence arrays that are inefficient for streaming or external processing.

Planned work:

- Consider optional NDJSON outputs for evidence-heavy commands:

```bash
pcat evidence -i capture.pcap --jsonl
pcat search -i capture.pcap keyword --jsonl
```

- Or provide pagination/limit metadata:
  - `total_count`
  - `returned_count`
  - `offset`
  - `limit`
  - `has_more`
- Keep regular `--json` behavior for normal use.

#### Error And Exit Contract

Problem:

Downstream tools need reliable failure handling.

Planned work:

- Document all exit codes in a machine-readable table.
- In JSON mode, provide structured error output when possible:

```json
{
  "error": {
    "exit_code": 2,
    "category": "invalid_argument",
    "message": "Invalid regex pattern",
    "detail": "..."
  }
}
```

- Keep traceback output behind `--debug`.
- Keep stderr for human diagnostics; keep stdout parseable when `--json` is requested.

#### Integration Documentation

Problem:

If teammates integrate LLMs, they need a contract and examples, not informal assumptions.

Planned docs:

- `docs/reference/PCAT_JSON_CONTRACT.md`
- `docs/reference/PCAT_ASSISTANT_HANDOFF.md`
- Example parser snippets:
  - Python
  - JavaScript/TypeScript if useful
- Example "safe integration rules":
  - cite evidence IDs
  - do not claim unsupported decoding
  - do not send sensitive output to external APIs without explicit user approval
  - prefer `handoff.json` before full `report.json`
  - ask PCAT for more evidence instead of guessing

Testing requirements:

- Golden JSON outputs for representative commands.
- Schema validation in tests.
- Deterministic ordering tests for top-level evidence/story/finding outputs.
- Tests that `--json` stdout contains only JSON.
- Tests for structured errors in JSON mode.
- Tests for recommended command `argv` arrays.
- Tests for sensitivity labels on credentials, cookies, tokens, payload bytes, and extracted artifacts.

Exit criteria:

- A teammate can write an LLM wrapper using documented JSON files without scraping terminal output.
- The wrapper can cite evidence IDs and frame references.
- All important terminal information exists in JSON.
- Large outputs are bounded, paginated, or streamable.
- Sensitive data is labeled.
- No AI model, AI API, MCP server, or chat feature is added to PCAT itself.

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

### V4.0 Candidate: MCP Or LLM-Facing Assistant Layer

Goal:

Expose PCAT's stable evidence, reports, case folders, and tool commands to an assistant or MCP-style workflow after the core analysis and integration layers are reliable.

Status:

Candidate future version only. This should not start before V2 is consolidated and V3 integration semantics are clear.

Dependency:

V2.7 should happen first. V2.7 creates the JSON, evidence, handoff, sensitivity, and command contracts that an MCP/LLM layer would need. V4 should consume those contracts instead of inventing a separate assistant-only data model.

Primary work:

- Define safe read-only operations first:
  - inspect case summary
  - list evidence/stories/findings
  - search evidence
  - retrieve artifact metadata
  - suggest next PCAT or external-tool commands
- Keep capture data local by default.
- Keep AI/LLM behavior grounded in existing PCAT evidence rather than free-form unsupported claims.
- Avoid exposing artifact execution or destructive filesystem operations.
- Treat LLM-written summaries as optional presentation, not as the source of truth.

Why this is later:

An assistant layer would be useful only if PCAT already produces structured, trustworthy evidence. Adding it too early would hide weak core logic behind natural language.

Exit criteria:

- MCP/assistant responses cite concrete PCAT evidence IDs, frames, files, or report fields.
- The assistant can explain limitations and uncertainty.
- The assistant does not claim unsupported protocol decoding or artifact validity.
- All write/export actions remain explicit user commands.

## Historical Bug Backlog From V2 Tests

Status:

Many of the original V2 test failures were addressed across V2.1 through V2.4.1. This section is kept as historical context and as a source of future regression-test ideas. It should not be read as a fully current open-issue list.

Current open themes from this backlog are mainly:

- richer DNS ranking/grouping
- deeper HTTP object/story clarity
- MQTT payload workflow
- ICMP trail grouping
- USB/HID and unusual-capture handoff
- broader CTF clue normalization after the core workflow is stable

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

Future note:

An MCP/LLM-facing layer is only a V4 candidate after PCAT has stable evidence, case, and integration semantics. It should cite PCAT evidence instead of becoming the source of truth.

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

Completed baseline:

1. V2.1 intake, parser, DNS, and CLI error fixes.
2. V2.2 analyst briefing, limitation language, and evidence stories.
3. V2.3/V2.3.1 trust hardening: timeline, artifact completeness, extraction accounting, stdout grouping, search consistency, and noise reduction.
4. V2.4 command consolidation and TFTP/UDP workflow: implemented in `0.2.4`, with CLI/help cleanup in `0.2.4.1`.

Next active order:

1. V2.4.2 post-prototype repo/release hygiene:
   - keep README/docs accurate
   - decide license
   - add release notes/changelog
   - revisit GitHub Pages design
   - triage any new tester reports into regression tests or documented limitations
2. V2.5 remaining protocol workflow:
   - DNS ranking/grouping
   - HTTP object/story clarity
   - MQTT topic/message payload view
   - ICMP trail summaries
   - better handoff for USB/HID, Bluetooth, QUIC/TLS-heavy, and unusual captures
3. V2.6 case caching and workflow reuse.
4. V2.7 AI/LLM integration readiness without AI integration:
   - schema-first JSON contracts
   - assistant handoff bundle
   - stable evidence graph
   - structured recommended commands
   - sensitivity and truncation metadata
5. Held V2.x CTF clue normalization after the core workflow is stronger.
6. V3.0 external integrations with Zeek/Suricata.
7. V4.0 candidate MCP/LLM-facing assistant layer after structured evidence and integrations are mature.

## Guiding Rule

When choosing between adding more output and making existing output more useful, choose usefulness.

PCAT should become sharper, more honest, and more selective before it becomes broader.
