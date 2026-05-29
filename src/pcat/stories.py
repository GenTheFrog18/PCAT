from __future__ import annotations

from collections import Counter

from .evidence import stable_id
from .models import AnalysisReport, AnalystBriefing, ArtifactRecord, EvidenceRecord, EvidenceStory, PacketRecord, severity_from_score
from .utils import format_shell_command


SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def build_stories(report: AnalysisReport, packets: list[PacketRecord]) -> list[EvidenceStory]:
    stories: list[EvidenceStory] = []
    stories.extend(artifact_stories(report))
    stories.extend(tftp_story(report))
    stories.extend(http_story(report))
    stories.extend(dns_story(report))
    stories.extend(mqtt_story(report))
    stories.extend(icmp_story(report, packets))
    stories.extend(syn_payload_story(report))
    stories.extend(encrypted_metadata_story(report))
    stories.extend(non_ip_story(report))
    return sorted(stories, key=lambda story: (SEVERITY_RANK.get(story.severity, 0), len(story.supporting_evidence_ids)), reverse=True)


def build_briefing(report: AnalysisReport, packets: list[PacketRecord]) -> AnalystBriefing:
    limitations = collect_limitations(report, packets)
    hooks = [story.title for story in report.stories[:5]]
    risks = [
        f"[{finding.severity}] {finding.title}"
        for finding in sorted(report.findings, key=lambda f: f.risk_score, reverse=True)[:5]
    ]
    commands = unique(
        [story.recommended_next_command for story in report.stories if story.recommended_next_command]
        + fallback_commands(report)
    )[:5]
    return AnalystBriefing(
        capture_type=describe_capture_type(report),
        top_hooks=hooks or ["No strong story hooks were generated from the parsed evidence."],
        top_risks=risks or ["No high-priority findings were generated."],
        limitations=limitations,
        recommended_next_commands=commands,
    )


def artifact_stories(report: AnalysisReport) -> list[EvidenceStory]:
    stories: list[EvidenceStory] = []
    groups = {
        "confirmed": [item for item in report.artifacts if item.certainty == "confirmed"],
        "candidate": [item for item in report.artifacts if item.certainty == "candidate"],
        "rejected": [item for item in report.artifacts if item.certainty == "rejected"],
    }
    for certainty, artifacts in groups.items():
        if not artifacts:
            continue
        top_score = max((artifact.score for artifact in artifacts), default=0)
        if certainty == "confirmed":
            title = f"{len(artifacts)} confirmed artifact(s) ready for extraction/review"
            why = "PCAT validated the file structure after a magic-byte match, so these are the safest artifact leads to inspect first."
            severity = severity_from_score(top_score)
            confidence = "high"
            command = format_shell_command(["pcat", "extract", "-i", report.summary.file, "--include-raw" if raw_only(artifacts, report.artifacts) else ""])
            limitations: list[str] = []
        elif certainty == "candidate":
            title = f"{len(artifacts)} artifact candidate(s) need validation"
            why = "PCAT found file signatures but could not fully validate structure and completeness. Treat these as leads, not confirmed files."
            severity = severity_from_score(top_score)
            confidence = "medium"
            command = format_shell_command(["pcat", "artifacts", "-i", report.summary.file, "--json"])
            limitations = ["Candidate artifacts may be incomplete, truncated, carved from partial payloads, or unsupported by PCAT's validator."]
        else:
            title = f"{len(artifacts)} rejected file signature hit(s) skipped"
            why = "Magic bytes were present, but structure validation failed. PCAT preserved the observation while avoiding misleading extraction output."
            severity = "low"
            confidence = "high"
            command = format_shell_command(["pcat", "artifacts", "-i", report.summary.file, "--json"])
            limitations = ["Rejected hits are not extractable artifacts unless manual analysis proves otherwise."]
        stories.append(EvidenceStory(
            id=stable_id("story", "artifact", certainty, ",".join(item.artifact_id for item in artifacts[:25])),
            kind="artifact_story",
            title=title,
            why_it_matters=why,
            severity=severity,
            confidence=confidence,
            supporting_evidence_ids=evidence_ids_for_artifacts(report.evidence, artifacts),
            anchors={
                "certainty": certainty,
                "artifact_ids": [item.artifact_id for item in artifacts[:25]],
                "kinds": dict(Counter(item.kind for item in artifacts)),
                "sources": dict(Counter(item.source for item in artifacts)),
                "source_scopes": dict(Counter(item.source_scope for item in artifacts)),
                "truncated_count": sum(1 for item in artifacts if item.truncated),
            },
            recommended_next_command=command,
            limitations=limitations,
        ))
    return stories


def http_story(report: AnalysisReport) -> list[EvidenceStory]:
    if not report.http_records:
        return []
    hosts = Counter(record.host for record in report.http_records if record.host)
    streams = sorted({record.stream_id for record in report.http_records if record.stream_id})
    transfers = [record for record in report.http_records if record.status or record.content_type or record.content_length]
    return [EvidenceStory(
        id=stable_id("story", "http", ",".join(hosts.keys()), len(report.http_records)),
        kind="http_transfer_story",
        title=f"HTTP activity across {len(hosts) or 'unknown'} host(s)",
        why_it_matters="HTTP metadata often exposes downloaded objects, uploaded data, paths, hosts, and CTF clue locations.",
        severity="medium" if transfers else "low",
        confidence="high",
        supporting_evidence_ids=evidence_ids_by_type(report.evidence, {"http_request", "http_download", "http_upload"}),
        anchors={"top_hosts": dict(hosts.most_common(10)), "streams": streams[:25], "transfer_like_records": len(transfers)},
        recommended_next_command=format_shell_command(["pcat", "http", "-i", report.summary.file, "--json"]),
    )]


def dns_story(report: AnalysisReport) -> list[EvidenceStory]:
    dns_findings = [finding for finding in report.findings if finding.category == "dns"]
    if not report.dns_records and not dns_findings:
        return []
    queries = Counter(record.query for record in report.dns_records if record.query)
    failed = sum(1 for record in report.dns_records if record.rcode and record.rcode not in {"0", "NoError"})
    severity = max((finding.severity for finding in dns_findings), key=lambda value: SEVERITY_RANK.get(value, 0), default="low")
    limitations = [finding.explanation for finding in dns_findings if "could not extract" in finding.explanation.lower()]
    return [EvidenceStory(
        id=stable_id("story", "dns", ",".join(queries.keys()), failed, len(dns_findings)),
        kind="dns_anomaly_story",
        title="DNS activity or parser limitation observed" if limitations else f"DNS activity with {len(queries)} queried name(s)",
        why_it_matters="DNS can reveal target domains, failed lookups, tunneling hints, and parser visibility gaps.",
        severity=severity,
        confidence="medium" if limitations else "high",
        supporting_evidence_ids=evidence_ids_by_type(report.evidence, {"dns_query"}),
        anchors={"top_queries": dict(queries.most_common(10)), "failed_response_count": failed},
        recommended_next_command=format_shell_command(["pcat", "dns", "-i", report.summary.file, "--json"]),
        limitations=limitations[:3],
    )]


def mqtt_story(report: AnalysisReport) -> list[EvidenceStory]:
    if not report.mqtt_records:
        return []
    topics = Counter(record.topic for record in report.mqtt_records if record.topic)
    return [EvidenceStory(
        id=stable_id("story", "mqtt", ",".join(topics.keys()), len(report.mqtt_records)),
        kind="mqtt_topic_story",
        title=f"MQTT topics/messages observed ({len(topics)} topic(s))",
        why_it_matters="MQTT topics and messages can contain IoT instructions, credentials, or CTF clues.",
        severity="medium",
        confidence="high",
        supporting_evidence_ids=evidence_ids_by_type(report.evidence, {"mqtt_message"}),
        anchors={"topics": dict(topics.most_common(10))},
        recommended_next_command=format_shell_command(["pcat", "hunt", "-i", report.summary.file, "--json"]),
    )]


def tftp_story(report: AnalysisReport) -> list[EvidenceStory]:
    if not report.tftp_records and not report.tftp_transfers:
        return []
    complete = [item for item in report.tftp_transfers if item.completeness == "complete" and item.byte_count]
    incomplete = [item for item in report.tftp_transfers if item.completeness in {"incomplete", "error", "unknown"}]
    filenames = Counter(item.filename or "(unknown)" for item in report.tftp_transfers)
    top = sorted(report.tftp_transfers, key=lambda item: (item.byte_count, item.filename), reverse=True)[:5]
    severity = "high" if complete else "medium" if report.tftp_transfers else "low"
    limitations = []
    if incomplete:
        limitations.append("Some TFTP transfers are incomplete, errored, or lack a final short block; exported bytes may need manual validation.")
    command_parts = ["pcat", "tftp", "-i", report.summary.file, "--json"]
    if complete:
        command_parts = ["pcat", "tftp", "-i", report.summary.file, "--export"]
    return [EvidenceStory(
        id=stable_id("story", "tftp", len(report.tftp_records), ",".join(item.transfer_id for item in top)),
        kind="tftp_transfer_story",
        title=f"TFTP transfer activity observed ({len(report.tftp_transfers)} transfer(s))",
        why_it_matters="TFTP is a simple UDP file-transfer protocol often used for firmware, boot images, configs, and CTF payloads.",
        severity=severity,
        confidence="high" if report.tftp_transfers else "medium",
        supporting_evidence_ids=evidence_ids_by_type(report.evidence, {"tftp_packet", "tftp_transfer"}),
        anchors={
            "filenames": dict(filenames.most_common(10)),
            "complete_transfers": len(complete),
            "incomplete_or_unknown_transfers": len(incomplete),
            "top_transfers": [
                {
                    "transfer_id": item.transfer_id,
                    "filename": item.filename,
                    "byte_count": item.byte_count,
                    "completeness": item.completeness,
                }
                for item in top
            ],
        },
        recommended_next_command=format_shell_command(command_parts),
        limitations=limitations,
    )]


def icmp_story(report: AnalysisReport, packets: list[PacketRecord]) -> list[EvidenceStory]:
    icmp_packets = [packet for packet in packets if packet.transport == "ICMP" or packet.protocol == "ICMP"]
    icmp_payload_ids = evidence_ids_by_type(report.evidence, {"icmp_payload"})
    if not icmp_packets and not icmp_payload_ids:
        return []
    endpoints = Counter(f"{packet.src_ip}->{packet.dst_ip}" for packet in icmp_packets if packet.src_ip or packet.dst_ip)
    return [EvidenceStory(
        id=stable_id("story", "icmp", len(icmp_packets), ",".join(endpoints.keys())),
        kind="icmp_trail_story",
        title=f"ICMP traffic observed ({len(icmp_packets)} packet(s))",
        why_it_matters="ICMP may be ordinary diagnostics, but payload-bearing ICMP can also be a clue or covert channel in CTF captures.",
        severity="medium" if icmp_payload_ids else "low",
        confidence="medium",
        supporting_evidence_ids=icmp_payload_ids,
        anchors={"endpoint_pairs": dict(endpoints.most_common(10)), "payload_evidence_count": len(icmp_payload_ids)},
        recommended_next_command=format_shell_command(["pcat", "hunt", "-i", report.summary.file, "--json"]),
    )]


def syn_payload_story(report: AnalysisReport) -> list[EvidenceStory]:
    ids = evidence_ids_by_type(report.evidence, {"syn_payload"})
    if not ids:
        return []
    return [EvidenceStory(
        id=stable_id("story", "syn_payload", len(ids)),
        kind="syn_payload_story",
        title=f"TCP SYN payload evidence observed ({len(ids)} frame(s))",
        why_it_matters="TCP SYN packets usually do not carry application payloads; payloads here can indicate covert data or CTF encoding.",
        severity="high",
        confidence="high",
        supporting_evidence_ids=ids,
        anchors={"evidence_count": len(ids)},
        recommended_next_command=format_shell_command(["pcat", "hunt", "-i", report.summary.file, "--json"]),
    )]


def encrypted_metadata_story(report: AnalysisReport) -> list[EvidenceStory]:
    protocols = report.summary.protocols
    encrypted = protocols.get("TLS", 0) + protocols.get("QUIC", 0)
    if not encrypted:
        return []
    total = max(1, report.summary.packet_count)
    severity = "medium" if encrypted / total >= 0.3 else "low"
    return [EvidenceStory(
        id=stable_id("story", "encrypted", encrypted, total),
        kind="encrypted_metadata_story",
        title=f"Encrypted traffic limits payload visibility ({encrypted} packet(s))",
        why_it_matters="PCAT can still use metadata such as hosts, ports, SNI, and timing, but encrypted payload contents are not visible.",
        severity=severity,
        confidence="high",
        supporting_evidence_ids=[],
        anchors={"tls_quic_packets": encrypted, "packet_count": total},
        recommended_next_command=format_shell_command(["pcat", "streams", "-i", report.summary.file, "--json"]),
        limitations=["TLS/QUIC payloads are encrypted; PCAT cannot inspect application content without keys or decrypted traffic."],
    )]


def non_ip_story(report: AnalysisReport) -> list[EvidenceStory]:
    protocols = {name.upper(): count for name, count in report.summary.protocols.items()}
    if not any(token in protocols for token in {"USB", "USBHID", "BLUETOOTH", "BTATT", "BTHCI_EVT"}):
        return []
    return [EvidenceStory(
        id=stable_id("story", "non_ip", ",".join(protocols.keys())),
        kind="non_ip_capture_story",
        title="Non-IP or mixed capture data needs tool handoff",
        why_it_matters="PCAT is strongest for network metadata and common protocol evidence. Non-IP captures may need protocol-specific manual analysis.",
        severity="low",
        confidence="high",
        supporting_evidence_ids=[],
        anchors={"protocols": protocols},
        recommended_next_command=format_shell_command(["pcat", "summary", "-i", report.summary.file, "--json"]),
        limitations=["Use Wireshark or protocol-specific tooling for USB, Bluetooth, HID, or other non-IP payload interpretation."],
    )]


def describe_capture_type(report: AnalysisReport) -> str:
    protocols = [name for name, _ in list(report.summary.protocols.items())[:5] if name and name != "UNKNOWN"]
    if not protocols:
        return "unknown or weakly decoded capture"
    if any(name.upper() in {"USB", "USBHID"} for name in protocols):
        return "USB/non-network capture with limited PCAT visibility"
    encrypted = report.summary.protocols.get("TLS", 0) + report.summary.protocols.get("QUIC", 0)
    if encrypted and encrypted / max(1, report.summary.packet_count) >= 0.5:
        return "encrypted-heavy TLS/QUIC capture"
    return " / ".join(protocols[:4]) + " capture"


def collect_limitations(report: AnalysisReport, packets: list[PacketRecord]) -> list[str]:
    limitations: list[str] = []
    protocols = {name.upper(): count for name, count in report.summary.protocols.items()}
    if any(token in protocols for token in {"USB", "USBHID"}):
        limitations.append("USB/HID captures are outside PCAT's strongest network-analysis workflow.")
    if any("BT" in token or "BLUETOOTH" in token for token in protocols):
        limitations.append("Bluetooth or mixed wireless captures may need Wireshark and protocol-specific tooling.")
    encrypted = protocols.get("TLS", 0) + protocols.get("QUIC", 0)
    if encrypted and encrypted / max(1, report.summary.packet_count) >= 0.3:
        limitations.append("TLS/QUIC payloads are encrypted; PCAT can inspect metadata only.")
    if report.summary.packet_count and report.summary.packet_count < 10:
        limitations.append("Very small captures may not contain enough context for confident prioritization.")
    if any(finding.title == "DNS traffic needs manual parser review" for finding in report.findings):
        limitations.append("DNS-like traffic was observed, but useful DNS records were not fully extracted.")
    if any(transfer.completeness in {"incomplete", "error", "unknown"} for transfer in report.tftp_transfers):
        limitations.append("Some TFTP transfers may not be complete enough for confident export.")
    for story in report.stories:
        limitations.extend(story.limitations)
    return unique(limitations)[:6]


def fallback_commands(report: AnalysisReport) -> list[str]:
    file = report.summary.file
    commands = [
        format_shell_command(["pcat", "evidence", "-i", file, "--top", "50"]),
        format_shell_command(["pcat", "timeline", "-i", file, "--top", "100"]),
    ]
    if report.artifacts:
        commands.append(format_shell_command(["pcat", "artifacts", "-i", file, "--json"]))
    if report.tftp_transfers:
        commands.append(format_shell_command(["pcat", "tftp", "-i", file, "--json"]))
    return commands


def raw_only(group: list[ArtifactRecord], all_artifacts: list[ArtifactRecord]) -> bool:
    raw_extractable = [item for item in group if item.source == "raw-file" and item.certainty != "rejected"]
    packet_extractable = [item for item in all_artifacts if item.source != "raw-file" and item.certainty != "rejected"]
    return bool(raw_extractable) and not packet_extractable


def evidence_ids_by_type(evidence: list[EvidenceRecord], types: set[str]) -> list[str]:
    return [item.evidence_id for item in evidence if item.type in types][:25]


def evidence_ids_for_artifacts(evidence: list[EvidenceRecord], artifacts: list[ArtifactRecord]) -> list[str]:
    artifact_ids = {artifact.artifact_id for artifact in artifacts}
    return [
        item.evidence_id
        for item in evidence
        if artifact_ids & set(item.related_artifact_ids)
    ][:25]


def unique(values: list[str]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result
