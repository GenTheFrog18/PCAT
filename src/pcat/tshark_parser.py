from __future__ import annotations

import csv
import sys
import subprocess
from io import StringIO
from pathlib import Path

from .errors import InputFileError
from .models import PacketRecord
from .utils import input_parse_guidance, require_tshark


FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "frame.protocols",
    "_ws.col.Protocol",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "tcp.flags",
    "tcp.len",
    "tcp.stream",
    "dns.qry.name",
    "dns.resp.name",
    "dns.a",
    "dns.aaaa",
    "dns.cname",
    "dns.ptr.domain_name",
    "dns.ns",
    "dns.mx.mail_exchange",
    "dns.txt",
    "dns.flags.rcode",
    "http.host",
    "http.request.method",
    "http.request.uri",
    "http.request.full_uri",
    "http.user_agent",
    "http.response.code",
    "http.content_type",
    "http.content_length_header",
    "http.content_length",
    "tls.handshake.extensions_server_name",
    "icmp.type",
    "data.data",
    "tcp.payload",
    "udp.payload",
    "smtp.req.command",
    "smtp.req.parameter",
    "smtp.response",
    "smtp.response.code",
    "smtp.message",
    "smtp.auth.username",
    "smtp.auth.password",
    "mqtt.msgtype",
    "mqtt.topic",
    "mqtt.msg_text",
    "mqtt.username",
    "mqtt.passwd",
    "tftp.opcode",
    "tftp.source_file",
    "tftp.destination_file",
    "tftp.request_frame",
    "tftp.type",
    "tftp.block",
    "tftp.block.full",
    "tftp.error.code",
    "tftp.error.message",
    "tftp.data",
    "tftp.reassembled.data",
    "tftp.reassembled.length",
]


def run_tshark_fields(path: Path) -> str:
    tshark = require_tshark()
    cmd = [tshark, "-r", str(path), "-T", "fields", "-E", "header=y", "-E", "separator=\t", "-E", "quote=d"]
    for field in FIELDS:
        cmd.extend(["-e", field])
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    if result.returncode != 0:
        message = result.stderr.strip() or "tshark failed to parse the input file."
        raise InputFileError(input_parse_guidance(path, message))
    return result.stdout


def parse_packets(path: Path) -> list[PacketRecord]:
    raise_csv_field_limit()
    output = run_tshark_fields(path)
    if not output.strip():
        raise InputFileError("The PCAP appears to be empty or tshark returned no packets.")
    rows = csv.DictReader(StringIO(output), delimiter="\t")
    packets: list[PacketRecord] = []
    for row in rows:
        try:
            frame = int(first(row.get("frame.number", "")) or 0)
            timestamp = float(first(row.get("frame.time_epoch", "")) or 0.0)
            length = int(first(row.get("frame.len", "")) or 0)
        except ValueError:
            continue
        src_ip = first(row.get("ip.src", "")) or first(row.get("ipv6.src", ""))
        dst_ip = first(row.get("ip.dst", "")) or first(row.get("ipv6.dst", ""))
        src_port = first(row.get("tcp.srcport", "")) or first(row.get("udp.srcport", ""))
        dst_port = first(row.get("tcp.dstport", "")) or first(row.get("udp.dstport", ""))
        tcp_src = first(row.get("tcp.srcport", ""))
        tcp_dst = first(row.get("tcp.dstport", ""))
        udp_src = first(row.get("udp.srcport", ""))
        udp_dst = first(row.get("udp.dstport", ""))
        transport = "TCP" if first(row.get("tcp.srcport", "")) or first(row.get("tcp.dstport", "")) else ""
        if not transport and (udp_src or udp_dst):
            transport = "UDP"
        if not transport and first(row.get("icmp.type", "")):
            transport = "ICMP"
        protocol_stack = first(row.get("frame.protocols", ""))
        protocol = choose_protocol(
            first(row.get("_ws.col.Protocol", "")),
            protocol_stack,
            src_port,
            dst_port,
        )
        payload_hex = first_nonempty(
            row.get("data.data", ""),
            row.get("tcp.payload", ""),
            row.get("udp.payload", ""),
        )
        packets.append(
            PacketRecord(
                frame_number=frame,
                timestamp=timestamp,
                length=length,
                protocol=protocol,
                protocol_stack=protocol_stack,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                transport=transport,
                tcp_flags=first(row.get("tcp.flags", "")),
                tcp_len=first(row.get("tcp.len", "")),
                tcp_stream=first(row.get("tcp.stream", "")),
                dns_query=first_nonempty(row.get("dns.qry.name", ""), row.get("dns.resp.name", "")),
                dns_answer=joined_unique_fields(
                    row,
                    [
                        "dns.a",
                        "dns.aaaa",
                        "dns.cname",
                        "dns.ptr.domain_name",
                        "dns.ns",
                        "dns.mx.mail_exchange",
                        "dns.txt",
                    ],
                ),
                dns_rcode=first(row.get("dns.flags.rcode", "")),
                http_host=first(row.get("http.host", "")),
                http_method=first(row.get("http.request.method", "")),
                http_uri=first(row.get("http.request.uri", "")),
                http_full_uri=first(row.get("http.request.full_uri", "")),
                http_user_agent=first(row.get("http.user_agent", "")),
                http_status=first(row.get("http.response.code", "")),
                http_content_type=first(row.get("http.content_type", "")),
                http_content_length=first(row.get("http.content_length_header", "")) or first(row.get("http.content_length", "")),
                tls_sni=first(row.get("tls.handshake.extensions_server_name", "")),
                icmp_type=first(row.get("icmp.type", "")),
                payload_hex=payload_hex,
                smtp_command=first(row.get("smtp.req.command", "")),
                smtp_parameter=first(row.get("smtp.req.parameter", "")),
                smtp_response=first(row.get("smtp.response", "")),
                smtp_response_code=first(row.get("smtp.response.code", "")),
                smtp_message=first(row.get("smtp.message", "")),
                smtp_auth_username=first(row.get("smtp.auth.username", "")),
                smtp_auth_password=first(row.get("smtp.auth.password", "")),
                mqtt_msg_type=first(row.get("mqtt.msgtype", "")),
                mqtt_topic=first(row.get("mqtt.topic", "")),
                mqtt_message=first(row.get("mqtt.msg_text", "")),
                mqtt_username=first(row.get("mqtt.username", "")),
                mqtt_password=first(row.get("mqtt.passwd", "")),
                tftp_opcode=first(row.get("tftp.opcode", "")),
                tftp_source_file=first(row.get("tftp.source_file", "")),
                tftp_destination_file=first(row.get("tftp.destination_file", "")),
                tftp_request_frame=first(row.get("tftp.request_frame", "")),
                tftp_type=first(row.get("tftp.type", "")),
                tftp_block=first(row.get("tftp.block", "")),
                tftp_block_full=first(row.get("tftp.block.full", "")),
                tftp_error_code=first(row.get("tftp.error.code", "")),
                tftp_error_message=first(row.get("tftp.error.message", "")),
                tftp_data=first(row.get("tftp.data", "")),
                tftp_reassembled_data=first(row.get("tftp.reassembled.data", "")),
                tftp_reassembled_length=first(row.get("tftp.reassembled.length", "")),
            )
        )
    if not packets:
        raise InputFileError("No packets could be parsed from the PCAP.")
    return packets


def first(value: str | None) -> str:
    if not value:
        return ""
    return value.split(",", 1)[0].strip()


def first_nonempty(*values: str | None) -> str:
    for value in values:
        item = first(value)
        if item:
            return item
    return ""


def joined_unique_fields(row: dict[str, str], fields: list[str]) -> str:
    values: list[str] = []
    seen = set()
    for field in fields:
        raw = row.get(field, "")
        if not raw:
            continue
        for item in raw.split(","):
            item = item.strip()
            if item and item not in seen:
                seen.add(item)
                values.append(item)
    return ", ".join(values)


def raise_csv_field_limit() -> None:
    limit = sys.maxsize
    while True:
        try:
            csv.field_size_limit(limit)
            return
        except OverflowError:
            limit = int(limit / 10)


def choose_protocol(column_protocol: str, protocol_stack: str, src_port: str = "", dst_port: str = "") -> str:
    stack = [item.lower() for item in protocol_stack.split(":") if item]
    preferred = [
        ("mqtt", "MQTT"),
        ("tftp", "TFTP"),
        ("smtp", "SMTP"),
        ("http", "HTTP"),
        ("http2", "HTTP2"),
        ("tls", "TLS"),
        ("quic", "QUIC"),
        ("dns", "DNS"),
        ("mdns", "MDNS"),
        ("llmnr", "LLMNR"),
        ("nbns", "NBNS"),
        ("ssdp", "SSDP"),
        ("dhcp", "DHCP"),
        ("icmp", "ICMP"),
        ("igmp", "IGMP"),
        ("arp", "ARP"),
        ("usb", "USB"),
        ("usbhid", "USBHID"),
    ]
    for token, label in preferred:
        if token in stack:
            return label
    if src_port == "1900" or dst_port == "1900":
        return "SSDP"
    if column_protocol:
        return column_protocol.upper()
    if stack:
        return stack[-1].upper()
    return ""
