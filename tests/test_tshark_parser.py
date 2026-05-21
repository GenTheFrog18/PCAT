from pathlib import Path
from types import SimpleNamespace

import pcat.tshark_parser as parser


def tshark_output(row_values):
    row = {field: "" for field in parser.FIELDS}
    row.update(row_values)
    return "\t".join(parser.FIELDS) + "\n" + "\t".join(row[field] for field in parser.FIELDS) + "\n"


def test_parse_packets_raises_csv_field_limit(monkeypatch, tmp_path):
    big_payload = "41" * 70000
    monkeypatch.setattr(
        parser,
        "run_tshark_fields",
        lambda path: tshark_output(
            {
                "frame.number": "1",
                "frame.time_epoch": "1.5",
                "frame.len": "70040",
                "frame.protocols": "raw:ip:tcp:data",
                "_ws.col.Protocol": "TCP",
                "ip.src": "10.0.0.1",
                "ip.dst": "10.0.0.2",
                "tcp.srcport": "12345",
                "tcp.dstport": "80",
                "tcp.len": "70000",
                "data.data": big_payload,
            }
        ),
    )
    sample = tmp_path / "large.pcap"
    sample.write_bytes(b"not real")
    packets = parser.parse_packets(sample)
    assert packets[0].payload_hex == big_payload
    assert packets[0].tcp_len == "70000"


def test_parse_packets_uses_tcp_payload_and_app_protocol(monkeypatch, tmp_path):
    monkeypatch.setattr(
        parser,
        "run_tshark_fields",
        lambda path: tshark_output(
            {
                "frame.number": "7",
                "frame.time_epoch": "2.0",
                "frame.len": "80",
                "frame.protocols": "raw:ip:tcp:mqtt",
                "_ws.col.Protocol": "TCP",
                "ip.src": "10.0.0.1",
                "ip.dst": "10.0.0.2",
                "tcp.srcport": "1883",
                "tcp.dstport": "51515",
                "tcp.payload": "666c6167",
                "mqtt.topic": "demo/topic",
                "mqtt.msg_text": "decode me",
            }
        ),
    )
    sample = tmp_path / "mqtt.pcap"
    sample.write_bytes(b"not real")
    packet = parser.parse_packets(sample)[0]
    assert packet.payload_hex == "666c6167"
    assert packet.protocol == "MQTT"
    assert packet.mqtt_topic == "demo/topic"


def test_parse_packets_combines_dns_answer_fields(monkeypatch, tmp_path):
    monkeypatch.setattr(
        parser,
        "run_tshark_fields",
        lambda path: tshark_output(
            {
                "frame.number": "10",
                "frame.time_epoch": "3.0",
                "frame.len": "120",
                "frame.protocols": "eth:ip:udp:dns",
                "_ws.col.Protocol": "DNS",
                "ip.src": "10.0.0.2",
                "ip.dst": "10.0.0.53",
                "udp.srcport": "5353",
                "udp.dstport": "53",
                "dns.qry.name": "example.test",
                "dns.aaaa": "2001:db8::1",
                "dns.cname": "alias.example.test",
                "dns.ptr.domain_name": "ptr.example.test",
                "dns.ns": "ns1.example.test",
                "dns.mx.mail_exchange": "mail.example.test",
                "dns.txt": "v=spf1 -all",
                "dns.flags.rcode": "0",
            }
        ),
    )
    sample = tmp_path / "dns.cap"
    sample.write_bytes(b"not real")
    packet = parser.parse_packets(sample)[0]
    assert packet.dns_query == "example.test"
    assert packet.dns_answer == "2001:db8::1, alias.example.test, ptr.example.test, ns1.example.test, mail.example.test, v=spf1 -all"
    assert packet.dns_rcode == "0"


def test_run_tshark_fields_adds_input_class_guidance(monkeypatch, tmp_path):
    monkeypatch.setattr(parser, "require_tshark", lambda: "tshark")

    def fake_run(*args, **kwargs):
        return SimpleNamespace(returncode=2, stdout="", stderr="not a capture")

    monkeypatch.setattr(parser.subprocess, "run", fake_run)

    archive = tmp_path / "bundle.zip"
    archive.write_bytes(b"PK\x03\x04demo")
    html = tmp_path / "download.pcap"
    html.write_bytes(b"<html>not raw pcap</html>")
    gzip_file = tmp_path / "capture.pcap.gz"
    gzip_file.write_bytes(b"\x1f\x8b\x08demo")

    cases = [
        (archive, "archive"),
        (html, "HTML"),
        (gzip_file, "decompress"),
    ]
    for path, expected in cases:
        try:
            parser.run_tshark_fields(path)
        except Exception as exc:
            assert expected in str(exc)
        else:
            raise AssertionError("expected parser failure")
