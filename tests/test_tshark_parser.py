from pathlib import Path

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
