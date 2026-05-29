from pcat.analysis import build_streams, build_tftp_records, build_tftp_transfers
from pcat.evidence import build_report_evidence
from pcat.models import AnalysisReport, CaptureSummary, PacketRecord


def test_udp_conversations_are_in_stream_view():
    packets = [
        PacketRecord(
            frame_number=1,
            timestamp=1.0,
            length=80,
            protocol="TFTP",
            transport="UDP",
            src_ip="10.0.0.2",
            src_port="49152",
            dst_ip="10.0.0.3",
            dst_port="69",
        ),
        PacketRecord(
            frame_number=2,
            timestamp=1.5,
            length=96,
            protocol="TFTP",
            transport="UDP",
            src_ip="10.0.0.3",
            src_port="69",
            dst_ip="10.0.0.2",
            dst_port="49152",
        ),
    ]
    streams = build_streams(packets)
    assert len(streams) == 1
    assert streams[0].kind == "udp_conversation"
    assert streams[0].protocol == "TFTP"
    assert streams[0].packet_count == 2
    assert streams[0].frame_start == 1
    assert streams[0].frame_end == 2


def test_tftp_transfer_grouping_and_evidence():
    packets = [
        PacketRecord(
            frame_number=1,
            timestamp=1.0,
            length=64,
            protocol="TFTP",
            transport="UDP",
            src_ip="10.0.0.2",
            src_port="49152",
            dst_ip="10.0.0.3",
            dst_port="69",
            tftp_opcode="1",
            tftp_source_file="firmware.bin",
            tftp_type="octet",
        ),
        PacketRecord(
            frame_number=2,
            timestamp=1.1,
            length=520,
            protocol="TFTP",
            transport="UDP",
            src_ip="10.0.0.3",
            src_port="50000",
            dst_ip="10.0.0.2",
            dst_port="49152",
            tftp_opcode="3",
            tftp_request_frame="1",
            tftp_block="1",
            tftp_data=b"abc".hex(),
        ),
        PacketRecord(
            frame_number=3,
            timestamp=1.2,
            length=520,
            protocol="TFTP",
            transport="UDP",
            src_ip="10.0.0.3",
            src_port="50000",
            dst_ip="10.0.0.2",
            dst_port="49152",
            tftp_opcode="3",
            tftp_request_frame="1",
            tftp_block="2",
            tftp_data=b"de".hex(),
        ),
    ]
    records = build_tftp_records(packets)
    transfers = build_tftp_transfers(records)
    assert len(transfers) == 1
    assert transfers[0].filename == "firmware.bin"
    assert transfers[0].direction == "download"
    assert transfers[0].byte_count == 5
    assert transfers[0].completeness == "complete"
    assert transfers[0].data_frames == [2, 3]

    report = AnalysisReport(
        summary=CaptureSummary(file="capture.pcap", size_bytes=1),
        tftp_records=records,
        tftp_transfers=transfers,
    )
    build_report_evidence(report, [], [])
    assert any(item.type == "tftp_transfer" for item in report.evidence)
