from pcat.utils import classify_input_file, validate_input


def test_validate_input_allows_tshark_parseable_extensions(tmp_path):
    for name in ["capture.cap", "capture.pcap.gz", "capture.weird"]:
        sample = tmp_path / name
        sample.write_bytes(b"\xd4\xc3\xb2\xa1")
        assert validate_input(sample) == sample


def test_classify_input_file_detects_common_non_capture_inputs(tmp_path):
    archive = tmp_path / "bundle.zip"
    archive.write_bytes(b"PK\x03\x04demo")
    html = tmp_path / "download.pcap"
    html.write_bytes(b"<!doctype html><html>not the raw capture</html>")
    gzip_file = tmp_path / "capture.gz"
    gzip_file.write_bytes(b"\x1f\x8b\x08demo")

    assert classify_input_file(archive) == "archive"
    assert classify_input_file(html) == "html"
    assert classify_input_file(gzip_file) == "gzip"
