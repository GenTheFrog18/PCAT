import json
import gzip

from pcat.artifacts import detect_artifacts, extract_artifacts, write_artifact_manifest


def test_detect_artifact_magic_raw_file(tmp_path):
    sample = tmp_path / "sample.pcap"
    sample.write_bytes(b"noise%PDF-1.7\nbody\n%%EOFtail")
    artifacts = detect_artifacts(sample, include_raw=True)
    assert artifacts
    assert artifacts[0].kind == "pdf"
    assert artifacts[0].source == "raw-file"
    assert artifacts[0].certainty == "confirmed"


def test_extract_artifact(tmp_path):
    sample = tmp_path / "sample.pcap"
    sample.write_bytes(b"noise%PDF-1.7\nbody\n%%EOFtail")
    artifacts = detect_artifacts(sample, include_raw=True)
    saved = extract_artifacts(sample, artifacts, tmp_path / "artifacts")
    assert saved
    assert saved[0].sha256
    assert saved[0].path.endswith(".pdf")


def test_extract_artifact_limit_applies_before_writing(tmp_path):
    sample = tmp_path / "sample.pcap"
    sample.write_bytes(b"%PDF-1.7\none\n%%EOFnoise%PDF-1.7\ntwo\n%%EOF")
    artifacts = detect_artifacts(sample, include_raw=True)
    saved = extract_artifacts(sample, artifacts, tmp_path / "artifacts", limit=1)
    assert len(saved) == 1
    assert len(list((tmp_path / "artifacts").glob("*"))) == 1


def test_invalid_artifact_is_not_extracted(tmp_path):
    sample = tmp_path / "sample.pcap"
    sample.write_bytes(b"noise\x1f\x8bnot-a-real-gzip")
    artifacts = detect_artifacts(sample, include_raw=True)
    assert artifacts[0].validation == "invalid"
    assert artifacts[0].certainty == "rejected"
    saved = extract_artifacts(sample, artifacts, tmp_path / "artifacts")
    assert saved == []
    assert artifacts[0].extraction_status == "skipped_invalid"


def test_truncated_gzip_is_candidate_not_extracted(tmp_path):
    sample = tmp_path / "sample.pcap"
    sample.write_bytes(b"noise" + gzip.compress(b"flag{inside}")[:-8])
    artifacts = detect_artifacts(sample, include_raw=True)
    assert artifacts[0].kind == "gzip"
    assert artifacts[0].validation == "truncated"
    assert artifacts[0].certainty == "candidate"
    assert artifacts[0].complete_file_valid is False
    assert artifacts[0].truncated is True
    saved = extract_artifacts(sample, artifacts, tmp_path / "artifacts")
    assert saved == []
    assert artifacts[0].extraction_status == "skipped_incomplete"


def test_pcap_gz_input_wrapper_is_not_reported_as_artifact(tmp_path):
    sample = tmp_path / "sample.pcap.gz"
    sample.write_bytes(gzip.compress(b"pcap bytes placeholder"))
    artifacts = detect_artifacts(sample, include_raw=True)
    assert artifacts == []


def test_embedded_packet_gzip_still_detected(tmp_path):
    sample = tmp_path / "sample.pcap"
    sample.write_bytes(b"not gzip")
    artifacts = detect_artifacts(sample, [("packet:7", gzip.compress(b"flag{inside}"))], include_raw=True)
    assert len(artifacts) == 1
    assert artifacts[0].kind == "gzip"
    assert artifacts[0].source == "packet:7"
    assert artifacts[0].certainty == "confirmed"


def test_ordinary_media_artifact_is_not_critical(tmp_path):
    sample = tmp_path / "sample.pcap"
    sample.write_bytes(b"not image")
    artifacts = detect_artifacts(sample, [("packet:9", b"GIF89a;")], include_raw=False)
    assert artifacts[0].kind == "gif"
    assert artifacts[0].certainty == "confirmed"
    assert artifacts[0].score < 75


def test_signature_only_artifact_is_candidate(tmp_path):
    sample = tmp_path / "sample.pcap"
    sample.write_bytes(b"noiseRar!\x1a\x07\x00payload")
    artifacts = detect_artifacts(sample, include_raw=True)
    assert artifacts[0].kind == "rar"
    assert artifacts[0].validation == "signature_only"
    assert artifacts[0].certainty == "candidate"


def test_pe_artifact_is_detected_and_ranked(tmp_path):
    sample = tmp_path / "sample.pcap"
    pe = bytearray(b"MZ" + b"\x00" * 0x300)
    pe[0x3C:0x40] = (0x80).to_bytes(4, "little")
    pe[0x80:0x84] = b"PE\x00\x00"
    pe[0x84:0x86] = (0x14C).to_bytes(2, "little")
    pe[0x86:0x88] = (1).to_bytes(2, "little")
    pe[0x94:0x96] = (0xE0).to_bytes(2, "little")
    section = 0x80 + 24 + 0xE0
    pe[section : section + 8] = b".text\x00\x00\x00"
    pe[section + 16 : section + 20] = (4).to_bytes(4, "little")
    pe[section + 20 : section + 24] = (0x200).to_bytes(4, "little")
    pe[0x200:0x204] = b"\x90\x90\xc3\x00"
    sample.write_bytes(bytes(pe))
    artifacts = detect_artifacts(sample, include_raw=True)
    assert artifacts[0].kind == "pe"
    assert artifacts[0].validation == "validated"
    assert artifacts[0].certainty == "confirmed"
    assert artifacts[0].score >= 50


def test_write_artifact_manifest(tmp_path):
    sample = tmp_path / "sample.pcap"
    sample.write_bytes(b"noise%PDF-1.7\nbody\n%%EOFtail")
    artifacts = detect_artifacts(sample, include_raw=True)
    saved = extract_artifacts(sample, artifacts, tmp_path / "artifacts")
    manifest = write_artifact_manifest(saved, tmp_path / "artifacts")
    data = json.loads(manifest.read_text())
    assert manifest.name == "manifest.json"
    assert data[0]["artifact_id"] == saved[0].artifact_id
    assert data[0]["manifest_path"].endswith("manifest.json")
