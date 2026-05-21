import json

from pcat.artifacts import detect_artifacts, extract_artifacts, write_artifact_manifest


def test_detect_artifact_magic_raw_file(tmp_path):
    sample = tmp_path / "sample.pcap"
    sample.write_bytes(b"noise%PDF-1.7\nbody\n%%EOFtail")
    artifacts = detect_artifacts(sample, include_raw=True)
    assert artifacts
    assert artifacts[0].kind == "pdf"
    assert artifacts[0].source == "raw-file"


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
    saved = extract_artifacts(sample, artifacts, tmp_path / "artifacts")
    assert saved == []


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
