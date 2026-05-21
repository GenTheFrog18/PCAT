from pcat.artifacts import detect_artifacts
from pcat.models import AnalysisReport, CaptureSummary
from pcat.stories import build_briefing, build_stories


def test_artifact_stories_separate_confirmed_and_rejected(tmp_path):
    sample = tmp_path / "sample.pcap"
    sample.write_bytes(b"%PDF-1.7\nbody\n%%EOFnoise\x1f\x8bnot-a-real-gzip")
    artifacts = detect_artifacts(sample, include_raw=True)
    report = AnalysisReport(summary=CaptureSummary(file=str(sample), size_bytes=sample.stat().st_size, packet_count=1), artifacts=artifacts)

    report.stories = build_stories(report, [])
    report.briefing = build_briefing(report, [])

    titles = [story.title for story in report.stories]
    assert any("confirmed artifact" in title for title in titles)
    assert any("rejected file signature" in title for title in titles)
    assert any("rejected" in limit.lower() for story in report.stories for limit in story.limitations)
    assert report.briefing.capture_type
