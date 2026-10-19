"""End-to-end pipeline test using offline fixtures."""

from darkpulse.config import DEFAULT_FIXTURE_DIR, Settings
from darkpulse.pipeline import Pipeline, load_fixtures
from darkpulse.storage.base import InMemoryStore


def _pipeline(tmp_path) -> Pipeline:
    settings = Settings(
        offline=True,
        fixture_dir=DEFAULT_FIXTURE_DIR,
        snapshot_dir=tmp_path / "snapshots",
    )
    store = InMemoryStore(snapshot_dir=settings.snapshot_dir)
    return Pipeline(settings=settings, store=store)


class TestPipelineOffline:
    def test_fixture_loading(self):
        records = load_fixtures(DEFAULT_FIXTURE_DIR)
        assert len(records) >= 10
        sources = {r.source.value for r in records}
        assert {"nvd", "cisa_kev", "rss"} <= sources

    def test_full_run(self, tmp_path):
        pipeline = _pipeline(tmp_path)
        result = pipeline.run(offline=True)

        assert result.raw_stored >= 10
        assert result.normalized_stored >= 10
        assert result.extractions == result.normalized_stored
        assert result.nodes > 10
        assert result.edges > 10
        assert result.correlated_events > 1
        assert not result.errors, result.errors

    def test_extraction_finds_cves_and_entities(self, tmp_path):
        pipeline = _pipeline(tmp_path)
        records = pipeline.ingest(offline=True)
        extractions = pipeline.extract(records)

        all_cves = {
            i.value for ext in extractions for i in ext.indicators if i.kind == "cve"
        }
        assert "CVE-2024-3400" in all_cves
        all_names = {e.name for ext in extractions for e in ext.entities}
        assert "LockBit" in all_names or "APT28" in all_names

    def test_analysis_produces_alerts(self, tmp_path):
        pipeline = _pipeline(tmp_path)
        pipeline.run(offline=True)
        assert pipeline.last_alerts, "expected ranked alerts"
        top = pipeline.last_alerts[0]
        assert top.rank == 1
        assert top.score > 0
        assert top.entity

    def test_artifacts_export(self, tmp_path):
        pipeline = _pipeline(tmp_path)
        pipeline.run(offline=True)
        paths = pipeline.export_artifacts(str(tmp_path / "out"))
        for key in ("snapshot", "graph", "alerts", "spikes"):
            assert key in paths
        import json, os

        assert os.path.exists(paths["graph"])
        with open(paths["alerts"], encoding="utf-8") as fh:
            alerts = json.load(fh)
        assert alerts and alerts[0]["rank"] == 1
