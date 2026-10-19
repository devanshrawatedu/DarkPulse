"""Edge cases and failure paths: malformed input must degrade, not crash."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from darkpulse.analysis.risk import RiskEngine
from darkpulse.analysis.temporal import TemporalAnalyzer
from darkpulse.config import (
    DEFAULT_FIXTURE_DIR,
    RiskWeights,
    Settings,
    SourceConfig,
)
from darkpulse.correlation import cluster_events
from darkpulse.extraction.indicators import (
    Extractor,
    extract_entities_heuristic,
    extract_indicators,
)
from darkpulse.graph.kb import ThreatGraph, canonical_entity
from darkpulse.ingestion.retry import TransientError
from darkpulse.ingestion.sources import (
    FeedConnector,
    KevConnector,
    NvdConnector,
    _extract_cvss,
)
from darkpulse.models import (
    EntityType,
    ExtractedEntity,
    NormalizedRecord,
    SourceKind,
)
from darkpulse.pipeline import Pipeline, load_fixtures
from darkpulse.storage.base import InMemoryStore
from darkpulse.utils import parse_dt

NOW = datetime.now(timezone.utc)


def _record(
    record_id: str,
    *,
    title: str = "title",
    text: str = "text",
    days_ago: int | None = 0,
    source: SourceKind = SourceKind.RSS,
) -> NormalizedRecord:
    published = None if days_ago is None else NOW - timedelta(days=days_ago)
    return NormalizedRecord(
        id=record_id,
        source=source,
        source_record_id=record_id,
        record_type="article",
        title=title,
        text=text,
        published_at=published,
    )


class _FakeResponse:
    """Minimal httpx.Response stand-in for connector tests."""

    url = "https://example.invalid/resource"

    def __init__(
        self,
        *,
        payload: dict | None = None,
        content: bytes = b"",
        json_error: Exception | None = None,
    ) -> None:
        self._payload = payload
        self._json_error = json_error
        self.content = content

    def json(self):
        if self._json_error is not None:
            raise self._json_error
        return self._payload


def _settings(**overrides) -> Settings:
    return Settings(offline=True, fixture_dir=DEFAULT_FIXTURE_DIR, **overrides)


class TestMalformedIndicators:
    @pytest.mark.parametrize(
        "text",
        [
            "CVE-2024-340",  # sequence too short
            "CVE-24-1234",  # year too short
            "CVE-0000-0000",  # invalid year
            "CVE-1800-1234",  # pre-CVE year
            "CVE-2024-0000",  # zero sequence
            "CVE-2024-12345678901234x",  # trailing junk
        ],
    )
    def test_rejects_malformed_cve_ids(self, text: str) -> None:
        assert [i for i in extract_indicators(text) if i.kind == "cve"] == []

    def test_normalizes_case_but_keeps_digits(self) -> None:
        cves = [i.value for i in extract_indicators("cve-2024-3400") if i.kind == "cve"]
        assert cves == ["CVE-2024-3400"]

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("play and display and playbook", {"play"}),
            ("NotPetya samples", {"notpetya"}),
        ],
    )
    def test_glossary_uses_word_boundaries(
        self, text: str, expected: set[str]
    ) -> None:
        names = {e.name.lower() for e in extract_entities_heuristic(text)}
        assert expected <= names
        if "notpetya" in expected:
            assert "petya" not in names
        if "play" in expected:
            assert names == {"play"}

    def test_defanged_indicators_are_restored(self) -> None:
        kinds = {i.kind for i in extract_indicators("hxxp://evil[.]example[.]com")}
        assert "domain" in kinds

    def test_empty_text_returns_no_indicators(self) -> None:
        assert extract_indicators("") == []
        assert extract_entities_heuristic("") == []

    def test_ner_indicator_noise_is_not_an_entity(self) -> None:
        class _NlpStub:
            def extract(self, text: str) -> list[ExtractedEntity]:
                return [
                    ExtractedEntity(
                        name="CVE-2024-3400",
                        type=EntityType.ORGANIZATION,
                        confidence=0.55,
                        extractor="spacy",
                    ),
                    ExtractedEntity(
                        name="Acme Corp",
                        type=EntityType.ORGANIZATION,
                        confidence=0.55,
                        extractor="spacy",
                    ),
                ]

        extractor = Extractor(use_nlp=False)
        extractor.nlp = _NlpStub()
        result = extractor.extract(
            _record("ner", title="advisory", text="Acme Corp said")
        )
        assert [entity.name for entity in result.entities] == ["Acme Corp"]


class TestTimestampFailures:
    @pytest.mark.parametrize(
        "value", [None, "", "   ", "not-a-date", "2024-99-99T00:00:00Z", 12345]
    )
    def test_unparseable_timestamps_return_none(self, value) -> None:
        assert parse_dt(value) is None

    def test_naive_and_offset_timestamps_are_normalized_to_utc(self) -> None:
        naive = parse_dt("2024-01-01T12:00:00")
        offset = parse_dt("2024-01-01T12:00:00+05:30")
        assert naive is not None and naive.tzinfo is timezone.utc
        assert offset is not None and offset.hour == 6 and offset.minute == 30

    def test_invalid_timestamp_is_rejected_by_the_model(self) -> None:
        with pytest.raises(ValidationError):
            NormalizedRecord(
                id="x",
                source=SourceKind.RSS,
                source_record_id="x",
                record_type="article",
                title="t",
                text="b",
                published_at="not-a-date",
            )

    def test_record_falls_back_to_ingested_at(self) -> None:
        record = _record("r", days_ago=None)
        assert record.published_at is None
        assert record.timestamp == record.ingested_at

    def test_temporal_analysis_handles_missing_timestamps(self) -> None:
        record = _record("r", text="CVE-2024-1111", days_ago=None)
        spikes = TemporalAnalyzer().detect_spikes(
            [record], {record.id: ["CVE-2024-1111"]}
        )
        assert spikes == []


class TestTemporalRegression:
    def test_spike_beyond_the_first_baseline_window_is_detected(self) -> None:
        """Regression: the analyzer once only inspected the first 15 days."""
        records: list[NormalizedRecord] = []
        keys: dict[str, list[str]] = {}
        for offset in range(40):
            record = _record(f"day-{offset}", days_ago=39 - offset)
            records.append(record)
            keys[record.id] = []
        for index in range(6):
            record = _record(f"burst-{index}", days_ago=0)
            records.append(record)
            keys[record.id] = ["CVE-2024-9999"]

        spikes = TemporalAnalyzer(z_threshold=1.5, min_baseline=3).detect_spikes(
            records, keys
        )
        assert [spike.entity for spike in spikes] == ["CVE-2024-9999"]
        assert spikes[0].window == NOW.strftime("%Y-%m-%d")
        assert spikes[0].z_score >= 1.5

    def test_empty_records_produce_no_spikes(self) -> None:
        assert TemporalAnalyzer().detect_spikes([]) == []

    def test_unknown_record_keys_are_ignored(self) -> None:
        record = _record("r")
        assert TemporalAnalyzer().detect_spikes([record], {"other": ["x"]}) == []


class TestIngestionFailurePaths:
    def test_kev_empty_catalog_still_stores_raw_provenance(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            "darkpulse.ingestion.sources.fetch_with_retry",
            lambda *args, **kwargs: _FakeResponse(payload={"vulnerabilities": []}),
        )
        store = InMemoryStore()
        settings = _settings()
        connector = KevConnector(store, settings, settings.source("cisa_kev"))

        assert connector.fetch() == []
        assert store.count_raw() == 1

    def test_kev_malformed_json_returns_empty(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            "darkpulse.ingestion.sources.fetch_with_retry",
            lambda *args, **kwargs: _FakeResponse(
                json_error=ValueError("bad json")
            ),
        )
        store = InMemoryStore()
        settings = _settings()
        connector = KevConnector(store, settings, settings.source("cisa_kev"))

        assert connector.fetch() == []
        assert store.count_raw() == 0

    def test_feed_outage_returns_empty_and_continues(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def _fail(*args, **kwargs):
            raise TransientError("feed down")

        monkeypatch.setattr("darkpulse.ingestion.sources.fetch_with_retry", _fail)
        store = InMemoryStore()
        settings = _settings()
        connector = FeedConnector(store, settings, settings.source("feeds"))

        assert connector.fetch(feeds=["https://example.invalid/feed"]) == []
        assert store.count_normalized() == 0

    def test_empty_feed_body_returns_no_records(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        empty_rss = (
            b'<?xml version="1.0"?><rss version="2.0"><channel>'
            b"<title>empty</title></channel></rss>"
        )
        monkeypatch.setattr(
            "darkpulse.ingestion.sources.fetch_with_retry",
            lambda *args, **kwargs: _FakeResponse(content=empty_rss),
        )
        store = InMemoryStore()
        settings = _settings()
        connector = FeedConnector(store, settings, settings.source("feeds"))

        assert connector.fetch(feeds=["https://example.invalid/feed"]) == []

    def test_nvd_normalization_tolerates_missing_fields(self) -> None:
        settings = _settings()
        connector = NvdConnector(
            InMemoryStore(), settings, settings.source("nvd")
        )

        assert connector._normalize_cve({}, "raw") is None
        record = connector._normalize_cve({"id": "CVE-2024-1111"}, "raw")
        assert record is not None
        assert record.published_at is None
        assert record.metadata["cvss"] is None
        assert record.labels == ["cve"]

    def test_cvss_parsing_ignores_garbage_scores(self) -> None:
        assert _extract_cvss({}) is None
        assert _extract_cvss({"cvssMetricV31": [{"cvssData": {"baseScore": "high"}}]}) is None
        assert (
            _extract_cvss({"cvssMetricV2": [{"cvssData": {"baseScore": "7.5"}}]})
            == 7.5
        )

    def test_load_fixtures_skips_bad_records_and_broken_files(self, tmp_path) -> None:
        directory = tmp_path / "fixtures"
        directory.mkdir()
        (directory / "broken.json").write_text("{not json", encoding="utf-8")
        (directory / "mixed.json").write_text(
            json.dumps(
                {
                    "records": [
                        {"source": "bogus", "title": "bad source"},
                        {
                            "source": "rss",
                            "source_record_id": "ok-1",
                            "record_type": "article",
                            "title": "Valid",
                            "text": "CVE-2024-3400",
                        },
                    ]
                }
            ),
            encoding="utf-8",
        )

        records = load_fixtures(directory)
        assert len(records) == 1
        assert records[0].source is SourceKind.RSS

    def test_missing_fixture_directory_returns_empty(self, tmp_path) -> None:
        assert load_fixtures(tmp_path / "does-not-exist") == []


class TestPipelineResilience:
    def test_disabled_sources_are_not_fetched(self, tmp_path) -> None:
        settings = Settings(
            offline=False,
            fixture_dir=DEFAULT_FIXTURE_DIR,
            snapshot_dir=tmp_path / "snapshots",
            sources=[
                SourceConfig(name="nvd", url="https://invalid.example", enabled=False),
                SourceConfig(
                    name="cisa_kev", url="https://invalid.example", enabled=False
                ),
                SourceConfig(name="feeds", url="", enabled=False),
            ],
        )
        pipeline = Pipeline(settings, InMemoryStore())

        assert pipeline.ingest(offline=False) == []

    def test_failing_phase_is_recorded_and_run_completes(
        self, tmp_path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = Settings(
            offline=True,
            fixture_dir=DEFAULT_FIXTURE_DIR,
            snapshot_dir=tmp_path / "snapshots",
        )
        pipeline = Pipeline(settings, InMemoryStore())

        def _boom(record):
            raise RuntimeError("extractor exploded")

        monkeypatch.setattr(pipeline.extractor, "extract", _boom)
        result = pipeline.run(offline=True)

        assert any(error.startswith("extract:") for error in result.errors)
        assert result.finished_at is not None
        assert result.alerts == 0
        assert result.nodes == 0
        assert pipeline.last_alerts == []

    def test_graph_is_rebuilt_between_runs(self, tmp_path) -> None:
        settings = Settings(
            offline=True,
            fixture_dir=DEFAULT_FIXTURE_DIR,
            snapshot_dir=tmp_path / "snapshots",
        )
        pipeline = Pipeline(settings, InMemoryStore())

        first = pipeline.run(offline=True)
        second = pipeline.run(offline=True)

        assert first.nodes == second.nodes
        assert first.edges == second.edges


class TestCorrelationEdgeCases:
    def test_no_records_produces_no_events(self) -> None:
        assert cluster_events([]) == []

    def test_entity_names_are_attached_to_events(self) -> None:
        record = _record("r", text="CVE-2024-7777 ransomware")
        events = cluster_events([record], entity_names={record.id: ["LockBit", "LockBit"]})
        assert events[0].entities == ["LockBit"]
        assert events[0].cves == ["CVE-2024-7777"]

    def test_same_source_metadata_is_deduplicated(self) -> None:
        first = _record("a", text="CVE-2024-6666", source=SourceKind.NVD)
        second = _record("b", text="CVE-2024-6666", source=SourceKind.NVD)
        events = cluster_events([first, second])
        assert events[0].sources == ["nvd"]


class TestRiskEdgeCases:
    def test_no_entities_yields_no_alerts(self) -> None:
        assert (
            RiskEngine().score_entities(
                {},
                entity_meta={},
                mention_dates={},
                graph_degree={},
            )
            == []
        )

    def test_zero_weights_yield_zero_scores(self) -> None:
        engine = RiskEngine(
            weights=RiskWeights(
                activity_growth=0,
                relationship_density=0,
                severity=0,
                recency=0,
                asset_relevance=0,
            )
        )
        alerts = engine.score_entities(
            {"vulnerability:cve-x": 3},
            entity_meta={
                "vulnerability:cve-x": {
                    "type": "vulnerability",
                    "name": "CVE-X",
                    "cvss": 10.0,
                }
            },
            mention_dates={"vulnerability:cve-x": [NOW]},
            graph_degree={"vulnerability:cve-x": 4},
        )
        assert alerts[0].score == 0.0
        assert set(alerts[0].components.values()) == {0.0}

    def test_inflated_weights_are_normalized(self) -> None:
        engine = RiskEngine(
            weights=RiskWeights(
                activity_growth=1.0,
                relationship_density=1.0,
                severity=1.0,
                recency=1.0,
                asset_relevance=1.0,
            )
        )
        alerts = engine.score_entities(
            {"vulnerability:cve-x": 3},
            entity_meta={
                "vulnerability:cve-x": {
                    "type": "vulnerability",
                    "name": "CVE-X",
                    "cvss": 10.0,
                    "related_cves": ["CVE-X", "CVE-X"],
                }
            },
            mention_dates={"vulnerability:cve-x": [NOW]},
            graph_degree={"vulnerability:cve-x": 4},
        )
        assert 0.0 <= alerts[0].score <= 1.0
        assert alerts[0].related_cves == ["CVE-X"]

    def test_negative_weights_are_rejected(self) -> None:
        with pytest.raises(ValidationError):
            RiskWeights(severity=-0.5)

    def test_non_positive_half_life_is_rejected(self) -> None:
        with pytest.raises(ValueError):
            RiskEngine(half_life_days=0)

    def test_unknown_entity_type_degrades_to_indicator(self) -> None:
        alerts = RiskEngine().score_entities(
            {"mystery": 1},
            entity_meta={"mystery": {"type": "not-a-type", "name": "Mystery"}},
            mention_dates={"mystery": [NOW]},
            graph_degree={"mystery": 1},
        )
        assert alerts[0].entity_type is EntityType.INDICATOR


class TestStorageAndGraphEdgeCases:
    def test_limit_zero_returns_no_records(self) -> None:
        store = InMemoryStore()
        store.save_normalized(_record("r"))
        assert store.list_normalized(limit=0) == []
        assert store.count_normalized() == 1

    def test_edges_to_unknown_nodes_are_ignored(self) -> None:
        graph = ThreatGraph()
        graph.add_edge("missing:a", "missing:b", "USED_BY")
        assert graph.stats() == {"nodes": 0, "edges": 0}

    def test_reset_clears_the_graph(self) -> None:
        graph = ThreatGraph()
        graph.ensure_node("CVE-2024-3400", EntityType.VULNERABILITY)
        graph.reset()
        assert graph.stats() == {"nodes": 0, "edges": 0}

    def test_canonicalization_collapses_whitespace(self) -> None:
        assert canonical_entity("  Fancy   Bear ") == (
            EntityType.THREAT_ACTOR,
            "APT28",
        )

    def test_empty_name_has_no_canonical_form(self) -> None:
        assert canonical_entity("   ") is None

    def test_snapshot_roundtrip_creates_parent_directories(self, tmp_path) -> None:
        store = InMemoryStore()
        store.save_normalized(_record("r", title="hello"))
        target = store.save_snapshot(tmp_path / "nested" / "dir" / "snap.json")
        restored = InMemoryStore.load_snapshot(target)
        assert restored.list_normalized()[0].title == "hello"
