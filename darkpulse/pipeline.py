"""End-to-end pipeline: ingestion -> extraction -> graph -> correlation -> analysis."""

from __future__ import annotations

import json
import logging
from collections import Counter
from collections.abc import Callable, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any, TypeVar

from .analysis.risk import RiskEngine
from .analysis.temporal import TemporalAnalyzer
from .config import Settings, get_settings
from .correlation import cluster_events
from .extraction import Extractor
from .graph.kb import ThreatGraph, canonical_entity
from .ingestion.sources import FeedConnector, KevConnector, NvdConnector
from .models import (
    CorrelatedEvent,
    EntityType,
    ExtractionResult,
    NormalizedRecord,
    PipelineResult,
    RawRecord,
    RiskAlert,
    SourceKind,
    Spike,
    stable_id,
)
from .storage import InMemoryStore, create_store
from .storage.base import BaseStore
from .utils import configure_logging, utcnow

logger = logging.getLogger(__name__)

T = TypeVar("T")

_CONNECTORS = {
    "nvd": NvdConnector,
    "cisa_kev": KevConnector,
    "feeds": FeedConnector,
}


class Pipeline:
    """Orchestrates every DarkPulse layer and keeps the latest artifacts."""

    def __init__(
        self, settings: Settings | None = None, store: BaseStore | None = None
    ) -> None:
        self.settings = settings or get_settings()
        configure_logging(self.settings.log_level)
        self.settings.ensure_dirs()
        self.store = store or create_store(self.settings)
        self.extractor = Extractor(spacy_model=self.settings.spacy_model)
        self.graph = ThreatGraph()

        # Artifacts from the last run (consumed by the dashboard/CLI)
        self.last_records: list[NormalizedRecord] = []
        self.last_events: list[CorrelatedEvent] = []
        self.last_spikes: list[Spike] = []
        self.last_alerts: list[RiskAlert] = []
        self.last_errors: list[str] = []

    # ------------------------------------------------------------------
    # 1. Ingestion
    # ------------------------------------------------------------------
    def ingest(self, offline: bool | None = None) -> list[NormalizedRecord]:
        if offline is None:
            offline = self.settings.offline
        if offline:
            return self._ingest_fixtures()

        records: list[NormalizedRecord] = []
        for name, connector_type in _CONNECTORS.items():
            config = self.settings.source(name)
            if config is None or not config.enabled:
                continue
            try:
                records.extend(
                    connector_type(self.store, self.settings, config).fetch()
                )
            except Exception as exc:  # one broken source must not abort the rest
                logger.exception("connector %r failed", name)
                self.last_errors.append(f"connector {name}: {exc}")

        self.last_records = records
        return records

    def _ingest_fixtures(self) -> list[NormalizedRecord]:
        records = load_fixtures(self.settings.fixture_dir)
        for record in records:
            raw_id = stable_id(record.source.value, record.source_record_id)
            self.store.save_raw(
                RawRecord(
                    id=raw_id,
                    source=record.source,
                    source_record_id=record.source_record_id,
                    payload=record.model_dump(mode="json"),
                )
            )
            record.raw_id = raw_id
            self.store.save_normalized(record)
        logger.info("offline mode: %d fixture records ingested", len(records))
        self.last_records = records
        return records

    # ------------------------------------------------------------------
    # 2. Extraction
    # ------------------------------------------------------------------
    def extract(self, records: Sequence[NormalizedRecord]) -> list[ExtractionResult]:
        results = [self.extractor.extract(record) for record in records]
        logger.info("extraction: %d results from %d records", len(results), len(records))
        return results

    # ------------------------------------------------------------------
    # 3. Graph
    # ------------------------------------------------------------------
    def build_graph(
        self,
        records: Sequence[NormalizedRecord],
        extractions: Sequence[ExtractionResult],
        cve_severities: dict[str, float] | None = None,
    ) -> ThreatGraph:
        """Rebuild the graph from scratch for this run (no cross-run bleed)."""
        self.graph.reset()
        self.graph.build_from_extractions(
            list(extractions),
            {record.id: record for record in records},
            cve_severities or {},
        )
        logger.info("graph: %s", self.graph.stats())
        return self.graph

    # ------------------------------------------------------------------
    # 4. Correlation
    # ------------------------------------------------------------------
    def correlate(
        self,
        records: Sequence[NormalizedRecord],
        extractions: Sequence[ExtractionResult] | None = None,
    ) -> list[CorrelatedEvent]:
        entity_names = {
            extraction.record_id: [entity.name for entity in extraction.entities]
            for extraction in extractions or ()
        }
        events = cluster_events(
            records,
            similarity_threshold=self.settings.correlation_similarity_threshold,
            entity_names=entity_names,
        )
        self.last_events = events
        return events

    # ------------------------------------------------------------------
    # 5. Analysis (temporal + risk)
    # ------------------------------------------------------------------
    def analyze(
        self,
        records: Sequence[NormalizedRecord],
        extractions: Sequence[ExtractionResult],
    ) -> tuple[list[Spike], list[RiskAlert]]:
        by_record = {
            extraction.record_id: extraction for extraction in extractions
        }
        mention_counts: Counter[str] = Counter()
        mention_dates: dict[str, list[datetime]] = {}
        entity_meta: dict[str, dict[str, Any]] = {}

        for record in records:
            extraction = by_record.get(record.id)
            if extraction is None:
                continue
            metadata = record.metadata or {}
            cvss = _as_float(metadata.get("cvss"))
            ransomware = metadata.get("known_ransomware")

            for key, entity_type, display in self._entity_keys(extraction):
                mention_counts[key] += 1
                mention_dates.setdefault(key, []).append(record.timestamp)
                meta = entity_meta.setdefault(
                    key,
                    {
                        "type": entity_type,
                        "name": display,
                        "aliases": set(),
                        "labels": set(),
                        "related_cves": [],
                        "cvss": None,
                        "ransomware_use": None,
                    },
                )
                meta["aliases"].add(display)
                meta["labels"].update(record.labels)
                if entity_type is EntityType.VULNERABILITY:
                    if cvss is not None:
                        meta["cvss"] = (
                            cvss if meta["cvss"] is None else max(meta["cvss"], cvss)
                        )
                    if ransomware == "Known":
                        meta["ransomware_use"] = "Known"
                    if display not in meta["related_cves"]:
                        meta["related_cves"].append(display)

        for key, dates in mention_dates.items():
            entity_meta[key]["first_seen"] = min(dates)
            entity_meta[key]["last_seen"] = max(dates)

        spike_input = {
            record_id: [
                display
                for _, entity_type, display in self._entity_keys(extraction)
                if entity_type is EntityType.VULNERABILITY
            ]
            for record_id, extraction in by_record.items()
        }
        spikes = TemporalAnalyzer(
            z_threshold=self.settings.spike_z_threshold,
            min_baseline=self.settings.min_baseline_observations,
        ).detect_spikes(records, spike_input)

        alerts = RiskEngine(
            weights=self.settings.risk_weights,
            monitored_assets=self.settings.monitored_assets,
        ).score_entities(
            mention_counts,
            entity_meta=entity_meta,
            mention_dates=mention_dates,
            graph_degree=self.graph.entity_degrees(),
        )

        self.last_spikes = spikes
        self.last_alerts = alerts
        return spikes, alerts

    @staticmethod
    def _entity_keys(
        extraction: ExtractionResult,
    ) -> list[tuple[str, EntityType, str]]:
        """Return ``(graph node id, type, display name)`` for every hit."""
        keys: list[tuple[str, EntityType, str]] = []
        for indicator in extraction.indicators:
            if indicator.kind == "cve":
                keys.append(
                    (
                        f"vulnerability:{indicator.value.lower()}",
                        EntityType.VULNERABILITY,
                        indicator.value,
                    )
                )
        for entity in extraction.entities:
            canonical = canonical_entity(entity.name, entity.type)
            if canonical is None:
                continue
            entity_type, name = canonical
            keys.append((f"{entity_type.value}:{name.lower()}", entity_type, name))
        return keys

    # ------------------------------------------------------------------
    # Full run
    # ------------------------------------------------------------------
    def run(self, offline: bool | None = None) -> PipelineResult:
        result = PipelineResult()
        self.last_errors = []

        records = self._phase(result, "ingest", self.ingest, offline) or []
        result.raw_stored = self.store.count_raw()
        result.normalized_stored = self.store.count_normalized()

        extractions = self._phase(result, "extract", self.extract, records) or []
        result.extractions = len(extractions)

        records_by_id = {record.id: record for record in records}
        severities: dict[str, float] = {}
        for extraction in extractions:
            record = records_by_id.get(extraction.record_id)
            cvss = _as_float((record.metadata if record else {}).get("cvss"))
            if cvss is None:
                continue
            for indicator in extraction.indicators:
                if indicator.kind == "cve":
                    severities[indicator.value] = cvss

        self._phase(result, "build_graph", self.build_graph, records, extractions, severities)
        result.nodes = self.graph.graph.number_of_nodes()
        result.edges = self.graph.graph.number_of_edges()

        events = self._phase(result, "correlate", self.correlate, records, extractions) or []
        result.correlated_events = len(events)

        analysis = self._phase(result, "analyze", self.analyze, records, extractions)
        if analysis is not None:
            spikes, alerts = analysis
            result.spikes = len(spikes)
            result.alerts = len(alerts)

        result.errors.extend(self.last_errors)
        result.finished_at = utcnow()
        logger.info("pipeline complete: %s", result.summary())
        return result

    def _phase(
        self,
        result: PipelineResult,
        name: str,
        step: Callable[..., T],
        *args: Any,
    ) -> T | None:
        """Run one pipeline phase in isolation so a failure cannot kill the run."""
        try:
            return step(*args)
        except Exception as exc:
            logger.exception("pipeline phase %r failed: %s", name, exc)
            result.errors.append(f"{name}: {exc}")
            return None

    # ------------------------------------------------------------------
    # Artifact export (consumed by the dashboard without a live run)
    # ------------------------------------------------------------------
    def export_artifacts(self, directory: str | Path | None = None) -> dict[str, str]:
        target = Path(directory) if directory is not None else self.settings.snapshot_dir
        target.mkdir(parents=True, exist_ok=True)
        paths: dict[str, str] = {}

        if isinstance(self.store, InMemoryStore):
            snapshot = self.store.save_snapshot(target / "snapshot.json")
            paths["snapshot"] = str(snapshot)

        paths["graph"] = str(self.graph.export_json(target / "graph.json"))
        paths["alerts"] = str(
            _write_json(
                target / "alerts.json",
                [alert.model_dump(mode="json") for alert in self.last_alerts],
            )
        )
        paths["spikes"] = str(
            _write_json(
                target / "spikes.json",
                [spike.model_dump(mode="json") for spike in self.last_spikes],
            )
        )
        logger.info("artifacts exported to %s", target)
        return paths


def _write_json(path: Path, payload: Any) -> Path:
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return path


def _as_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def load_fixtures(fixture_dir: str | Path) -> list[NormalizedRecord]:
    """Load normalized records from JSON fixture files (offline/demo mode)."""
    directory = Path(fixture_dir)
    if not directory.is_dir():
        logger.warning("fixture directory not found: %s", directory)
        return []

    records: list[NormalizedRecord] = []
    for path in sorted(directory.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            logger.warning("fixture %s unreadable: %s", path, exc)
            continue

        items = data if isinstance(data, list) else data.get("records", [])
        if not isinstance(items, list):
            logger.warning("fixture %s has no record list", path)
            continue

        for index, item in enumerate(items):
            try:
                source = SourceKind(str(item.get("source", "rss")))
                payload = dict(item, source=source)
                payload.setdefault(
                    "id",
                    stable_id(
                        source.value,
                        item.get("source_record_id") or f"{path.name}:{index}",
                    ),
                )
                records.append(NormalizedRecord.model_validate(payload))
            except (ValueError, TypeError) as exc:
                logger.warning("fixture record %d invalid in %s: %s", index, path, exc)
    return records
