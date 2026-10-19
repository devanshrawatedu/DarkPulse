"""Pydantic models shared by every DarkPulse layer."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field

from .utils import utcnow


class EntityType(str, Enum):
    VULNERABILITY = "vulnerability"
    MALWARE = "malware"
    THREAT_ACTOR = "threat_actor"
    ORGANIZATION = "organization"
    TECHNOLOGY = "technology"
    INCIDENT = "incident"
    INDICATOR = "indicator"


class SourceKind(str, Enum):
    NVD = "nvd"
    CISA_KEV = "cisa_kev"
    RSS = "rss"


IndicatorKind = Literal["cve", "ip", "domain", "md5", "sha1", "sha256"]


# ---------------------------------------------------------------------------
# Storage records
# ---------------------------------------------------------------------------


class RawRecord(BaseModel):
    """Original payload exactly as received; never mutated by processing."""

    id: str  # sha1(source, source_record_id)
    source: SourceKind
    source_record_id: str
    fetched_at: datetime = Field(default_factory=utcnow)
    payload: dict[str, Any]


class NormalizedRecord(BaseModel):
    """Standardized schema every connector maps its output into."""

    id: str
    source: SourceKind
    source_record_id: str
    record_type: str  # "vulnerability" | "exploited" | "article" | "advisory"
    title: str
    text: str
    published_at: datetime | None = None
    ingested_at: datetime = Field(default_factory=utcnow)
    url: str | None = None
    labels: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    raw_id: str | None = None  # provenance link to raw_records

    @property
    def timestamp(self) -> datetime:
        """Observation time: publication time when known, else ingestion time."""
        return self.published_at or self.ingested_at


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------


class Indicator(BaseModel):
    kind: IndicatorKind
    value: str
    span: tuple[int, int] | None = None


class ExtractedEntity(BaseModel):
    name: str
    type: EntityType
    confidence: float = Field(0.5, ge=0.0, le=1.0)
    evidence: str | None = None  # supporting snippet
    extractor: str = "regex"  # regex | glossary | spacy


class ExtractionResult(BaseModel):
    record_id: str
    indicators: list[Indicator] = Field(default_factory=list)
    entities: list[ExtractedEntity] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Correlation / analysis
# ---------------------------------------------------------------------------


class CorrelatedEvent(BaseModel):
    """A cluster of normalized records describing the same underlying story."""

    id: str
    member_record_ids: list[str] = Field(default_factory=list)
    entities: list[str] = Field(default_factory=list)
    cves: list[str] = Field(default_factory=list)
    title: str = ""
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    sources: list[str] = Field(default_factory=list)


class Spike(BaseModel):
    entity: str
    entity_type: EntityType
    window: str  # ISO date of the day the spike was observed on
    baseline_mean: float
    observed: int
    z_score: float


class RiskAlert(BaseModel):
    rank: int
    entity: str
    entity_type: EntityType
    score: float = Field(ge=0.0, le=1.0)
    components: dict[str, float]  # weighted contribution of each risk factor
    reasons: list[str] = Field(default_factory=list)
    related_cves: list[str] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None


class PipelineResult(BaseModel):
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: datetime | None = None
    raw_stored: int = 0
    normalized_stored: int = 0
    extractions: int = 0
    nodes: int = 0
    edges: int = 0
    correlated_events: int = 0
    spikes: int = 0
    alerts: int = 0
    errors: list[str] = Field(default_factory=list)

    def summary(self) -> str:
        return (
            f"raw={self.raw_stored} normalized={self.normalized_stored} "
            f"extractions={self.extractions} nodes={self.nodes} edges={self.edges} "
            f"events={self.correlated_events} spikes={self.spikes} alerts={self.alerts} "
            f"errors={len(self.errors)}"
        )


def stable_id(*parts: Any) -> str:
    """Deterministic id from the given parts (raw ids, cluster ids, node keys)."""
    payload = json.dumps(parts, default=str, sort_keys=True).encode("utf-8")
    return hashlib.sha1(payload).hexdigest()


def node_id(entity_type: EntityType, name: str) -> str:
    return f"{entity_type.value}:{name.lower()}"
