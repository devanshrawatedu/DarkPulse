"""Multi-factor risk prioritization.

Score = weighted sum of activity growth, relationship density, severity (CVSS),
recency (exponential decay) and monitored-asset relevance. Weights are
normalized by their total, so the score is always in ``[0, 1]`` even when the
operator retunes them.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping, Sequence
from datetime import datetime

from ..config import RiskWeights
from ..models import EntityType, RiskAlert
from ..utils import as_utc, utcnow

logger = logging.getLogger(__name__)

HALF_LIFE_DAYS = 7.0


class RiskEngine:
    def __init__(
        self,
        weights: RiskWeights | None = None,
        monitored_assets: Sequence[str] | None = None,
        half_life_days: float = HALF_LIFE_DAYS,
    ) -> None:
        if half_life_days <= 0:
            raise ValueError("half_life_days must be positive")
        self.weights = weights or RiskWeights()
        self.monitored = [asset.lower() for asset in (monitored_assets or [])]
        self.half_life_days = half_life_days

    def score_entities(
        self,
        mention_counts: Mapping[str, int],
        *,
        entity_meta: Mapping[str, Mapping],
        mention_dates: Mapping[str, Sequence[datetime]],
        graph_degree: Mapping[str, int],
    ) -> list[RiskAlert]:
        """Score all entities and return ``RiskAlert`` models ranked by score."""
        if not mention_counts:
            return []

        max_mentions = max(mention_counts.values())
        max_degree = max(graph_degree.values(), default=0)
        total_weight = sum(self.weights.model_dump().values())
        now = utcnow()
        alerts: list[RiskAlert] = []

        for entity, mentions in mention_counts.items():
            meta = entity_meta.get(entity, {})
            entity_type = self._entity_type(meta.get("type"))
            growth = _norm(mentions, max_mentions)
            density = _norm(graph_degree.get(entity, 0), max_degree)
            severity = _severity(meta.get("cvss"))
            recency = self._recency_score(mention_dates.get(entity, ()), now)
            relevance = _asset_relevance(entity, meta, self.monitored)

            factors = {
                "activity_growth": (growth, self.weights.activity_growth),
                "relationship_density": (density, self.weights.relationship_density),
                "severity": (severity, self.weights.severity),
                "recency": (recency, self.weights.recency),
                "asset_relevance": (relevance, self.weights.asset_relevance),
            }
            components = {
                name: round((value * weight / total_weight) if total_weight else 0.0, 4)
                for name, (value, weight) in factors.items()
            }
            score = min(sum(components.values()), 1.0)

            labels = {str(label).lower() for label in meta.get("labels") or ()}
            reasons: list[str] = []
            if growth > 0.5:
                reasons.append(f"high mention volume ({mentions} observations)")
            if density > 0.5:
                reasons.append(
                    f"dense graph relationships ({graph_degree.get(entity, 0)} links)"
                )
            if severity > 0:
                reasons.append(f"CVSS {meta.get('cvss')}")
            if entity_type is EntityType.VULNERABILITY:
                if "kev" in labels:
                    reasons.append("listed in CISA KEV (known exploited)")
                if meta.get("ransomware_use") == "Known":
                    reasons.append("used in ransomware campaigns")
            if relevance > 0:
                reasons.append("matches monitored assets")

            alerts.append(
                RiskAlert(
                    rank=0,
                    entity=str(meta.get("name", entity)),
                    entity_type=entity_type,
                    score=round(score, 4),
                    components=components,
                    reasons=reasons,
                    related_cves=list(dict.fromkeys(meta.get("related_cves") or [])),
                    first_seen=meta.get("first_seen"),
                    last_seen=meta.get("last_seen"),
                )
            )

        alerts.sort(key=lambda alert: (-alert.score, alert.entity))
        for rank, alert in enumerate(alerts, start=1):
            alert.rank = rank
        logger.info("risk engine: scored %d entities", len(alerts))
        return alerts

    def _recency_score(
        self, dates: Sequence[datetime], now: datetime
    ) -> float:
        if not dates:
            return 0.0
        latest = as_utc(max(dates))
        age_days = max((now - latest).total_seconds() / 86400.0, 0.0)
        return 0.5 ** (age_days / self.half_life_days)

    @staticmethod
    def _entity_type(raw: object) -> EntityType:
        if isinstance(raw, EntityType):
            return raw
        try:
            return EntityType(str(raw))
        except ValueError:
            logger.debug("unknown entity type %r; scoring as indicator", raw)
            return EntityType.INDICATOR


def _norm(value: float, maximum: float) -> float:
    return min(value / maximum, 1.0) if maximum > 0 else 0.0


def _severity(cvss: object) -> float:
    try:
        score = float(cvss)
    except (TypeError, ValueError):
        return 0.0
    return min(max(score, 0.0), 10.0) / 10.0


def _asset_relevance(
    entity: str, meta: Mapping, monitored: Sequence[str]
) -> float:
    if not monitored:
        return 0.0
    haystack = " ".join(
        [entity, str(meta.get("name", "")), *(str(a) for a in meta.get("aliases") or ())]
    ).lower()
    hits = sum(1 for asset in monitored if _contains_token(haystack, asset))
    return min(hits / len(monitored), 1.0)


def _contains_token(haystack: str, token: str) -> bool:
    return re.search(
        rf"(?<![a-z0-9]){re.escape(token)}(?![a-z0-9])", haystack
    ) is not None
