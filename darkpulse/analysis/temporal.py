"""Temporal analysis: daily mention series and z-score spike detection."""

from __future__ import annotations

import logging
import math
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta

from ..extraction.indicators import extract_indicators
from ..models import EntityType, NormalizedRecord, Spike
from ..utils import as_utc

logger = logging.getLogger(__name__)


class TemporalAnalyzer:
    """Buckets entity mentions per UTC day and flags statistically unusual days."""

    def __init__(
        self,
        z_threshold: float = 2.0,
        min_baseline: int = 3,
        baseline_windows: int = 14,
    ) -> None:
        self.z_threshold = z_threshold
        self.min_baseline = min_baseline
        self.baseline_windows = baseline_windows

    def detect_spikes(
        self,
        records: Sequence[NormalizedRecord],
        extractions: Mapping[str, Sequence[str]] | None = None,
    ) -> list[Spike]:
        """Return the strongest spike per entity across the whole series.

        Each day is compared with the trailing ``baseline_windows`` days, so
        spikes late in a long series are detected (the previous implementation
        only ever inspected the first window).
        """
        entity_keys = (
            dict(extractions)
            if extractions is not None
            else self._default_cve_keys(records)
        )

        # Every observed day belongs on the axis, including quiet days with no
        # mentions: they are the zero baseline later bursts are measured against.
        buckets: dict[str, Counter[str]] = defaultdict(Counter)
        observed_days: set[str] = set()
        for record in records:
            day = _day(record.timestamp)
            if day is None:
                continue
            observed_days.add(day)
            for key in entity_keys.get(record.id, ()):
                buckets[day][key] += 1

        if not observed_days:
            return []

        days = _day_range(min(observed_days), max(observed_days))
        entities = {entity for counts in buckets.values() for entity in counts}

        spikes: list[Spike] = []
        for entity in entities:
            counts = [buckets[day][entity] for day in days]
            spike = self._strongest_spike(entity, counts, days)
            if spike is not None:
                spikes.append(spike)

        spikes.sort(key=lambda item: (-item.z_score, item.entity))
        logger.info(
            "temporal analysis: %d spikes across %d entities over %d days",
            len(spikes),
            len(entities),
            len(days),
        )
        return spikes

    def _strongest_spike(
        self, entity: str, counts: Sequence[int], days: Sequence[str]
    ) -> Spike | None:
        best: tuple[int, float, float] | None = None  # (index, z, baseline_mean)
        for index in range(1, len(counts)):
            baseline = counts[max(0, index - self.baseline_windows) : index]
            if len(baseline) < self.min_baseline:
                continue
            observed = counts[index]
            mean = sum(baseline) / len(baseline)
            if observed <= mean:
                continue
            variance = sum((value - mean) ** 2 for value in baseline) / len(baseline)
            # Floor the std at 1 so a burst out of a flat baseline still scores.
            std = max(math.sqrt(variance), 1.0)
            z_score = (observed - mean) / std
            if z_score < self.z_threshold:
                continue
            if best is None or z_score > best[1]:
                best = (index, z_score, mean)

        if best is None:
            return None
        index, z_score, mean = best
        return Spike(
            entity=entity,
            entity_type=EntityType.VULNERABILITY,
            window=days[index],
            observed=counts[index],
            baseline_mean=round(mean, 2),
            z_score=round(z_score, 2),
        )

    @staticmethod
    def _default_cve_keys(
        records: Sequence[NormalizedRecord],
    ) -> dict[str, list[str]]:
        keys: dict[str, list[str]] = {}
        for record in records:
            text = f"{record.title} {record.text}"
            keys[record.id] = [
                indicator.value
                for indicator in extract_indicators(text)
                if indicator.kind == "cve"
            ]
        return keys


def _day(timestamp: datetime | None) -> str | None:
    if timestamp is None:
        return None
    return as_utc(timestamp).strftime("%Y-%m-%d")


def _day_range(start: str, end: str) -> list[str]:
    """Inclusive list of ISO dates between ``start`` and ``end``."""
    first = datetime.strptime(start, "%Y-%m-%d")
    last = datetime.strptime(end, "%Y-%m-%d")
    if last < first:
        return []
    return [
        (first + timedelta(days=offset)).strftime("%Y-%m-%d")
        for offset in range((last - first).days + 1)
    ]
