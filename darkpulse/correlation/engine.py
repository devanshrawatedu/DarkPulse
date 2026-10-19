"""Cross-source event clustering: records telling the same story become one event."""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence

from ..extraction.indicators import extract_indicators
from ..models import CorrelatedEvent, NormalizedRecord, stable_id
from ..utils import similarity

logger = logging.getLogger(__name__)


def cluster_events(
    records: Sequence[NormalizedRecord],
    *,
    similarity_threshold: float = 0.60,
    entity_names: Mapping[str, Sequence[str]] | None = None,
) -> list[CorrelatedEvent]:
    """Greedy single-pass clustering of records into events.

    Records join an existing event when they share a CVE id (the strongest
    cross-source signal) or when their text is similar enough. ``entity_names``
    optionally provides pre-computed entity names per record id so that events
    can be used for supporting-evidence lookup downstream.
    """
    events: list[CorrelatedEvent] = []
    names_by_record = entity_names or {}

    for record in records:
        text = f"{record.title} {record.text}"
        cves = {
            indicator.value
            for indicator in extract_indicators(text)
            if indicator.kind == "cve"
        }

        target = next(
            (event for event in events if cves.intersection(event.cves)), None
        )
        if target is None:
            best_event: CorrelatedEvent | None = None
            best_score = 0.0
            for event in events:
                score = similarity(text, event.title)
                if score > best_score:
                    best_event, best_score = event, score
            if best_event is not None and best_score >= similarity_threshold:
                target = best_event

        if target is None:
            target = CorrelatedEvent(
                id=stable_id("event", record.id),
                title=record.title[:120],
            )
            events.append(target)

        target.member_record_ids.append(record.id)
        if record.source.value not in target.sources:
            target.sources.append(record.source.value)
        for cve in sorted(cves):
            if cve not in target.cves:
                target.cves.append(cve)
        for name in names_by_record.get(record.id, ()):
            if name not in target.entities:
                target.entities.append(name)

        timestamp = record.timestamp
        if target.first_seen is None or timestamp < target.first_seen:
            target.first_seen = timestamp
        if target.last_seen is None or timestamp > target.last_seen:
            target.last_seen = timestamp

    logger.info("clustered %d records into %d events", len(records), len(events))
    return events
