"""Dashboard data layer.

The old dashboard rebuilt pyvis markup and re-scanned every record on each
Streamlit rerun, which is what made it slow and occasionally blank. Here the
pipeline output is indexed *once* and every endpoint serves a bounded,
serialisable payload:

* entity -> record mappings are built upfront, so evidence lookup is O(1)
  instead of an ``events x records`` nested scan;
* the MultiDiGraph is aggregated into one visual link per node pair;
* graph views return a degree/score ranked subset around an optional focus
  entity, with an explicit ``truncated`` flag instead of dumping the whole
  network on the canvas.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Iterable, Sequence

import networkx as nx

from ..models import (
    CorrelatedEvent,
    EntityType,
    NormalizedRecord,
    PipelineResult,
    RiskAlert,
    Spike,
    node_id,
)
from ..utils import as_utc, utcnow

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

SOURCE_NODE_PREFIX = "source:"
ENTITY_TYPES: tuple[str, ...] = tuple(entity.value for entity in EntityType) + ("source",)
DEFAULT_GRAPH_LIMIT = 320
MAX_GRAPH_LIMIT = 1500


@dataclass(frozen=True)
class GraphRequest:
    """A bounded slice of the knowledge graph."""

    focus: str | None = None
    depth: int = 2
    types: tuple[str, ...] = tuple(e.value for e in EntityType)
    limit: int = DEFAULT_GRAPH_LIMIT
    include_records: bool = False


class DashboardDataset:
    """Immutable, pre-indexed view of one pipeline run."""

    def __init__(
        self,
        *,
        records: Sequence[NormalizedRecord],
        events: Sequence[CorrelatedEvent],
        alerts: Sequence[RiskAlert],
        spikes: Sequence[Spike],
        graph: nx.MultiDiGraph,
        result: PipelineResult | None = None,
        offline: bool = False,
        generated_at: datetime | None = None,
    ) -> None:
        self.records = list(records)
        self.events = list(events)
        self.alerts = list(alerts)
        self.spikes = list(spikes)
        self.graph = graph
        self.result = result
        self.offline = offline
        self.generated_at = utcnow() if generated_at is None else generated_at

        self._records_by_id: dict[str, NormalizedRecord] = {
            record.id: record for record in self.records
        }
        self._build_graph_indexes()
        self._build_alert_indexes()
        self._build_record_payloads()
        self._build_trends()
        self._overview_cache: dict[str, Any] | None = None

    # ------------------------------------------------------------------
    # Index construction (done once per pipeline run)
    # ------------------------------------------------------------------
    def _build_graph_indexes(self) -> None:
        self._adjacency: dict[str, set[str]] = defaultdict(set)
        self._edge_meta: dict[tuple[str, str], dict[str, Any]] = {}
        self._node_records: dict[str, set[str]] = defaultdict(set)
        self._node_payloads: dict[str, dict[str, Any]] = {}
        self._name_index: dict[str, list[str]] = defaultdict(list)

        graph = self.graph
        is_multi = graph.is_multigraph()

        edges_iter = (
            graph.edges(data=True, keys=True) if is_multi else graph.edges(data=True)
        )
        for raw in edges_iter:
            if is_multi:
                source, target, _key, data = raw  # type: ignore[misc]
            else:
                source, target, data = raw  # type: ignore[misc]
            if source == target:
                continue

            self._adjacency[source].add(target)
            self._adjacency[target].add(source)

            pair = (source, target) if source < target else (target, source)
            meta = self._edge_meta.get(pair)
            weight = float(data.get("weight", 1.0) or 1.0)
            rel_type = str(data.get("type") or "RELATED")
            if meta is None:
                self._edge_meta[pair] = {
                    "source": source,
                    "target": target,
                    "type": rel_type,
                    "weight": weight,
                    "max_weight": weight,
                    "count": 1,
                }
            else:
                meta["count"] += 1
                meta["weight"] += weight
                # Keep the arrow/type of the strongest contributing relation.
                if weight > meta["max_weight"]:
                    meta["max_weight"] = weight
                    meta["source"], meta["target"], meta["type"] = (
                        source,
                        target,
                        rel_type,
                    )

            if source.startswith(SOURCE_NODE_PREFIX):
                for record_id in data.get("records") or ():
                    self._node_records[target].add(str(record_id))
            if target.startswith(SOURCE_NODE_PREFIX):
                for record_id in data.get("records") or ():
                    self._node_records[source].add(str(record_id))

        for nid, data in graph.nodes(data=True):
            if nid.startswith(SOURCE_NODE_PREFIX):
                record_id = str(data.get("record_id") or nid[len(SOURCE_NODE_PREFIX) :])
                self._node_payloads[nid] = {
                    "id": nid,
                    "name": data.get("name", "record"),
                    "type": "source",
                    "degree": len(self._adjacency.get(nid, ())),
                    "score": 0.0,
                    "records": 1,
                    "source": data.get("source"),
                    "url": data.get("url") or None,
                    "record_id": record_id,
                }
                continue

            self._node_payloads[nid] = {
                "id": nid,
                "name": data.get("name", nid),
                "type": data.get("type", "indicator"),
                "degree": len(self._adjacency.get(nid, ())),
                "score": 0.0,
                "records": 0,
            }
            self._name_index[str(data.get("name", nid)).lower()].append(nid)

        for nid, payload in self._node_payloads.items():
            if payload["type"] == "source":
                continue
            linked = self._node_records.get(nid, set())
            payload["records"] = len(linked)
            timestamps = [
                as_utc(self._records_by_id[record_id].timestamp)
                for record_id in linked
                if record_id in self._records_by_id
            ]
            if timestamps:
                payload["first_seen"] = min(timestamps).isoformat()
                payload["last_seen"] = max(timestamps).isoformat()
            cvss = self.graph.nodes[nid].get("cvss")
            if cvss is not None:
                payload["cvss"] = cvss

        self._node_dates: dict[str, Counter[str]] = {}
        for nid, linked in self._node_records.items():
            counts: Counter[str] = Counter()
            for record_id in linked:
                record = self._records_by_id.get(record_id)
                if record is None:
                    continue
                counts[as_utc(record.timestamp).strftime("%Y-%m-%d")] += 1
            self._node_dates[nid] = counts

    def _build_alert_indexes(self) -> None:
        self._alert_by_node: dict[str, RiskAlert] = {}
        self._alert_payloads: list[dict[str, Any]] = []
        for alert in self.alerts:
            nid = node_id(alert.entity_type, alert.entity)
            self._alert_by_node[nid] = alert
            payload = self._node_payloads.get(nid)
            if payload is not None:
                payload["score"] = alert.score
            self._alert_payloads.append(self._alert_payload(alert, nid))

        self._node_scores: dict[str, float] = {
            nid: alert.score for nid, alert in self._alert_by_node.items()
        }

    def _alert_payload(self, alert: RiskAlert, nid: str) -> dict[str, Any]:
        return {
            "node_id": nid,
            "rank": alert.rank,
            "entity": alert.entity,
            "type": alert.entity_type.value,
            "score": round(alert.score, 4),
            "components": {k: round(v, 4) for k, v in alert.components.items()},
            "reasons": list(alert.reasons),
            "related_cves": list(alert.related_cves),
            "first_seen": _iso(alert.first_seen),
            "last_seen": _iso(alert.last_seen),
            "degree": self._node_payloads.get(nid, {}).get("degree", 0),
            "cvss": self._node_payloads.get(nid, {}).get("cvss"),
            "mentions": self._node_payloads.get(nid, {}).get("records", 0),
        }

    def _build_record_payloads(self) -> None:
        # Full-text haystack kept out of the JSON payload but used for filtering.
        self._record_search: dict[str, str] = {
            record.id: f"{record.title} {record.text} {' '.join(record.labels)}".lower()
            for record in self.records
        }
        self._record_payloads: list[dict[str, Any]] = []
        for record in self.records:
            self._record_payloads.append(
                {
                    "id": record.id,
                    "source": record.source.value,
                    "record_type": record.record_type,
                    "title": record.title,
                    "snippet": _snippet(record.text, 320),
                    "url": record.url,
                    "labels": list(record.labels),
                    "published_at": _iso(record.published_at),
                    "ingested_at": _iso(record.ingested_at),
                    "timestamp": _iso(record.timestamp),
                    "cves": _record_cves(record),
                }
            )
        self._record_payloads.sort(key=lambda item: item["timestamp"] or "", reverse=True)
        self._record_by_payload_id = {
            payload["id"]: payload for payload in self._record_payloads
        }

    def _build_trends(self) -> None:
        counts: Counter[tuple[str, str]] = Counter()
        totals: Counter[str] = Counter()
        for record in self.records:
            day = as_utc(record.timestamp).strftime("%Y-%m-%d")
            counts[(day, record.source.value)] += 1
            totals[day] += 1

        if not totals:
            self._trend_days: list[str] = []
            self._trend_counts = counts
            self._trend_totals = totals
            return

        first = datetime.strptime(min(totals), "%Y-%m-%d")
        last = datetime.strptime(max(totals), "%Y-%m-%d")
        span = (last - first).days + 1
        self._trend_days = [
            (first + timedelta(days=offset)).strftime("%Y-%m-%d")
            for offset in range(span)
        ]
        self._trend_counts = counts
        self._trend_totals = totals

    # ------------------------------------------------------------------
    # Overview
    # ------------------------------------------------------------------
    def to_overview(self) -> dict[str, Any]:
        if self._overview_cache is not None:
            return self._overview_cache

        entity_nodes = [
            payload
            for payload in self._node_payloads.values()
            if payload["type"] != "source"
        ]
        source_counts = Counter(record.source.value for record in self.records)
        top_alerts = sorted(self._alert_payloads, key=lambda item: item["score"], reverse=True)[:6]
        recent_totals = self._trend_totals
        days = self._trend_days[-14:]
        top_scores = [alert["score"] for alert in top_alerts[:5]]
        total_sources = len(source_counts)

        payload = {
            "generated_at": _iso(self.generated_at),
            "offline": self.offline,
            "records": len(self.records),
            "entities": len(entity_nodes),
            "nodes": self.graph.number_of_nodes(),
            "edges": self.graph.number_of_edges(),
            "events": len(self.events),
            "spikes": len(self.spikes),
            "alerts": len(self.alerts),
            "avg_top_score": round(sum(top_scores) / len(top_scores), 4) if top_scores else 0.0,
            "sources": dict(source_counts.most_common()),
            "source_total": total_sources,
            "top_alerts": top_alerts,
            "activity": {
                "dates": days,
                "values": [recent_totals.get(day, 0) for day in days],
            },
            "type_counts": dict(
                Counter(payload["type"] for payload in entity_nodes).most_common()
            ),
            "errors": list(self.result.errors) if self.result else [],
            "result": (
                {
                    "started_at": _iso(self.result.started_at),
                    "finished_at": _iso(self.result.finished_at),
                    "raw_stored": self.result.raw_stored,
                    "normalized_stored": self.result.normalized_stored,
                    "extractions": self.result.extractions,
                }
                if self.result
                else None
            ),
            "range": _date_range(self.records),
        }
        self._overview_cache = payload
        return payload

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------
    def to_alerts(
        self,
        *,
        types: Iterable[str] | None = None,
        query: str = "",
        limit: int = 100,
    ) -> dict[str, Any]:
        selected = set(types) if types else None
        needle = query.strip().lower()
        items = self._alert_payloads
        if selected:
            items = [item for item in items if item["type"] in selected]
        if needle:
            items = [
                item
                for item in items
                if needle in item["entity"].lower()
                or any(needle in cve.lower() for cve in item["related_cves"])
                or any(needle in reason.lower() for reason in item["reasons"])
            ]
        capped = items[: max(1, min(limit, 500))]
        return {
            "total": len(items),
            "types": dict(Counter(item["type"] for item in self._alert_payloads).most_common()),
            "items": capped,
        }

    def alert_detail(self, key: str) -> dict[str, Any] | None:
        alert = self._alert_by_node.get(key)
        nid = key
        if alert is None:
            try:
                rank = int(key)
            except ValueError:
                rank = -1
            if rank > 0:
                match = next((item for item in self.alerts if item.rank == rank), None)
                if match is not None:
                    alert = match
                    nid = node_id(match.entity_type, match.entity)
        if alert is None:
            return None

        payload = dict(self._alert_payload(alert, nid))
        payload["records"] = self.evidence_for(nid, limit=12)
        payload["series"] = self._series_for_node(nid, days=30)
        payload["node"] = self._node_payloads.get(nid)
        neighbours = sorted(
            (
                self._node_payloads[other]
                for other in self._adjacency.get(nid, ())
                if other in self._node_payloads
            ),
            key=lambda item: item["degree"],
            reverse=True,
        )[:8]
        payload["neighbours"] = neighbours
        return payload

    def evidence_for(self, nid: str, limit: int = 10) -> list[dict[str, Any]]:
        record_ids = self._node_records.get(nid, set())
        records = [
            self._records_by_id[record_id]
            for record_id in record_ids
            if record_id in self._records_by_id
        ]
        records.sort(key=lambda record: as_utc(record.timestamp), reverse=True)
        return [_evidence_payload(record) for record in records[:limit]]

    def _series_for_node(self, nid: str, days: int = 30) -> dict[str, Any]:
        counts = self._node_dates.get(nid, Counter())
        if not counts or not self._trend_days:
            return {"dates": [], "values": []}
        dates = self._trend_days[-days:]
        return {"dates": dates, "values": [counts.get(day, 0) for day in dates]}

    # ------------------------------------------------------------------
    # Graph
    # ------------------------------------------------------------------
    def graph_payload(self, request: GraphRequest) -> dict[str, Any]:
        allowed = {etype for etype in request.types if etype in ENTITY_TYPES}
        if not allowed:
            allowed = {entity.value for entity in EntityType}
        if request.include_records:
            allowed.add("source")
        else:
            allowed.discard("source")

        limit = max(10, min(request.limit, MAX_GRAPH_LIMIT))
        focus = self.resolve_node(request.focus) if request.focus else None
        depth = max(1, min(int(request.depth), 4))

        if focus is not None:
            ranked = self._ego_ranking(focus, depth, allowed)
            focus_payload = self._node_payloads.get(focus)
        else:
            ranked = self._global_ranking(allowed)
            focus_payload = None

        if request.include_records:
            # Reserve part of the cap for provenance nodes attached to the
            # entities actually on screen, otherwise records always rank last.
            entity_ranked = [
                item for item in ranked if not item[0].startswith(SOURCE_NODE_PREFIX)
            ]
            record_slots = max(8, min(limit // 5, 120))
            entity_ids = [nid for nid, _ in entity_ranked[: limit - record_slots]]
            kept_ids = entity_ids + self._attached_records(entity_ids, record_slots)
        else:
            kept_ids = [nid for nid, _ in ranked[:limit]]
        kept = set(kept_ids)
        nodes = [self._node_payloads[nid] for nid in kept_ids]
        links = self._links_within(kept)

        dropped = max(len(ranked) - len(kept_ids), 0)
        missing_focus = bool(request.focus) and focus is None
        return {
            "nodes": nodes,
            "links": links,
            "meta": {
                "focus": focus_payload,
                "requested_focus": request.focus,
                "missing_focus": missing_focus,
                "depth": depth,
                "types": sorted(allowed),
                "include_records": request.include_records,
                "limit": limit,
                "available": len(ranked),
                "shown": len(nodes),
                "truncated": dropped > 0,
                "dropped": dropped,
                "total_nodes": self.graph.number_of_nodes(),
                "total_edges": self.graph.number_of_edges(),
                "entity_nodes": sum(
                    1 for nid in self._node_payloads if not nid.startswith(SOURCE_NODE_PREFIX)
                ),
            },
        }

    def neighbors_payload(self, key: str, limit: int = 70) -> dict[str, Any] | None:
        nid = self.resolve_node(key)
        if nid is None:
            return None
        limit = max(5, min(limit, 400))
        neighbours = sorted(
            (
                other
                for other in self._adjacency.get(nid, ())
                if other in self._node_payloads and not other.startswith(SOURCE_NODE_PREFIX)
            ),
            key=lambda other: (
                self._node_payloads[other]["score"],
                self._node_payloads[other]["degree"],
            ),
            reverse=True,
        )
        kept = [nid] + neighbours[:limit]
        kept_set = set(kept)
        return {
            "nodes": [self._node_payloads[other] for other in kept],
            "links": self._links_within(kept_set),
            "meta": {
                "focus": self._node_payloads[nid],
                "shown": len(kept),
                "available": len(neighbours) + 1,
                "truncated": len(neighbours) > limit,
            },
        }

    def _ego_ranking(
        self, focus: str, depth: int, allowed: set[str]
    ) -> list[tuple[str, tuple[float, ...]]]:
        """BFS around ``focus``, ranked by distance then relevance."""
        seen: dict[str, int] = {focus: 0}
        frontier = [focus]
        for distance in range(1, depth + 1):
            next_frontier: list[str] = []
            for nid in frontier:
                for other in self._adjacency.get(nid, ()):
                    if other in seen or not self._in_allowed(other, allowed):
                        continue
                    seen[other] = distance
                    next_frontier.append(other)
            frontier = next_frontier
            if not frontier:
                break

        ranked: list[tuple[str, tuple[float, ...]]] = []
        for nid, distance in seen.items():
            if nid != focus and not self._in_allowed(nid, allowed):
                continue
            payload = self._node_payloads[nid]
            score = self._node_scores.get(nid, 0.0)
            ranked.append(
                (
                    nid,
                    (
                        float(distance),
                        -score,
                        -payload["degree"],
                        -payload["records"],
                    ),
                )
            )
        ranked.sort(key=lambda item: item[1])
        return ranked

    def _global_ranking(self, allowed: set[str]) -> list[tuple[str, tuple[float, ...]]]:
        ranked: list[tuple[str, tuple[float, ...]]] = []
        for nid, payload in self._node_payloads.items():
            if not self._in_allowed(nid, allowed):
                continue
            score = self._node_scores.get(nid, 0.0)
            ranked.append(
                (
                    nid,
                    (-score, -payload["degree"], -payload["records"], nid),
                )
            )
        ranked.sort(key=lambda item: item[1])
        return ranked

    def _in_allowed(self, nid: str, allowed: set[str]) -> bool:
        payload = self._node_payloads.get(nid)
        if payload is None:
            return False
        return payload["type"] in allowed

    def _attached_records(self, ordered: Sequence[str], slots: int) -> list[str]:
        """Up to ``slots`` record nodes adjacent to the kept entities."""
        if slots <= 0:
            return []
        chosen: list[str] = []
        seen: set[str] = set(ordered)
        for nid in ordered:
            for other in self._adjacency.get(nid, ()):
                if not other.startswith(SOURCE_NODE_PREFIX) or other in seen:
                    continue
                seen.add(other)
                chosen.append(other)
                if len(chosen) >= slots:
                    return chosen
        return chosen

    def _links_within(self, kept: set[str]) -> list[dict[str, Any]]:
        links: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for pair, meta in self._edge_meta.items():
            source, target = pair
            if source not in kept or target not in kept or pair in seen:
                continue
            seen.add(pair)
            links.append(
                {
                    "source": meta["source"],
                    "target": meta["target"],
                    "type": meta["type"],
                    "weight": round(float(meta["weight"]), 3),
                    "count": meta["count"],
                }
            )
        return links

    def resolve_node(self, key: str | None) -> str | None:
        if not key:
            return None
        candidate = key.strip()
        if candidate in self._node_payloads:
            return candidate
        lowered = candidate.lower()
        exact = self._name_index.get(lowered)
        if exact:
            return exact[0]
        matches = [
            nid
            for name, nids in self._name_index.items()
            if lowered in name
            for nid in nids
        ]
        if matches:
            matches.sort(
                key=lambda nid: (
                    self._node_payloads[nid]["score"],
                    self._node_payloads[nid]["degree"],
                ),
                reverse=True,
            )
            return matches[0]
        return None

    def search_nodes(self, query: str, limit: int = 12, types: Iterable[str] | None = None) -> list[dict[str, Any]]:
        needle = query.strip().lower()
        if not needle:
            return []
        allowed = set(types) if types else None
        results: list[dict[str, Any]] = []
        for name, nids in self._name_index.items():
            if needle not in name:
                continue
            for nid in nids:
                payload = self._node_payloads[nid]
                if allowed and payload["type"] not in allowed:
                    continue
                results.append(payload)
        results.sort(
            key=lambda item: (item["score"], item["degree"], item["records"]),
            reverse=True,
        )
        return results[:limit]

    # ------------------------------------------------------------------
    # Trends
    # ------------------------------------------------------------------
    def to_trends(self, days: int = 60) -> dict[str, Any]:
        days = max(7, min(days, 365))
        dates = self._trend_days[-days:]
        sources = sorted({record.source.value for record in self.records})
        series = {
            source: [self._trend_counts.get((day, source), 0) for day in dates]
            for source in sources
        }
        entity_series = []
        for payload in sorted(
            self._alert_payloads, key=lambda item: item["score"], reverse=True
        )[:5]:
            series_payload = self._series_for_node(payload["node_id"], days=days)
            entity_series.append(
                {
                    "entity": payload["entity"],
                    "type": payload["type"],
                    "values": series_payload["values"],
                }
            )
        return {
            "dates": dates,
            "series": series,
            "total": [self._trend_totals.get(day, 0) for day in dates],
            "entities": entity_series,
            "spikes": [
                {
                    "entity": spike.entity,
                    "type": spike.entity_type.value,
                    "window": spike.window,
                    "observed": spike.observed,
                    "baseline": spike.baseline_mean,
                    "z_score": spike.z_score,
                }
                for spike in self.spikes
            ],
            "range": _date_range(self.records),
        }

    # ------------------------------------------------------------------
    # Records
    # ------------------------------------------------------------------
    def to_records(
        self,
        *,
        source: str = "",
        query: str = "",
        cve: str = "",
        offset: int = 0,
        limit: int = 40,
    ) -> dict[str, Any]:
        limit = max(5, min(limit, 200))
        offset = max(0, offset)
        items = self._record_payloads
        if source:
            items = [item for item in items if item["source"] == source]
        needle = query.strip().lower()
        if needle:
            items = [
                item
                for item in items
                if needle in self._record_search.get(item["id"], "")
            ]
        cve_needle = cve.strip().upper()
        if cve_needle:
            items = [
                item
                for item in items
                if any(cve_needle in found for found in item["cves"])
            ]
        return {
            "total": len(items),
            "offset": offset,
            "limit": limit,
            "sources": dict(
                Counter(item["source"] for item in self._record_payloads).most_common()
            ),
            "items": items[offset : offset + limit],
        }

    def record_detail(self, record_id: str) -> dict[str, Any] | None:
        record = self._records_by_id.get(record_id)
        if record is None:
            return None
        return {
            "id": record.id,
            "raw_id": record.raw_id,
            "source": record.source.value,
            "record_type": record.record_type,
            "title": record.title,
            "text": record.text,
            "url": record.url,
            "labels": list(record.labels),
            "metadata": record.metadata,
            "published_at": _iso(record.published_at),
            "ingested_at": _iso(record.ingested_at),
            "source_record_id": record.source_record_id,
        }


# ---------------------------------------------------------------------------
# Construction from a completed pipeline run
# ---------------------------------------------------------------------------


def build_dataset(
    *,
    records: Sequence[NormalizedRecord],
    events: Sequence[CorrelatedEvent],
    alerts: Sequence[RiskAlert],
    spikes: Sequence[Spike],
    graph: nx.MultiDiGraph,
    result: PipelineResult | None = None,
    offline: bool = False,
) -> DashboardDataset:
    """Index one pipeline run for the dashboard."""
    return DashboardDataset(
        records=records,
        events=events,
        alerts=alerts,
        spikes=spikes,
        graph=graph,
        result=result,
        offline=offline,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return as_utc(value).isoformat()


def _snippet(text: str, size: int) -> str:
    collapsed = " ".join(text.split())
    return collapsed[:size] + ("…" if len(collapsed) > size else "")


def _evidence_payload(record: NormalizedRecord) -> dict[str, Any]:
    return {
        "id": record.id,
        "source": record.source.value,
        "title": record.title,
        "text": _snippet(record.text, 900),
        "url": record.url,
        "timestamp": _iso(record.timestamp),
        "labels": list(record.labels),
    }


def _record_cves(record: NormalizedRecord) -> list[str]:
    found = {
        value.upper()
        for value in _CVE_RE.findall(f"{record.title} {record.text}")
    }
    return sorted(found)


def _date_range(records: Sequence[NormalizedRecord]) -> dict[str, Any]:
    if not records:
        return {"min": None, "max": None, "days": 0}
    stamps = [as_utc(record.timestamp) for record in records]
    first, last = min(stamps), max(stamps)
    return {
        "min": first.isoformat(),
        "max": last.isoformat(),
        "days": (last.date() - first.date()).days + 1,
    }
