"""Unit tests for the risk prioritization engine."""

from datetime import datetime, timedelta, timezone

from darkpulse.analysis.risk import RiskEngine
from darkpulse.config import RiskWeights
from darkpulse.models import EntityType

NOW = datetime.now(timezone.utc)


class TestRiskScoring:
    def _engine(self, **kw) -> RiskEngine:
        return RiskEngine(
            weights=kw.get("weights", RiskWeights()),
            monitored_assets=kw.get("monitored", []),
        )

    def test_higher_cvss_scores_higher(self):
        engine = self._engine()
        meta = {
            "vulnerability:cve-a": {"type": "vulnerability", "name": "CVE-2024-A", "cvss": 9.8},
            "vulnerability:cve-b": {"type": "vulnerability", "name": "CVE-2024-B", "cvss": 4.0},
        }
        alerts = engine.score_entities(
            {"vulnerability:cve-a": 5, "vulnerability:cve-b": 5},
            entity_meta=meta,
            mention_dates={
                "vulnerability:cve-a": [NOW],
                "vulnerability:cve-b": [NOW],
            },
            graph_degree={"vulnerability:cve-a": 2, "vulnerability:cve-b": 2},
        )
        scores = {a.entity: a.score for a in alerts}
        assert scores["CVE-2024-A"] > scores["CVE-2024-B"]

    def test_enum_entity_types_are_preserved(self):
        engine = self._engine()
        alerts = engine.score_entities(
            {"vulnerability:cve-x": 1},
            entity_meta={
                "vulnerability:cve-x": {
                    "type": EntityType.VULNERABILITY,
                    "name": "CVE-X",
                }
            },
            mention_dates={"vulnerability:cve-x": [NOW]},
            graph_degree={"vulnerability:cve-x": 1},
        )
        assert alerts[0].entity_type is EntityType.VULNERABILITY

    def test_recency_decay_prefers_fresh(self):
        engine = self._engine()
        meta = {
            "vulnerability:cve-old": {"type": "vulnerability", "name": "CVE-OLD", "cvss": 9.8},
            "vulnerability:cve-new": {"type": "vulnerability", "name": "CVE-NEW", "cvss": 9.8},
        }
        alerts = engine.score_entities(
            {"vulnerability:cve-old": 3, "vulnerability:cve-new": 3},
            entity_meta=meta,
            mention_dates={
                "vulnerability:cve-old": [NOW - timedelta(days=30)],
                "vulnerability:cve-new": [NOW],
            },
            graph_degree={"vulnerability:cve-old": 1, "vulnerability:cve-new": 1},
        )
        scores = {a.entity: a.score for a in alerts}
        assert scores["CVE-NEW"] > scores["CVE-OLD"]

    def test_relationship_density_contributes(self):
        engine = self._engine()
        meta = {
            "malware:m1": {"type": "malware", "name": "MalwareOne"},
            "malware:m2": {"type": "malware", "name": "MalwareTwo"},
        }
        alerts = engine.score_entities(
            {"malware:m1": 2, "malware:m2": 2},
            entity_meta=meta,
            mention_dates={"malware:m1": [NOW], "malware:m2": [NOW]},
            graph_degree={"malware:m1": 10, "malware:m2": 1},
        )
        scores = {a.entity: a.score for a in alerts}
        assert scores["MalwareOne"] > scores["MalwareTwo"]

    def test_monitored_assets_boost(self):
        engine = self._engine(monitored=["pan-os"])
        meta = {
            "technology:pan-os": {"type": "technology", "name": "PAN-OS", "aliases": ["PAN-OS"]},
            "technology:other": {"type": "technology", "name": "Other"},
        }
        alerts = engine.score_entities(
            {"technology:pan-os": 2, "technology:other": 2},
            entity_meta=meta,
            mention_dates={"technology:pan-os": [NOW], "technology:other": [NOW]},
            graph_degree={"technology:pan-os": 1, "technology:other": 1},
        )
        scores = {a.entity: a.score for a in alerts}
        assert scores["PAN-OS"] > scores["Other"]

    def test_scores_bounded_and_ranked(self):
        engine = self._engine()
        meta = {
            f"vulnerability:cve-{i}": {"type": "vulnerability", "name": f"CVE-{i}", "cvss": 10.0}
            for i in range(5)
        }
        alerts = engine.score_entities(
            {f"vulnerability:cve-{i}": i + 1 for i in range(5)},
            entity_meta=meta,
            mention_dates={f"vulnerability:cve-{i}": [NOW] for i in range(5)},
            graph_degree={f"vulnerability:cve-{i}": i for i in range(5)},
        )
        assert [a.rank for a in alerts] == list(range(1, len(alerts) + 1))
        assert all(0.0 <= a.score <= 1.0 for a in alerts)
        assert alerts == sorted(alerts, key=lambda a: -a.score)

    def test_kev_and_ransomware_reasons(self):
        engine = self._engine()
        meta = {
            "vulnerability:cve-x": {
                "type": "vulnerability",
                "name": "CVE-X",
                "cvss": 10.0,
                "labels": {"kev"},
                "ransomware_use": "Known",
                "related_cves": ["CVE-X"],
            }
        }
        alerts = engine.score_entities(
            {"vulnerability:cve-x": 4},
            entity_meta=meta,
            mention_dates={"vulnerability:cve-x": [NOW]},
            graph_degree={"vulnerability:cve-x": 3},
        )
        reasons = " ".join(alerts[0].reasons).lower()
        assert "kev" in reasons
        assert "ransomware" in reasons
