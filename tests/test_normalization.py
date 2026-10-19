"""Unit tests for entity normalization and knowledge graph construction."""

from darkpulse.extraction.indicators import Extractor
from darkpulse.graph.kb import ThreatGraph, canonical_entity
from darkpulse.models import EntityType, NormalizedRecord, SourceKind, stable_id


class TestCanonicalization:
    def test_alias_map(self):
        assert canonical_entity("Fancy Bear") == (EntityType.THREAT_ACTOR, "APT28")
        assert canonical_entity("cozy bear") == (EntityType.THREAT_ACTOR, "APT29")
        assert canonical_entity("sodinokibi") == (EntityType.MALWARE, "REvil")
        assert canonical_entity("pan-os") == (EntityType.TECHNOLOGY, "PAN-OS")

    def test_case_insensitive(self):
        assert canonical_entity("LOCKBIT") == (EntityType.MALWARE, "LockBit")

    def test_hint_fallback_titlecases(self):
        assert canonical_entity("acme corp", EntityType.ORGANIZATION) == (
            EntityType.ORGANIZATION,
            "Acme Corp",
        )

    def test_unknown_without_hint_is_none(self):
        assert canonical_entity("zzz-unknown") is None


def _record(title: str, text: str) -> NormalizedRecord:
    return NormalizedRecord(
        id=stable_id("test", title),
        source=SourceKind.RSS,
        source_record_id=title,
        record_type="article",
        title=title,
        text=text,
    )


class TestGraph:
    def test_node_dedup_via_normalization(self):
        g = ThreatGraph()
        r1 = _record("t1", "Fancy Bear used cobalt strike against NATO")
        r2 = _record("t2", "APT28 deployed CobaltStrike in a campaign")
        ext1 = Extractor(use_nlp=False).extract(r1)
        ext2 = Extractor(use_nlp=False).extract(r2)
        g.build_from_extractions([ext1, ext2], {r1.id: r1, r2.id: r2})
        names = {n["name"] for n in g.nodes()}
        assert "APT28" in names
        assert "Cobalt Strike" in names
        assert "Fancy Bear" not in names and "cobaltstrike" not in names

    def test_semantic_edges(self):
        g = ThreatGraph()
        r = _record("t", "CVE-2024-3400 exploits attributed to APT28 used LockBit malware against PAN-OS")
        ext = Extractor(use_nlp=False).extract(r)
        g.build_from_extractions([ext], {r.id: r})
        edge_types = {e["type"] for e in g.edges()}
        assert "EXPLOITED_BY" in edge_types
        assert "USED_BY" in edge_types
        assert "AFFECTS" in edge_types

    def test_provenance_edges_and_stats(self):
        g = ThreatGraph()
        r = _record("t", "CVE-2023-4966 Citrix NetScaler Citrix Bleed")
        ext = Extractor(use_nlp=False).extract(r)
        g.build_from_extractions([ext], {r.id: r})
        stats = g.stats()
        assert stats["nodes"] >= 4  # source node + CVE + tech + org
        assert stats["edges"] >= 3

    def test_mention_counts(self):
        g = ThreatGraph()
        r = _record("t", "CVE-2024-3400 and CVE-2023-4966")
        ext = Extractor(use_nlp=False).extract(r)
        g.build_from_extractions([ext], {r.id: r})
        counts = g.entity_degrees()
        assert counts["vulnerability:cve-2024-3400"] >= 1

    def test_subgraph_for(self):
        import networkx as nx

        g = ThreatGraph()
        r = _record("t", "CVE-2024-3400 attributed to APT28 used LockBit against PAN-OS")
        ext = Extractor(use_nlp=False).extract(r)
        g.build_from_extractions([ext], {r.id: r})
        sub = g.subgraph_for("vulnerability:cve-2024-3400", depth=2)
        assert isinstance(sub, nx.Graph)
        assert sub.number_of_nodes() >= 2
