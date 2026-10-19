"""Entity normalization and the NetworkX-backed cybersecurity knowledge graph."""

from __future__ import annotations

import json
import logging
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import networkx as nx

from ..config import Neo4jConfig
from ..models import (
    EntityType,
    ExtractionResult,
    NormalizedRecord,
    node_id,
)
from ..utils import utcnow

logger = logging.getLogger(__name__)

ALIAS_MAP: dict[str, tuple[EntityType, str]] = {
    # Threat actors
    "fancy bear": (EntityType.THREAT_ACTOR, "APT28"),
    "sofia": (EntityType.THREAT_ACTOR, "APT28"),
    "apt28": (EntityType.THREAT_ACTOR, "APT28"),
    "cozy bear": (EntityType.THREAT_ACTOR, "APT29"),
    "the dukes": (EntityType.THREAT_ACTOR, "APT29"),
    "apt29": (EntityType.THREAT_ACTOR, "APT29"),
    "lazarus": (EntityType.THREAT_ACTOR, "Lazarus Group"),
    "lazarus group": (EntityType.THREAT_ACTOR, "Lazarus Group"),
    "hidden cobra": (EntityType.THREAT_ACTOR, "Lazarus Group"),
    "sandworm": (EntityType.THREAT_ACTOR, "Sandworm"),
    "sandworm team": (EntityType.THREAT_ACTOR, "Sandworm"),
    "scattered spider": (EntityType.THREAT_ACTOR, "Scattered Spider"),
    "bitwise spider": (EntityType.THREAT_ACTOR, "Scattered Spider"),
    "unc3944": (EntityType.THREAT_ACTOR, "Scattered Spider"),
    "0ktapus": (EntityType.THREAT_ACTOR, "Scattered Spider"),
    "fin7": (EntityType.THREAT_ACTOR, "FIN7"),
    "carbanak": (EntityType.THREAT_ACTOR, "FIN7"),
    "fin11": (EntityType.THREAT_ACTOR, "FIN11"),
    "ta505": (EntityType.THREAT_ACTOR, "TA505"),
    "volt typhoon": (EntityType.THREAT_ACTOR, "Volt Typhoon"),
    "volttyphoon": (EntityType.THREAT_ACTOR, "Volt Typhoon"),
    "salt typhoon": (EntityType.THREAT_ACTOR, "Salt Typhoon"),
    "mustang panda": (EntityType.THREAT_ACTOR, "Mustang Panda"),
    "winter vivern": (EntityType.THREAT_ACTOR, "Winter Vivern"),
    "charm power": (EntityType.THREAT_ACTOR, "Charm Power"),
    "darkside": (EntityType.THREAT_ACTOR, "DarkSide"),
    "cl0p team": (EntityType.THREAT_ACTOR, "Cl0p"),
    "cl0p": (EntityType.THREAT_ACTOR, "Cl0p"),
    "clop": (EntityType.THREAT_ACTOR, "Cl0p"),
    # Malware
    "cobaltstrike": (EntityType.MALWARE, "Cobalt Strike"),
    "cobalt strike": (EntityType.MALWARE, "Cobalt Strike"),
    "sodinokibi": (EntityType.MALWARE, "REvil"),
    "revil": (EntityType.MALWARE, "REvil"),
    "sodin": (EntityType.MALWARE, "REvil"),
    "zettilim": (EntityType.MALWARE, "LockBit"),
    "lockbit 3.0": (EntityType.MALWARE, "LockBit"),
    "lockbit": (EntityType.MALWARE, "LockBit"),
    "blackcat": (EntityType.MALWARE, "BlackCat"),
    "alphv": (EntityType.MALWARE, "BlackCat"),
    "qakbot": (EntityType.MALWARE, "Qakbot"),
    "qbot": (EntityType.MALWARE, "Qakbot"),
    "pinecrow": (EntityType.MALWARE, "Qakbot"),
    "icedid": (EntityType.MALWARE, "IcedID"),
    "bugat": (EntityType.MALWARE, "Dridex"),
    "dridex": (EntityType.MALWARE, "Dridex"),
    "emotet": (EntityType.MALWARE, "Emotet"),
    "heodo": (EntityType.MALWARE, "Emotet"),
    "trickbot": (EntityType.MALWARE, "TrickBot"),
    "wannacry": (EntityType.MALWARE, "WannaCry"),
    "wanacry": (EntityType.MALWARE, "WannaCry"),
    "notpetya": (EntityType.MALWARE, "NotPetya"),
    "petya": (EntityType.MALWARE, "Petya"),
    "mirai": (EntityType.MALWARE, "Mirai"),
    "akira": (EntityType.MALWARE, "Akira"),
    "cl0p malware": (EntityType.MALWARE, "Cl0p"),
    "clop malware": (EntityType.MALWARE, "Cl0p"),
    # Technologies
    "pan-os": (EntityType.TECHNOLOGY, "PAN-OS"),
    "panos": (EntityType.TECHNOLOGY, "PAN-OS"),
    "pan os": (EntityType.TECHNOLOGY, "PAN-OS"),
    "globalprotect": (EntityType.TECHNOLOGY, "GlobalProtect"),
    "fortios": (EntityType.TECHNOLOGY, "FortiOS"),
    "fortigate": (EntityType.TECHNOLOGY, "FortiOS"),
    "connect secure": (EntityType.TECHNOLOGY, "Ivanti Connect Secure"),
    "pulse secure": (EntityType.TECHNOLOGY, "Ivanti Connect Secure"),
    "moveself": (EntityType.TECHNOLOGY, "MOVEit Transfer"),
    "moveit": (EntityType.TECHNOLOGY, "MOVEit Transfer"),
    "goanywhere mft": (EntityType.TECHNOLOGY, "GoAnywhere MFT"),
    "goanywhere": (EntityType.TECHNOLOGY, "GoAnywhere MFT"),
    "vcenter": (EntityType.TECHNOLOGY, "VMware vCenter"),
    "esxi": (EntityType.TECHNOLOGY, "VMware ESXi"),
    "vsphere": (EntityType.TECHNOLOGY, "VMware vSphere"),
    "confluence": (EntityType.TECHNOLOGY, "Atlassian Confluence"),
    "jenkins": (EntityType.TECHNOLOGY, "Jenkins"),
    "netscaler": (EntityType.TECHNOLOGY, "Citrix NetScaler"),
    "citrix netscaler": (EntityType.TECHNOLOGY, "Citrix NetScaler"),
    "citrix netscaler adc": (EntityType.TECHNOLOGY, "Citrix NetScaler"),
    "exchange": (EntityType.TECHNOLOGY, "Microsoft Exchange"),
    "sharepoint": (EntityType.TECHNOLOGY, "Microsoft SharePoint"),
    "log4j": (EntityType.TECHNOLOGY, "Apache Log4j"),
    "spring": (EntityType.TECHNOLOGY, "Spring Framework"),
    "spring4shell": (EntityType.TECHNOLOGY, "Spring Framework"),
    "cisco ios": (EntityType.TECHNOLOGY, "Cisco IOS"),
    "cisco asa": (EntityType.TECHNOLOGY, "Cisco ASA"),
    "iis": (EntityType.TECHNOLOGY, "Microsoft IIS"),
    "gitlab": (EntityType.TECHNOLOGY, "GitLab"),
    "manageengine": (EntityType.TECHNOLOGY, "ManageEngine"),
    "wordpress": (EntityType.TECHNOLOGY, "WordPress"),
    "openssl": (EntityType.TECHNOLOGY, "OpenSSL"),
    "papercut": (EntityType.TECHNOLOGY, "PaperCut"),
    "ws_ftp": (EntityType.TECHNOLOGY, "WS_FTP"),
    # Organizations (acronyms that title-casing would mangle)
    "cisa": (EntityType.ORGANIZATION, "CISA"),
    "fbi": (EntityType.ORGANIZATION, "FBI"),
    "nsa": (EntityType.ORGANIZATION, "NSA"),
}

# Cypher relationship types cannot be parameterized, so validate before
# interpolating them into a query string.
_REL_TYPE_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")


def canonical_entity(
    name: str, hint: EntityType | None = None
) -> tuple[EntityType, str] | None:
    """Resolve aliases and case/spacing variants into a canonical entity identity."""
    key = " ".join(name.split()).lower()
    if not key:
        return None
    if key in ALIAS_MAP:
        return ALIAS_MAP[key]
    if hint is not None:
        return hint, _titlecase(key)
    return None


def _titlecase(name: str) -> str:
    keep = {"mft", "vpn", "iot", "mssp"}
    return " ".join(
        word.upper() if word in keep else word[:1].upper() + word[1:]
        for word in name.split()
    )


class ThreatGraph:
    """In-memory knowledge graph with optional Neo4j export.

    Nodes are keyed ``"<type>:<canonical name>"``; edges carry typed relations
    (``EXPLOITED_BY``, ``USED_BY``, ``AFFECTS``, ``MENTIONED_IN``, ...).
    """

    def __init__(self) -> None:
        self.graph: nx.MultiDiGraph = nx.MultiDiGraph()

    def reset(self) -> None:
        self.graph.clear()

    def ensure_node(
        self,
        name: str,
        etype: EntityType,
        aliases: list[str] | None = None,
    ) -> str:
        nid = node_id(etype, name)
        if self.graph.has_node(nid):
            node = self.graph.nodes[nid]
            node["last_seen"] = utcnow()
            existing = {alias.lower() for alias in node.get("aliases", [])}
            for alias in aliases or []:
                if alias.lower() not in existing:
                    node.setdefault("aliases", []).append(alias)
                    existing.add(alias.lower())
            return nid
        self.graph.add_node(
            nid,
            id=nid,
            name=name,
            type=etype.value,
            aliases=list(aliases or []),
            first_seen=utcnow(),
            last_seen=utcnow(),
        )
        return nid

    def add_edge(
        self,
        src_id: str,
        dst_id: str,
        etype: str,
        weight: float = 1.0,
        source: str | None = None,
        record_id: str | None = None,
    ) -> None:
        if not self.graph.has_node(src_id) or not self.graph.has_node(dst_id):
            return
        key = f"{etype}:{src_id}->{dst_id}"
        if self.graph.has_edge(src_id, dst_id, key=key):
            edge = self.graph[src_id][dst_id][key]
            edge["weight"] = edge.get("weight", 1.0) + weight
            if record_id:
                edge.setdefault("records", []).append(record_id)
            return
        self.graph.add_edge(
            src_id,
            dst_id,
            key=key,
            type=etype,
            weight=weight,
            source=source,
            records=[record_id] if record_id else [],
        )

    def nodes(self, type: EntityType | None = None) -> list[dict[str, Any]]:
        return [
            dict(data)
            for _, data in self.graph.nodes(data=True)
            if type is None or data.get("type") == type.value
        ]

    def edges(self) -> list[dict[str, Any]]:
        return [
            dict(data) | {"src": src, "dst": dst, "key": key}
            for src, dst, key, data in self.graph.edges(data=True, keys=True)
        ]

    def neighbors(self, nid: str) -> list[str]:
        if nid not in self.graph:
            return []
        return list(self.graph.successors(nid)) + list(self.graph.predecessors(nid))

    def degree(self, nid: str) -> int:
        return self.graph.degree(nid) if nid in self.graph else 0

    def stats(self) -> dict[str, int]:
        by_type = Counter(node["type"] for node in self.nodes())
        return {
            "nodes": self.graph.number_of_nodes(),
            "edges": self.graph.number_of_edges(),
            **by_type,
        }

    # -- construction -------------------------------------------------------
    def build_from_extractions(
        self,
        extractions: list[ExtractionResult],
        records: dict[str, NormalizedRecord],
        cve_severities: dict[str, float | None] | None = None,
    ) -> None:
        """Create nodes/edges from extraction results plus co-mention relations."""
        severities = cve_severities or {}

        for extraction in extractions:
            record = records.get(extraction.record_id)
            if record is None:
                continue

            source_node = self.ensure_record_source_node(record)
            cve_nodes: list[str] = []
            for indicator in extraction.indicators:
                if indicator.kind != "cve":
                    continue
                nid = self.ensure_node(
                    indicator.value, EntityType.VULNERABILITY
                )
                cve_nodes.append(nid)
                self.add_edge(
                    source_node,
                    nid,
                    "MENTIONED_IN",
                    source=record.source.value,
                    record_id=record.id,
                )
                severity = severities.get(indicator.value)
                if severity is not None:
                    self.graph.nodes[nid]["cvss"] = severity

            by_type: dict[EntityType, list[str]] = defaultdict(list)
            for entity in extraction.entities:
                canonical = canonical_entity(entity.name, entity.type)
                if canonical is None:
                    continue
                ctype, cname = canonical
                nid = self.ensure_node(cname, ctype, aliases=[entity.name])
                if nid not in by_type[ctype]:
                    by_type[ctype].append(nid)
                self.add_edge(
                    source_node,
                    nid,
                    "MENTIONED_IN",
                    source=record.source.value,
                    record_id=record.id,
                )

            for cve_node in cve_nodes:
                for malware_node in by_type[EntityType.MALWARE]:
                    self.add_edge(
                        cve_node, malware_node, "EXPLOITED_BY",
                        source=record.source.value, record_id=record.id,
                    )
                for tech_node in by_type[EntityType.TECHNOLOGY]:
                    self.add_edge(
                        cve_node, tech_node, "AFFECTS",
                        source=record.source.value, record_id=record.id,
                    )
                for org_node in by_type[EntityType.ORGANIZATION]:
                    self.add_edge(
                        cve_node, org_node, "TARGETS_ORG",
                        source=record.source.value, record_id=record.id,
                    )
                for actor_node in by_type[EntityType.THREAT_ACTOR]:
                    self.add_edge(
                        cve_node, actor_node, "ATTRIBUTED_TO",
                        source=record.source.value, record_id=record.id,
                    )
            for malware_node in by_type[EntityType.MALWARE]:
                for actor_node in by_type[EntityType.THREAT_ACTOR]:
                    self.add_edge(
                        malware_node, actor_node, "USED_BY",
                        source=record.source.value, record_id=record.id,
                    )

    def ensure_record_source_node(self, record: NormalizedRecord) -> str:
        nid = f"source:{record.id}"
        if not self.graph.has_node(nid):
            self.graph.add_node(
                nid,
                id=nid,
                name=record.title[:80],
                type="source",
                record_id=record.id,
                source=record.source.value,
                url=record.url or "",
                published_at=(
                    record.published_at.isoformat() if record.published_at else None
                ),
            )
        return nid

    # -- analysis helpers ----------------------------------------------------
    def entity_degrees(self) -> dict[str, int]:
        """Graph degree of every entity node, keyed by node id."""
        return {
            data["id"]: self.degree(data["id"])
            for _, data in self.graph.nodes(data=True)
            if data.get("type") != "source"
        }

    def subgraph_for(self, entity: str, depth: int = 2) -> nx.Graph:
        if entity not in self.graph:
            return nx.Graph()
        reachable = nx.single_source_shortest_path_length(
            self.graph, entity, cutoff=depth
        )
        return nx.Graph(self.graph.subgraph(reachable).to_undirected())

    # -- export --------------------------------------------------------------
    def export_json(self, path: str | Path) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        data = nx.node_link_data(self.graph)
        target.write_text(
            json.dumps(data, default=str, ensure_ascii=False), encoding="utf-8"
        )
        logger.info("graph exported: %s", target)
        return target

    def export_neo4j(self, config: Neo4jConfig) -> int:
        """Push nodes and typed edges to Neo4j; returns the node count."""
        try:
            from neo4j import GraphDatabase
        except ImportError as exc:
            raise RuntimeError(
                "neo4j driver not installed (pip install darkpulse[neo4j])"
            ) from exc

        driver = GraphDatabase.driver(
            config.uri,
            auth=(config.user, config.password) if config.user else None,
        )
        created = 0
        try:
            with driver.session() as session:
                for _, data in self.graph.nodes(data=True):
                    if data.get("type") == "source":
                        continue
                    session.run(
                        "MERGE (n:Entity {id: $id}) SET n += $props",
                        id=data["id"],
                        props={k: v for k, v in data.items() if k != "id"},
                    )
                    created += 1
                for src, dst, data in self.graph.edges(data=True):
                    rel_type = str(data.get("type", ""))
                    if not _REL_TYPE_RE.fullmatch(rel_type):
                        logger.warning("skipping invalid Neo4j relationship %r", rel_type)
                        continue
                    session.run(
                        f"MATCH (a:Entity {{id: $src}}), (b:Entity {{id: $dst}}) "
                        f"MERGE (a)-[r:{rel_type}]->(b) SET r.weight = $weight",
                        src=src,
                        dst=dst,
                        weight=data.get("weight", 1.0),
                    )
        finally:
            driver.close()
        return created
