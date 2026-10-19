"""DarkPulse Streamlit dashboard.

Run with:  streamlit run darkpulse/dashboard/app.py
Demo mode: DARKPULSE_OFFLINE=1 streamlit run darkpulse/dashboard/app.py
"""

from __future__ import annotations

import tempfile
from collections import Counter
from collections.abc import Sequence
from pathlib import Path

import networkx as nx
import pandas as pd
import streamlit as st

from darkpulse.config import get_settings
from darkpulse.models import EntityType, NormalizedRecord, RiskAlert
from darkpulse.utils import as_utc

st.set_page_config(
    page_title="DarkPulse Threat Intelligence",
    page_icon="🛰️",
    layout="wide",
)


@st.cache_resource(show_spinner="Starting DarkPulse pipeline...")
def get_pipeline(offline: bool):
    from darkpulse.pipeline import Pipeline

    settings = get_settings()
    settings.offline = offline or settings.offline
    return Pipeline(settings)


@st.cache_data(ttl=600, show_spinner="Running pipeline...")
def run_pipeline(offline: bool, _pipeline) -> dict:
    pipeline = _pipeline
    result = pipeline.run(offline=offline)
    return {
        "result": result,
        "records": pipeline.last_records,
        "events": pipeline.last_events,
        "spikes": pipeline.last_spikes,
        "alerts": pipeline.last_alerts,
        "graph": pipeline.graph,
    }


def daily_series(records: Sequence[NormalizedRecord]) -> pd.DataFrame:
    """Daily record counts pivoted by source for the trends chart."""
    counts: Counter[tuple[str, str]] = Counter()
    for record in records:
        day = as_utc(record.timestamp).strftime("%Y-%m-%d")
        counts[(day, record.source.value)] += 1
    if not counts:
        return pd.DataFrame()
    frame = pd.DataFrame(
        [
            {"date": day, "source": source, "count": count}
            for (day, source), count in counts.items()
        ]
    )
    pivot = frame.pivot_table(
        index="date", columns="source", values="count", fill_value=0
    )
    return pivot.sort_index()


def _pyvis_html(graph: nx.Graph) -> str | None:
    """Render a graph with pyvis without leaving a file behind."""
    try:
        from pyvis.network import Network
    except ImportError:
        return None

    colors = {
        "vulnerability": "#ff5252",
        "malware": "#ffb74d",
        "threat_actor": "#ba68c8",
        "organization": "#4fc3f7",
        "technology": "#81c784",
        "source": "#607d8b",
    }
    network = Network(
        height="520px",
        width="100%",
        bgcolor="#111",
        font_color="white",
        cdn_resources="in_line",
    )
    network.barnes_hut()
    for node, data in graph.nodes(data=True):
        label = data.get("name", node)
        network.add_node(
            node,
            label=label,
            color=colors.get(data.get("type"), "#90a4ae"),
            title=f"{label} ({data.get('type')})",
        )
    for src, dst, data in graph.edges(data=True):
        network.add_edge(src, dst, title=data.get("type", ""))
    network.repulsion(node_distance=120, spring_length=120)
    with tempfile.TemporaryDirectory() as directory:
        return network.generate_html(name=str(Path(directory) / "graph.html"))


settings = get_settings()
offline_default = settings.offline

with st.sidebar:
    st.title("🛰️ DarkPulse")
    st.caption("Threat intelligence & leak analytics")

    offline_mode = st.toggle(
        "Offline demo mode",
        value=offline_default,
        help="Use bundled fixtures instead of live sources (NVD, CISA KEV, RSS).",
    )
    top_n = st.slider("Alerts to show", 5, 50, 15)
    entity_filter = st.multiselect(
        "Entity types",
        options=[entity.value for entity in EntityType],
        default=[entity.value for entity in EntityType],
    )

    if st.button("🔄 Re-run pipeline", width="stretch"):
        st.cache_data.clear()
        st.cache_resource.clear()
        st.rerun()

bundle = run_pipeline(offline_mode, get_pipeline(offline_mode))
result = bundle["result"]
alerts: list[RiskAlert] = bundle["alerts"]
spikes = bundle["spikes"]
graph: nx.MultiDiGraph = bundle["graph"].graph
records: list[NormalizedRecord] = bundle["records"]
events = bundle["events"]

col1, col2, col3, col4, col5, col6 = st.columns(6)
col1.metric("Raw records", result.raw_stored)
col2.metric("Normalized", result.normalized_stored)
col3.metric("Graph nodes", result.nodes)
col4.metric("Graph edges", result.edges)
col5.metric("Events", result.correlated_events)
col6.metric("Spikes", result.spikes)

if result.errors:
    st.warning("Phase errors (pipeline continued): " + "; ".join(result.errors))

tab_alerts, tab_graph, tab_trends, tab_inspector = st.tabs(
    [
        "🚨 Prioritized Alerts",
        "🕸️ Relationship Graph",
        "📈 Threat Trends",
        "🔎 Source Inspector",
    ]
)

with tab_alerts:
    st.subheader("Prioritized emerging threats")
    st.caption(
        "Multi-factor score: activity growth, relationship density, severity (CVSS), "
        "recency, asset relevance."
    )
    if not alerts:
        st.info("No alerts — run the pipeline with data.")
    else:
        frame = pd.DataFrame(
            [
                {
                    "rank": alert.rank,
                    "entity": alert.entity,
                    "type": alert.entity_type.value,
                    "score": alert.score,
                    "top reason": alert.reasons[0] if alert.reasons else "",
                }
                for alert in alerts
            ]
        )
        frame = frame[frame["type"].isin(entity_filter)]
        st.dataframe(frame.head(top_n), hide_index=True, height=420)

        selected = st.selectbox(
            "Inspect alert",
            options=alerts[:top_n],
            format_func=lambda alert: f"#{alert.rank} {alert.entity} ({alert.score:.3f})",
        )
        if selected:
            left, right = st.columns(2)
            with left:
                st.markdown("**Score components**")
                st.bar_chart(pd.Series(selected.components, name="weighted contribution"))
            with right:
                st.markdown("**Reasons**")
                for reason in selected.reasons or ["—"]:
                    st.markdown(f"- {reason}")
                if selected.related_cves:
                    st.markdown("**Related CVEs**")
                    st.write(", ".join(selected.related_cves[:12]))

            st.markdown("**Supporting records**")
            evidence: list[NormalizedRecord] = []
            needle = selected.entity.lower()
            for event in events:
                haystack = f"{' '.join(event.cves)} {' '.join(event.entities)}".lower()
                if needle not in haystack:
                    continue
                for record_id in event.member_record_ids[:5]:
                    record = next(
                        (item for item in records if item.id == record_id), None
                    )
                    if record is not None:
                        evidence.append(record)
            for record in evidence[:8]:
                with st.expander(f"[{record.source.value}] {record.title[:100]}"):
                    st.markdown(record.text[:600])
                    if record.url:
                        st.markdown(f"[source]({record.url})")

with tab_graph:
    st.subheader("Threat knowledge graph")
    st.caption("NetworkX graph of entities and provenance; rendered with pyvis.")

    node_types = {data.get("type") for _, data in graph.nodes(data=True)}
    show_types = st.multiselect(
        "Node types on canvas",
        options=sorted(node_types),
        default=sorted(node_types - {"source"}),
    )
    depth = st.slider("Expand depth from selected node", 1, 3, 2)

    node_options = sorted(
        {
            data.get("name")
            for _, data in graph.nodes(data=True)
            if data.get("type") != "source"
        }
    )
    focus = st.selectbox(
        "Focus entity (optional)", options=["(top alerts)"] + node_options
    )

    node_id = None
    if focus != "(top alerts)":
        node_id = next(
            (
                name
                for name, data in graph.nodes(data=True)
                if data.get("name") == focus
            ),
            None,
        )
    elif alerts:
        top = alerts[0]
        node_id = f"{top.entity_type.value}:{top.entity.lower()}"

    if graph.number_of_nodes() == 0:
        st.info("Graph is empty.")
    else:
        if node_id and node_id in graph:
            subgraph = bundle["graph"].subgraph_for(node_id, depth=depth)
        else:
            kept = [
                node
                for node, data in graph.nodes(data=True)
                if data.get("type") in set(show_types)
            ]
            subgraph = graph.subgraph([node for node in kept if node in graph])

        html = _pyvis_html(subgraph)
        if html is None:
            st.warning("pyvis not installed — showing edge list instead.")
            st.dataframe(pd.DataFrame(subgraph.edges(), columns=["src", "dst"]))
        else:
            st.html(html, unsafe_allow_javascript=True)

with tab_trends:
    st.subheader("Temporal trends & spikes")

    series = daily_series(records)
    if series.empty:
        st.info("No timestamped records to plot.")
    else:
        st.line_chart(series)

    st.markdown("### Detected spikes (z-score)")
    if not spikes:
        st.info("No spikes detected yet — spikes need a baseline of ≥ 3 days.")
    else:
        spike_frame = pd.DataFrame(
            [
                {
                    "entity": spike.entity,
                    "window": spike.window,
                    "observed": spike.observed,
                    "baseline": spike.baseline_mean,
                    "z-score": spike.z_score,
                }
                for spike in spikes
            ]
        )
        st.dataframe(spike_frame, hide_index=True)
        st.bar_chart(spike_frame.set_index("entity")["z-score"])

with tab_inspector:
    st.subheader("Source inspector")
    st.caption("Raw supporting evidence and provenance for individual observations.")

    source_counts = Counter(record.source.value for record in records)
    left, middle, right = st.columns(3)
    source_filter = left.selectbox("Source", ["all"] + sorted(source_counts))
    query = middle.text_input("Search text", "")
    cve_query = right.text_input("CVE filter (e.g. CVE-2024-3400)", "")

    rows = records
    if source_filter != "all":
        rows = [record for record in rows if record.source.value == source_filter]
    if query:
        rows = [
            record
            for record in rows
            if query.lower() in f"{record.title} {record.text}".lower()
        ]
    if cve_query:
        rows = [
            record
            for record in rows
            if cve_query.upper() in f"{record.title} {record.text}".upper()
        ]

    st.write(f"{len(rows)} records")
    for record in rows[:40]:
        with st.expander(f"[{record.source.value}] {record.title[:110]}"):
            st.markdown(
                f"**record id:** `{record.id}`  |  raw: `{record.raw_id or '-'}`"
            )
            if record.published_at:
                st.caption(f"published: {record.published_at.isoformat()}")
            st.markdown(record.text[:900] or "_no text_")
            if record.metadata:
                st.json(record.metadata, expanded=False)
            if record.url:
                st.markdown(f"[open source]({record.url})")
