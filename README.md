# 🛰️ DarkPulse

**Automated threat intelligence & leak analytics platform.**
DarkPulse correlates cybersecurity entities — vulnerabilities, malware, threat
actors, organizations, technologies and incidents — across heterogeneous public
sources, analyzes temporal behavior, prioritizes risks, and visualizes them
through an interactive Streamlit dashboard.


## Quick start

```bash
# 1. install
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m spacy download en_core_web_sm             # optional, improves NER

# 2. offline demo (no network needed) — fixtures included
darkpulse demo

# 3. live run: fetch NVD + CISA KEV + RSS feeds, then export artifacts
darkpulse pipeline

# 4. launch the dashboard
darkpulse dashboard          # or: streamlit run darkpulse/dashboard/app.py
```

The `demo` command runs the whole pipeline over bundled fixture data
(`darkpulse/fixtures/sample_records.json`) and prints the top prioritized threats.

## Dashboard views

| View | What it shows |
|---|---|
| 🚨 **Prioritized Alerts** | Ranked emerging threats with per-factor score breakdown, reasons and supporting records |
| 🕸️ **Relationship Graph** | Interactive pyvis network of entities; focus on any alert and expand N hops |
| 📈 **Threat Trends** | Daily activity per source + detected mention spikes (z-score) |
| 🔎 **Source Inspector** | Search/filter raw supporting evidence and provenance for each observation |

Toggle **Offline demo mode** in the sidebar to explore without hitting live APIs.

## Configuration (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `DARKPULSE_OFFLINE` | `0` | Never touch the network; use fixtures |
| `NVD_API_KEY` | – | Raises NVD rate limits (recommended) |
| `DARKPULSE_MONGO` | `0` | Use MongoDB for dual storage (`pymongo` required) |
| `DARKPULSE_NEO4J` | `0` | Export the graph to Neo4j (`neo4j` driver required) |
| `DARKPULSE_MONITORED_ASSETS` | – | Comma-separated asset names boosted in risk scoring |
| `DARKPULSE_SNAPSHOT_DIR` | `data/snapshots` | Where artifacts/snapshots are written (resolved from the project root) |
| `DARKPULSE_FIXTURE_DIR` | `darkpulse/fixtures` | Offline/demo fixture directory |
| `DARKPULSE_LOG_LEVEL` | `INFO` | Logging verbosity |

## Storage

Dual-storage separation is enforced by the store interface
(`darkpulse/storage/`):

* `raw_records` — original payloads exactly as received (immutable provenance).
* `normalized_records` — standardized schema: source, ids, title, text,
  timestamps, labels, metadata.

Backends: **MongoDB** (`pymongo`) or a zero-dependency **in-memory** store
with JSON snapshot persistence (`data/snapshots/snapshot.json`).

## Knowledge graph

Nodes are canonically named entities (`vulnerability:cve-2024-3400`,
`malware:lockbit`, `threat_actor:apt28`, ...); alias resolution happens in
`graph/kb.py::ALIAS_MAP` (e.g. *Fancy Bear → APT28*, *Sodinokibi → REvil*,
*FortiGate → FortiOS*). Edge types include:

* `(Vulnerability)-[:EXPLOITED_BY]->(Malware)`
* `(Malware)-[:USED_BY]->(ThreatActor)`
* `(Vulnerability)-[:AFFECTS]->(Technology)`
* `(Vulnerability)-[:TARGETS_ORG]->(Organization)`
* `(Record)-[:MENTIONED_IN]->(Entity)` — provenance to source documents

Export options: JSON (`node-link` format) or Neo4j (optional driver).

## Risk prioritization

Score is a weighted sum of five normalized factors (tunable via
`RiskWeights`). Weights are normalized by their total, so the final score stays
in `[0, 1]` even when retuned:

1. **Activity growth** — mention volume across sources
2. **Relationship density** — graph degree of the entity
3. **Severity** — CVSS base score when known
4. **Recency** — exponential decay (7-day half-life) of latest observation
5. **Asset relevance** — overlap with your monitored asset list

KEV listing and known ransomware-campaign use add human-readable reasons.

## Resilience

* All HTTP fetches — including RSS feeds — go through a tenacity retry policy
  (exponential backoff on timeouts, 429/5xx) and a per-source rate limiter
  (NVD paced at ~6 req/min). Retry count and backoff are configurable per
  source (`SourceConfig.max_retries` / `backoff_base`).
* Every pipeline phase is individually guarded: a failing connector or layer
  logs an error and the run continues.
* `offline` mode guarantees deterministic, network-free behavior for tests.

## Tests

```bash
pytest -v tests/
```

Covers indicator regexes (CVE/IP/domain/hash, defanged IOCs, malformed CVE ids),
entity normalization, graph construction, temporal spike detection, correlation
clustering, dual storage, risk scoring invariants, an end-to-end offline
pipeline run, and failure paths (empty feeds, unparseable timestamps, phase
isolation).

## Project layout

```
darkpulse/
├── config.py           # Pydantic settings
├── models.py           # shared data models
├── pipeline.py         # orchestrator + artifact export
├── cli.py              # `darkpulse` CLI
├── utils.py            # logging, time, similarity
├── ingestion/          # NVD, KEV, RSS connectors + retry/rate-limit
├── extraction/         # indicator regexes + heuristic/NER entities
├── graph/              # normalization + NetworkX knowledge graph
├── correlation/        # cross-source linking + event clustering
├── analysis/           # temporal spikes + risk engine
├── storage/            # in-memory + MongoDB dual-collection stores
├── dashboard/          # Streamlit app
└── fixtures/           # bundled offline/demo records
tests/                  # unit, integration and edge-case tests
```
