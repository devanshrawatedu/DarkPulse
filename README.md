# DarkPulse

**An Automated Threat Intelligence and Leak Analytics Platform**

DarkPulse is a cybersecurity intelligence platform that collects publicly available threat information, extracts and normalizes entities, correlates related records, constructs a knowledge graph, analyzes temporal activity, and prioritizes potentially significant threats.

It combines a Python-based analysis pipeline with a **FastAPI backend and an interactive web interface** for exploring prioritized alerts, entity relationships, threat trends, and source evidence.

## Key Features

- **Multi-source ingestion:** Collects vulnerability information from the National Vulnerability Database (NVD), known-exploited vulnerability data from CISA, and cybersecurity RSS/Atom feeds.
- **Entity and indicator extraction:** Identifies CVE identifiers, IP addresses, domains, file hashes, and other cybersecurity entities using pattern matching, normalization rules, and optional NLP-based extraction.
- **Knowledge graph:** Represents vulnerabilities, malware, threat actors, technologies, organizations, and source records as connected entities.
- **Cross-source correlation:** Links related records using shared vulnerability identifiers and heuristic event-clustering techniques.
- **Temporal analysis:** Examines activity over time and flags unusual changes in observed mention volumes.
- **Risk prioritization:** Ranks entities using a configurable, multi-factor scoring model and provides reasons supporting each ranking.
- **Interactive web console:** Provides an overview, prioritized alerts, a relationship graph, threat trends, and a searchable source-record inspector.
- **Evidence and provenance:** Retains source information to help users trace findings back to the records from which they were derived.
- **Offline demonstration mode:** Runs against bundled sample records without requiring external network access.
- **HTTP API:** Exposes dashboard data through documented endpoints, with interactive API documentation.

## Architecture

DarkPulse follows a modular processing pipeline:

```text
Public Threat Intelligence Sources
              |
              v
       Data Ingestion
              |
              v
   Normalization and Storage
              |
              v
     Entity Extraction
              |
              v
      Knowledge Graph
              |
              v
  Correlation and Clustering
              |
              v
 Temporal Analysis and Risk Scoring
              |
              v
       Dataset Preparation
              |
              v
       FastAPI Backend
              |
              v
      Interactive Web UI
```

### Technology Stack

| Component | Technologies |
|---|---|
| Core language | Python |
| API and web server | FastAPI, Uvicorn |
| Data validation and settings | Pydantic |
| HTTP requests | HTTPX |
| Feed parsing | Feedparser |
| Knowledge graph | NetworkX |
| Retry handling | Tenacity |
| Frontend | HTML, CSS, JavaScript |
| Graph and data visualization | ECharts |
| Optional NLP | spaCy |
| Optional storage | MongoDB |
| Optional graph integration | Neo4j |
| Testing | pytest |

## Dashboard

The web interface provides the following views:

### Overview
Displays key dataset statistics, prioritized entities, source coverage, recent activity, and pipeline status.

### Priority Alerts
Presents ranked entities with risk scores, contributing factors, explanatory reasons, activity summaries, and supporting records.

### Relationship Graph
Visualizes connections between cybersecurity entities. Graph requests can be focused on a particular entity, limited by traversal depth and node count, and filtered by entity type.

### Threat Trends
Shows daily activity by source, selected entity activity over time, and candidate spikes identified by temporal analysis.

### Source Inspector
Supports searching and filtering normalized records and inspecting their source information and associated metadata.

The interface communicates with the backend through the `/api` endpoints. Interactive API documentation is available at `/api/docs` while the application is running.

## Data Sources

DarkPulse is configured to collect information from:

- **NVD:** Vulnerability information and CVE records.
- **CISA Known Exploited Vulnerabilities (KEV) Catalog:** Vulnerabilities identified by CISA as exploited in the wild.
- **RSS/Atom feeds:** Additional cybersecurity news and threat-intelligence reporting from configured feeds.

The information available to the system depends on source accessibility, feed content, and successful ingestion. Extracted relationships and detected activity changes should be treated as analytical findings requiring appropriate interpretation, not automatic proof of an incident or attribution.

## Knowledge Graph

DarkPulse constructs a graph of normalized entities and their relationships. Entity types include:

- Vulnerabilities
- Malware
- Threat actors
- Organizations
- Technologies
- Incidents and source records

Example relationship types include:

- Vulnerability → Exploited by → Malware
- Malware → Used by → Threat actor
- Vulnerability → Affects → Technology
- Vulnerability → Targets organization → Organization
- Source record → Mentions → Entity

Entity aliases are normalized where supported by the configured rules. Source records can also be associated with entities to preserve provenance.

Relationships inferred from co-occurrence or heuristic extraction may be uncertain. Their interpretation should take account of the source evidence available.

## Risk Prioritization

DarkPulse calculates a configurable, weighted score to help prioritize entities for further investigation. The model considers five factors:

1. **Activity growth:** Observed mention volume across sources.
2. **Relationship density:** The entity's connectivity within the knowledge graph.
3. **Severity:** CVSS severity information when available.
4. **Recency:** How recently the entity was observed, using time decay.
5. **Asset relevance:** Overlap with configured monitored assets.

The system also incorporates contextual reasons, such as presence in the CISA KEV Catalog, where applicable.

The score is a heuristic prioritization measure, not a calibrated probability that an attack will occur. Rankings depend on the available data, configured weights, and the entities being analyzed.

## Getting Started

### Requirements

- Python 3.10 or later
- `pip`
- Internet access for live data collection
- A modern web browser for the dashboard

Internet access is not required for the offline demonstration.

### Installation

Clone or download the repository, then navigate to the project directory.

Create and activate a virtual environment:

```bash
python -m venv .venv
```

**Windows (PowerShell):**

```powershell
.venv\Scripts\Activate.ps1
```

**Linux/macOS:**

```bash
source .venv/bin/activate
```

Install the dependencies:

```bash
pip install -r requirements.txt
```

For editable installation with the command-line entry point:

```bash
pip install -e .
```

Optional NLP support can be installed with:

```bash
pip install -e ".[nlp]"
python -m spacy download en_core_web_sm
```

Optional MongoDB, Neo4j, and development dependencies are available through the corresponding extras in `pyproject.toml`.

### Run the Offline Demonstration

Run the bundled sample dataset through the pipeline:

```bash
darkpulse demo
```

Launch the web interface in offline mode:

```bash
darkpulse dashboard --offline
```

By default, the dashboard is available at:

`http://127.0.0.1:8000`

The initial pipeline run executes in the background. The interface displays the run status and populates with results when processing completes.

### Run with Live Sources

Launch the dashboard using configured live sources:

```bash
darkpulse dashboard
```

To run the pipeline from the command line and export its artifacts:

```bash
darkpulse pipeline
```

To run ingestion only:

```bash
darkpulse ingest
```

To explicitly use the bundled fixtures for a pipeline run:

```bash
darkpulse pipeline --offline
```

Additional dashboard options include:

```bash
darkpulse dashboard --host 127.0.0.1 --port 8000 --no-browser
```

Use `--live` to force live collection when offline mode is enabled through environment configuration.

## HTTP API

The application provides endpoints for dashboard data and pipeline control.

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/healthz` | Basic health and run-state check |
| `GET` | `/api/status` | Pipeline state, progress message, and errors |
| `GET` | `/api/meta` | Entity types, source coverage, and dataset metadata |
| `GET` | `/api/overview` | Overview statistics |
| `GET` | `/api/alerts` | Searchable and filterable prioritized alerts |
| `GET` | `/api/alerts/{key}` | Details for a prioritized entity |
| `GET` | `/api/graph` | Bounded relationship graph |
| `GET` | `/api/graph/neighbors` | One-hop graph expansion |
| `GET` | `/api/graph/search` | Entity search and autocomplete |
| `GET` | `/api/trends` | Temporal activity and spike data |
| `GET` | `/api/records` | Searchable, filterable, paginated records |
| `GET` | `/api/records/{record_id}` | Details for a source record |
| `POST` | `/api/refresh` | Request a background pipeline refresh |

Interactive API documentation:

`http://127.0.0.1:8000/api/docs`

## Configuration

DarkPulse supports environment variables for common configuration options.

| Variable | Purpose |
|---|---|
| `DARKPULSE_OFFLINE` | Enable offline mode using bundled fixtures |
| `NVD_API_KEY` | Optional API key for NVD requests |
| `DARKPULSE_MONGO` | Enable the optional MongoDB backend |
| `DARKPULSE_NEO4J` | Enable optional Neo4j integration |
| `DARKPULSE_NEO4J_URI` | Neo4j connection URI |
| `DARKPULSE_NEO4J_USER` | Neo4j username |
| `DARKPULSE_NEO4J_PASSWORD` | Neo4j password |
| `DARKPULSE_MONITORED_ASSETS` | Comma-separated asset names used in risk prioritization |
| `DARKPULSE_SNAPSHOT_DIR` | Directory for exported snapshots and artifacts |
| `DARKPULSE_FIXTURE_DIR` | Directory containing offline fixture records |
| `DARKPULSE_LOG_LEVEL` | Logging verbosity |

The optional database integrations require their respective Python drivers and appropriate service configuration.

## Storage and Artifacts

DarkPulse separates original source payloads from normalized records.

- **Raw records:** Preserve source payloads for provenance.
- **Normalized records:** Store standardized records used by downstream processing.

The default store operates in memory and supports JSON snapshot and artifact persistence. MongoDB is available as an optional storage backend. Optional Neo4j integration supports graph export.

By default, snapshots and exported artifacts are stored under `data/snapshots/`, configurable through `DARKPULSE_SNAPSHOT_DIR`.

## Reliability and Error Handling

- HTTP ingestion uses retry handling with exponential backoff for eligible failures.
- Sources use configured request pacing.
- Pipeline phases report errors so that failures can be diagnosed.
- The web interface tracks background run status.
- A failed refresh can leave the previously loaded dataset available.
- Offline mode enables repeatable demonstrations and tests without live-source dependencies.

Live-source results can vary depending on connectivity, API availability, rate limits, and changes in upstream data.

## Testing

Run the test suite from the repository root:

```bash
pytest -v tests/
```

The tests cover core pipeline behavior, indicator extraction, entity normalization, graph construction, temporal analysis, correlation, risk scoring, storage, and web API functionality, including selected error-handling scenarios.

## Project Structure

```text
DarkPulse/
├── darkpulse/
│   ├── analysis/       # Temporal analysis and risk scoring
│   ├── correlation/    # Cross-source correlation and clustering
│   ├── extraction/     # Indicator and entity extraction
│   ├── graph/          # Entity normalization and knowledge graph
│   ├── ingestion/      # NVD, CISA KEV, and feed connectors
│   ├── storage/        # Storage interfaces and optional backends
│   ├── web/
│   │   ├── app.py      # FastAPI application and API routes
│   │   ├── dataset.py  # Dashboard dataset and graph payloads
│   │   ├── server.py   # Local web server launcher
│   │   └── static/     # Frontend assets
│   ├── fixtures/       # Bundled offline sample records
│   ├── cli.py          # Command-line interface
│   ├── config.py       # Application configuration
│   ├── models.py       # Shared data models
│   ├── pipeline.py     # Pipeline orchestration
│   └── utils.py        # Shared utilities
├── data/
│   └── snapshots/      # Generated snapshots and artifacts
├── tests/              # Unit and integration tests
├── pyproject.toml      # Package and optional dependency configuration
├── requirements.txt    # Runtime and test dependencies
└── README.md
```

## Limitations

- Entity extraction and alias normalization depend on configured patterns, rules, and optional NLP capabilities.
- Cross-source correlation and event clustering use heuristics and may produce incorrect or incomplete associations.
- Temporal spikes indicate unusual changes in observed data; they do not independently establish an emerging threat.
- Risk rankings depend on source coverage, available severity information, selected weights, and monitored-asset configuration.
- Public threat-intelligence data may be incomplete, delayed, duplicated, or inconsistent.

DarkPulse is intended to support threat-intelligence exploration and prioritization. Findings should be reviewed against their supporting evidence before being used for operational decisions.
