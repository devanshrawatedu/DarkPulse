"""Dashboard data layer and web API tests (offline, no network)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from darkpulse.config import get_settings
from darkpulse.pipeline import Pipeline
from darkpulse.web.app import DashboardController, create_app
from darkpulse.web.dataset import (
    DEFAULT_GRAPH_LIMIT,
    DashboardDataset,
    GraphRequest,
    build_dataset,
)


@pytest.fixture(scope="module")
def dataset(tmp_path_factory) -> DashboardDataset:
    settings = get_settings()
    settings.offline = True
    settings.snapshot_dir = tmp_path_factory.mktemp("snapshots")
    pipeline = Pipeline(settings)
    result = pipeline.run(offline=True)
    return build_dataset(
        records=pipeline.last_records,
        events=pipeline.last_events,
        alerts=pipeline.last_alerts,
        spikes=pipeline.last_spikes,
        graph=pipeline.graph.graph,
        result=result,
        offline=True,
    )


@pytest.fixture(scope="module")
def controller(dataset: DashboardDataset) -> DashboardController:
    settings = get_settings()
    settings.offline = True
    instance = DashboardController(settings)
    instance.load(dataset)
    return instance


@pytest.fixture(scope="module")
def client(controller: DashboardController):
    app = create_app(controller=controller, auto_start=False)
    with TestClient(app) as test_client:
        yield test_client


# ---------------------------------------------------------------------------
# Dataset
# ---------------------------------------------------------------------------


def test_overview_matches_pipeline(dataset: DashboardDataset) -> None:
    overview = dataset.to_overview()
    assert overview["records"] == len(dataset.records)
    assert overview["alerts"] == len(dataset.alerts)
    assert overview["nodes"] == dataset.graph.number_of_nodes()
    assert overview["edges"] == dataset.graph.number_of_edges()
    assert sum(overview["sources"].values()) == len(dataset.records)
    assert overview["activity"]["dates"]


def test_graph_is_bounded_and_ranked(dataset: DashboardDataset) -> None:
    payload = dataset.graph_payload(GraphRequest(limit=10))
    assert len(payload["nodes"]) == 10
    assert payload["meta"]["truncated"] is True
    assert payload["meta"]["dropped"] > 0
    assert payload["meta"]["shown"] == 10
    assert all(node["type"] != "source" for node in payload["nodes"])
    kept = {node["id"] for node in payload["nodes"]}
    assert all(link["source"] in kept and link["target"] in kept for link in payload["links"])


def test_graph_default_limit_caps_large_views(dataset: DashboardDataset) -> None:
    payload = dataset.graph_payload(GraphRequest())
    assert payload["meta"]["limit"] == DEFAULT_GRAPH_LIMIT
    assert len(payload["nodes"]) <= DEFAULT_GRAPH_LIMIT


def test_graph_type_filter(dataset: DashboardDataset) -> None:
    payload = dataset.graph_payload(GraphRequest(types=("vulnerability",), limit=50))
    assert payload["nodes"]
    assert {node["type"] for node in payload["nodes"]} == {"vulnerability"}


def test_ego_graph_centers_on_focus(dataset: DashboardDataset) -> None:
    top = dataset.alerts[0]
    payload = dataset.graph_payload(
        GraphRequest(focus=top.entity, depth=1, limit=60)
    )
    assert payload["meta"]["focus"] is not None
    assert payload["meta"]["focus"]["name"] == top.entity
    ids = {node["id"] for node in payload["nodes"]}
    assert payload["meta"]["focus"]["id"] in ids
    assert len(payload["nodes"]) < dataset.graph.number_of_nodes()


def test_focus_resolution_is_case_insensitive(dataset: DashboardDataset) -> None:
    payload = dataset.graph_payload(GraphRequest(focus="cve-2024-3400"))
    assert payload["meta"]["focus"]["name"].upper() == "CVE-2024-3400"


def test_unknown_focus_reports_missing(dataset: DashboardDataset) -> None:
    payload = dataset.graph_payload(GraphRequest(focus="not-a-real-entity-xyz"))
    assert payload["meta"]["missing_focus"] is True
    assert payload["meta"]["focus"] is None
    assert payload["nodes"]


def test_provenance_nodes_are_opt_in(dataset: DashboardDataset) -> None:
    without = dataset.graph_payload(GraphRequest(limit=200))
    with_records = dataset.graph_payload(
        GraphRequest(include_records=True, limit=200)
    )
    assert all(node["type"] != "source" for node in without["nodes"])
    assert any(node["type"] == "source" for node in with_records["nodes"])


def test_neighbours_payload(dataset: DashboardDataset) -> None:
    top = dataset.alerts[0]
    payload = dataset.neighbors_payload(top.entity)
    assert payload is not None
    assert payload["meta"]["focus"]["name"] == top.entity
    assert payload["nodes"][0]["id"] == payload["meta"]["focus"]["id"]
    assert dataset.neighbors_payload("missing-entity") is None


def test_alert_detail_includes_evidence(dataset: DashboardDataset) -> None:
    payload = dataset.to_alerts(limit=5)["items"][0]
    detail = dataset.alert_detail(payload["node_id"])
    assert detail is not None
    assert detail["entity"] == payload["entity"]
    assert set(detail["components"]) == {
        "activity_growth",
        "relationship_density",
        "severity",
        "recency",
        "asset_relevance",
    }
    assert detail["records"], "scored entities should link back to evidence"
    assert len(detail["series"]["dates"]) == len(detail["series"]["values"])
    assert dataset.alert_detail("does-not-exist") is None


def test_alert_filters(dataset: DashboardDataset) -> None:
    payload = dataset.to_alerts(types=("vulnerability",), limit=200)
    assert payload["items"]
    assert {item["type"] for item in payload["items"]} == {"vulnerability"}
    searched = dataset.to_alerts(query="CVE-2024-3400", limit=50)
    assert any(item["entity"] == "CVE-2024-3400" for item in searched["items"])


def test_records_filtering_and_pagination(dataset: DashboardDataset) -> None:
    page = dataset.to_records(limit=5)
    assert page["total"] == len(dataset.records)
    assert len(page["items"]) == 5
    second = dataset.to_records(limit=5, offset=5)
    assert second["items"][0]["id"] != page["items"][0]["id"]

    source = next(iter(page["sources"]))
    filtered = dataset.to_records(source=source, limit=100)
    assert filtered["total"] == page["sources"][source]
    assert all(item["source"] == source for item in filtered["items"])

    cves = next(item for item in dataset.to_records(limit=200)["items"] if item["cves"])
    matched = dataset.to_records(cve=cves["cves"][0], limit=50)
    assert matched["total"] >= 1


def test_record_detail(dataset: DashboardDataset) -> None:
    record = dataset.records[0]
    detail = dataset.record_detail(record.id)
    assert detail is not None
    assert detail["id"] == record.id
    assert detail["metadata"] == record.metadata
    assert dataset.record_detail("nope") is None


def test_trends_series_alignment(dataset: DashboardDataset) -> None:
    trends = dataset.to_trends(days=30)
    length = len(trends["dates"])
    assert length > 0
    assert all(len(values) == length for values in trends["series"].values())
    assert len(trends["total"]) == length


def test_node_search(dataset: DashboardDataset) -> None:
    results = dataset.search_nodes("cve")
    assert results
    assert all("cve" in node["name"].lower() for node in results)


# ---------------------------------------------------------------------------
# HTTP API
# ---------------------------------------------------------------------------


def test_index_and_static_assets(client: TestClient) -> None:
    index = client.get("/")
    assert index.status_code == 200
    assert "DARKPULSE" in index.text
    assert "/static/app.js" in index.text

    script = client.get("/static/app.js")
    assert script.status_code == 200
    assert "echarts" in script.text

    vendor = client.get("/static/vendor/echarts.min.js")
    assert vendor.status_code == 200
    assert "immutable" in vendor.headers.get("cache-control", "")

    font = client.get("/static/vendor/fonts/inter-400.woff2")
    assert font.status_code == 200
    assert font.headers.get("content-type", "").startswith("font/")


def test_status_endpoint(client: TestClient) -> None:
    payload = client.get("/api/status").json()
    assert payload["state"] == "ready"
    assert payload["has_data"] is True
    assert payload["records"] > 0
    assert payload["version"].startswith("2.")


def test_api_reads(client: TestClient) -> None:
    overview = client.get("/api/overview").json()
    assert overview["alerts"] > 0

    alerts = client.get("/api/alerts", params={"limit": 5}).json()
    assert len(alerts["items"]) <= 5

    node_id = alerts["items"][0]["node_id"]
    detail = client.get(f"/api/alerts/{node_id}")
    assert detail.status_code == 200
    assert detail.json()["node_id"] == node_id

    assert client.get("/api/alerts/nothing-here").status_code == 404

    graph = client.get("/api/graph", params={"limit": 25}).json()
    assert len(graph["nodes"]) <= 25
    assert graph["meta"]["types"]

    neighbours = client.get(
        "/api/graph/neighbors", params={"node": node_id}
    ).json()
    assert neighbours["nodes"]

    search = client.get("/api/graph/search", params={"q": "cve"}).json()
    assert search["items"]

    trends = client.get("/api/trends", params={"days": 30}).json()
    assert trends["dates"]

    records = client.get("/api/records", params={"limit": 5}).json()
    assert len(records["items"]) <= 5
    record = client.get(f"/api/records/{records['items'][0]['id']}").json()
    assert record["id"] == records["items"][0]["id"]
    assert client.get("/api/records/missing").status_code == 404


def test_api_returns_503_without_dataset() -> None:
    settings = get_settings()
    settings.offline = True
    empty = DashboardController(settings)
    app = create_app(controller=empty, auto_start=False)
    with TestClient(app) as test_client:
        response = test_client.get("/api/overview")
        assert response.status_code == 503
        assert test_client.get("/api/status").json()["has_data"] is False


def test_failed_refresh_keeps_previous_dataset(
    dataset: DashboardDataset, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = get_settings()
    settings.offline = True
    instance = DashboardController(settings)
    instance.load(dataset)

    class ExplodingPipeline:
        def __init__(self, *args, **kwargs) -> None:
            raise RuntimeError("upstream unavailable")

    monkeypatch.setattr("darkpulse.web.app.Pipeline", ExplodingPipeline)
    assert instance.start(offline=True) is True
    instance.wait(10)

    status = instance.status
    assert instance.dataset is dataset
    assert status["state"] == "ready"
    assert "upstream unavailable" in (status["error"] or "")


def test_background_run_builds_dataset(tmp_path) -> None:
    settings = get_settings()
    settings.offline = True
    settings.snapshot_dir = tmp_path
    instance = DashboardController(settings)
    assert instance.start(offline=True) is True
    instance.wait(60)

    status = instance.status
    assert status["state"] == "ready", status
    assert status["error"] is None
    assert instance.dataset is not None
    assert len(instance.dataset.records) > 0
