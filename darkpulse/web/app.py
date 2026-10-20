"""FastAPI backend for the DarkPulse dashboard.

Design notes (why this is fast and does not blank out):

* the pipeline runs **once**, in a background thread, so the UI paints
  immediately and can surface progress instead of looking frozen;
* every response is built from :class:`DashboardDataset` indexes, never by
  re-scanning all records;
* graph views are bounded server-side (see ``GraphRequest``), so the browser
  never has to lay out an unbounded network;
* the frontend is served from local static files, with no CDN dependency.
"""

from __future__ import annotations

import logging
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from ..config import Settings, get_settings
from ..models import EntityType
from ..pipeline import Pipeline
from ..utils import configure_logging, utcnow
from .dataset import DashboardDataset, GraphRequest, build_dataset

logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).resolve().parent / "static"
VERSION = "2.0.0"


# ---------------------------------------------------------------------------
# Pipeline controller
# ---------------------------------------------------------------------------


class RefreshRequest(BaseModel):
    offline: bool | None = None


class DashboardController:
    """Owns the current dataset and the background pipeline run."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        configure_logging(self.settings.log_level)
        self._lock = threading.RLock()
        self._state = "idle"
        self._message = "Waiting for the first pipeline run"
        self._error: str | None = None
        self._warnings: list[str] = []
        self._started_at: str | None = None
        self._finished_at: str | None = None
        self._duration_ms: int | None = None
        self._thread: threading.Thread | None = None
        self.dataset: DashboardDataset | None = None

    # -- status ---------------------------------------------------------
    @property
    def status(self) -> dict[str, Any]:
        with self._lock:
            dataset = self.dataset
            return {
                "state": self._state,
                "message": self._message,
                "error": self._error,
                "warnings": list(self._warnings),
                "started_at": self._started_at,
                "finished_at": self._finished_at,
                "duration_ms": self._duration_ms,
                "has_data": dataset is not None,
                "records": len(dataset.records) if dataset else 0,
                "alerts": len(dataset.alerts) if dataset else 0,
                "spikes": len(dataset.spikes) if dataset else 0,
                "entities": len(dataset.graph.nodes) if dataset else 0,
                "generated_at": (
                    dataset.generated_at.isoformat() if dataset else None
                ),
                "offline": (
                    dataset.offline if dataset else self.settings.offline
                ),
                "version": VERSION,
            }

    # -- running --------------------------------------------------------
    def start(self, offline: bool | None = None, *, force: bool = False) -> bool:
        """Kick off a pipeline run; returns False when one is already running."""
        with self._lock:
            if self._state == "running" and not force:
                return False
            self._state = "running"
            self._message = (
                "Loading bundled fixtures" if (offline or self.settings.offline)
                else "Collecting from NVD, CISA KEV and RSS feeds"
            )
            self._error = None
            self._warnings = []
            self._started_at = utcnow().isoformat()
            self._finished_at = None
            self._duration_ms = None
            self._thread = threading.Thread(
                target=self._run,
                args=(offline,),
                name="darkpulse-pipeline",
                daemon=True,
            )
            self._thread.start()
            return True

    def wait(self, timeout: float | None = None) -> None:
        """Block until the current run finishes (used by tests and the CLI)."""
        thread = self._thread
        if thread is not None:
            thread.join(timeout)

    def load(self, dataset: DashboardDataset) -> None:
        """Adopt an already-built dataset (artifact replay, tests, embedding)."""
        with self._lock:
            self.dataset = dataset
            self._state = "ready"
            self._error = None
            self._warnings = list(dataset.result.errors) if dataset.result else []
            self._message = (
                f"{len(dataset.records)} records, {len(dataset.alerts)} entities scored"
            )
            self._started_at = dataset.generated_at.isoformat()
            self._finished_at = dataset.generated_at.isoformat()
            self._duration_ms = None

    def _run(self, offline: bool | None) -> None:
        started = time.perf_counter()
        try:
            settings = self.settings.model_copy(deep=True)
            if offline is not None:
                settings.offline = offline
            self._message = "Running ingestion, extraction, graph and risk phases"
            pipeline = Pipeline(settings)
            result = pipeline.run(offline=settings.offline)
            dataset = build_dataset(
                records=pipeline.last_records,
                events=pipeline.last_events,
                alerts=pipeline.last_alerts,
                spikes=pipeline.last_spikes,
                graph=pipeline.graph.graph,
                result=result,
                offline=settings.offline,
            )
            warnings = list(result.errors)
            with self._lock:
                self.dataset = dataset
                self._state = "ready"
                self._warnings = warnings
                self._error = None
                self._message = (
                    f"{len(dataset.records)} records, {len(dataset.alerts)} entities scored"
                )
                self._duration_ms = int((time.perf_counter() - started) * 1000)
                self._finished_at = utcnow().isoformat()
            logger.info("dashboard dataset ready in %d ms", self._duration_ms)
        except Exception as exc:  # a failed refresh must not blank the dashboard
            logger.exception("pipeline run failed")
            with self._lock:
                self._duration_ms = int((time.perf_counter() - started) * 1000)
                self._finished_at = utcnow().isoformat()
                self._message = "Pipeline run failed"
                self._error = f"{type(exc).__name__}: {exc}"
                # Keep serving the previous dataset when a refresh fails.
                self._state = "ready" if self.dataset is not None else "error"


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def create_app(
    settings: Settings | None = None,
    controller: DashboardController | None = None,
    *,
    auto_start: bool = True,
) -> FastAPI:
    controller = controller or DashboardController(settings)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        if auto_start:
            controller.start()
        yield

    app = FastAPI(
        title="DarkPulse",
        version=VERSION,
        docs_url="/api/docs",
        redoc_url=None,
        lifespan=lifespan,
    )
    app.state.controller = controller
    app.add_middleware(GZipMiddleware, minimum_size=700)

    # -- helpers --------------------------------------------------------
    def require_dataset() -> DashboardDataset:
        dataset = controller.dataset
        if dataset is None:
            raise HTTPException(
                status_code=503,
                detail="The first pipeline run has not finished yet.",
            )
        return dataset

    def no_store(payload: Any) -> JSONResponse:
        return JSONResponse(payload, headers={"Cache-Control": "no-store"})

    # -- shell ----------------------------------------------------------
    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(
            STATIC_DIR / "index.html",
            headers={"Cache-Control": "no-store"},
        )

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict[str, Any]:
        return {"ok": True, "state": controller.status["state"]}

    # -- meta -----------------------------------------------------------
    @app.get("/api/status")
    def api_status() -> JSONResponse:
        return no_store(controller.status)

    @app.post("/api/refresh")
    def api_refresh(body: RefreshRequest | None = None) -> JSONResponse:
        offline = body.offline if body else None
        started = controller.start(offline)
        return no_store({"started": started, "status": controller.status})

    @app.get("/api/meta")
    def api_meta() -> JSONResponse:
        dataset = require_dataset()
        return no_store(
            {
                "version": VERSION,
                "entity_types": [entity.value for entity in EntityType],
                "graph_limit": {
                    "default": 320,
                    "max": 1500,
                },
                "types": dataset.to_overview()["type_counts"],
                "sources": dataset.to_overview()["sources"],
                "range": dataset.to_overview()["range"],
                "generated_at": dataset.generated_at.isoformat(),
                "offline": dataset.offline,
            }
        )

    # -- overview -------------------------------------------------------
    @app.get("/api/overview")
    def api_overview() -> JSONResponse:
        return no_store(require_dataset().to_overview())

    # -- alerts ---------------------------------------------------------
    @app.get("/api/alerts")
    def api_alerts(
        types: str = "",
        q: str = "",
        limit: int = Query(100, ge=1, le=500),
    ) -> JSONResponse:
        selected = _split(types)
        return no_store(
            require_dataset().to_alerts(types=selected, query=q, limit=limit)
        )

    @app.get("/api/alerts/{key:path}")
    def api_alert_detail(key: str) -> JSONResponse:
        detail = require_dataset().alert_detail(key)
        if detail is None:
            raise HTTPException(status_code=404, detail=f"Unknown alert: {key}")
        return no_store(detail)

    # -- graph ----------------------------------------------------------
    @app.get("/api/graph")
    def api_graph(
        focus: str = "",
        depth: int = Query(2, ge=1, le=4),
        types: str = "",
        limit: int = Query(320, ge=10, le=1500),
        include_records: bool = False,
    ) -> JSONResponse:
        dataset = require_dataset()
        request = GraphRequest(
            focus=focus or None,
            depth=depth,
            types=tuple(_split(types)) or tuple(e.value for e in EntityType),
            limit=limit,
            include_records=include_records,
        )
        return no_store(dataset.graph_payload(request))

    @app.get("/api/graph/neighbors")
    def api_graph_neighbors(
        node: str,
        limit: int = Query(70, ge=5, le=400),
    ) -> JSONResponse:
        payload = require_dataset().neighbors_payload(node, limit=limit)
        if payload is None:
            raise HTTPException(status_code=404, detail=f"Unknown node: {node}")
        return no_store(payload)

    @app.get("/api/graph/search")
    def api_graph_search(
        q: str,
        limit: int = Query(12, ge=1, le=50),
    ) -> JSONResponse:
        dataset = require_dataset()
        return no_store({"items": dataset.search_nodes(q, limit=limit)})

    # -- trends ---------------------------------------------------------
    @app.get("/api/trends")
    def api_trends(days: int = Query(60, ge=7, le=365)) -> JSONResponse:
        return no_store(require_dataset().to_trends(days=days))

    # -- records --------------------------------------------------------
    @app.get("/api/records")
    def api_records(
        source: str = "",
        q: str = "",
        cve: str = "",
        offset: int = Query(0, ge=0),
        limit: int = Query(40, ge=5, le=200),
    ) -> JSONResponse:
        return no_store(
            require_dataset().to_records(
                source=source, query=q, cve=cve, offset=offset, limit=limit
            )
        )

    @app.get("/api/records/{record_id}")
    def api_record_detail(record_id: str) -> JSONResponse:
        detail = require_dataset().record_detail(record_id)
        if detail is None:
            raise HTTPException(status_code=404, detail=f"Unknown record: {record_id}")
        return no_store(detail)

    # -- static ---------------------------------------------------------
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.middleware("http")
    async def cache_static(request: Request, call_next):
        response = await call_next(request)
        if request.url.path.startswith("/static/vendor/"):
            response.headers.setdefault(
                "Cache-Control", "public, max-age=31536000, immutable"
            )
        return response

    logger.info("DarkPulse web app ready (static=%s)", STATIC_DIR)
    return app


def _split(raw: str) -> list[str]:
    return [item.strip() for item in raw.split(",") if item.strip()]
