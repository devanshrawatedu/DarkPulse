"""DarkPulse v2 web dashboard: FastAPI backend plus a static single-page UI."""

from __future__ import annotations

from typing import Any

from .dataset import DashboardDataset, GraphRequest, build_dataset

__all__ = ["DashboardDataset", "GraphRequest", "build_dataset", "create_app"]


def create_app(*args: Any, **kwargs: Any):
    """Import FastAPI lazily so the analysis core has no hard web dependency."""
    from .app import create_app as factory

    return factory(*args, **kwargs)
