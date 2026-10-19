"""Correlation subpackage: cross-source event clustering."""

from .engine import cluster_events
from ..models import CorrelatedEvent

__all__ = ["CorrelatedEvent", "cluster_events"]
