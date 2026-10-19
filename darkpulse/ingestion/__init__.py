"""Ingestion subpackage: source connectors, retry policy and rate limiting."""

from .retry import (
    DEFAULT_MAX_ATTEMPTS,
    RateLimiter,
    TransientError,
    fetch_with_retry,
)
from .sources import DEFAULT_FEEDS, FeedConnector, KevConnector, NvdConnector

__all__ = [
    "DEFAULT_FEEDS",
    "DEFAULT_MAX_ATTEMPTS",
    "FeedConnector",
    "KevConnector",
    "NvdConnector",
    "RateLimiter",
    "TransientError",
    "fetch_with_retry",
]
