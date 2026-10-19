"""Cross-cutting helpers: logging, UTC time handling and text similarity."""

from __future__ import annotations

import logging
import re
import sys
from datetime import datetime, timezone

from dateutil import parser as date_parser

LOG_FORMAT = "%(asctime)s %(levelname)-7s [%(name)s] %(message)s"
_LOGGER_ROOT = "darkpulse"
_handler_installed = False


def configure_logging(level: str | int = "INFO") -> None:
    """Install one stderr handler on the ``darkpulse`` logger.

    Idempotent, so it is safe to call from the CLI, the pipeline and tests.
    Library modules only ever use ``logging.getLogger(__name__)``.
    """
    global _handler_installed
    logger = logging.getLogger(_LOGGER_ROOT)
    if not _handler_installed:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter(LOG_FORMAT))
        logger.addHandler(handler)
        logger.propagate = False
        _handler_installed = True
    logger.setLevel(_coerce_level(level))


def _coerce_level(level: str | int) -> int:
    if isinstance(level, int):
        return level
    resolved = getattr(logging, str(level).upper(), None)
    return resolved if isinstance(resolved, int) else logging.INFO


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def as_utc(value: datetime) -> datetime:
    """Return ``value`` as an aware UTC datetime (naive input is assumed UTC)."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def parse_dt(value: str | datetime | None) -> datetime | None:
    """Parse ISO-8601 / RSS timestamps into aware UTC datetimes.

    Returns ``None`` for missing, blank or unparseable input instead of
    propagating feed-level date garbage into the pipeline.
    """
    if isinstance(value, datetime):
        return as_utc(value)
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return as_utc(date_parser.parse(value))
    except (ValueError, TypeError, OverflowError):
        return None


_WORD = re.compile(r"[a-z0-9]+")


def _tokens(text: str) -> set[str]:
    return set(_WORD.findall(text.lower()))


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def similarity(a: str, b: str) -> float:
    """Blend of token Jaccard and containment, for short headline-like texts."""
    ta, tb = _tokens(a), _tokens(b)
    if not ta or not tb:
        return 0.0
    containment = len(ta & tb) / min(len(ta), len(tb))
    return max(_jaccard(ta, tb), containment * 0.9)
