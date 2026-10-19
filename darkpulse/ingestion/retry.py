"""HTTP resilience: tenacity retry policy and polite request pacing."""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

logger = logging.getLogger(__name__)

DEFAULT_MAX_ATTEMPTS = 4
DEFAULT_BACKOFF_BASE = 1.6


class TransientError(Exception):
    """Retryable fetch failure: timeout, transport fault, HTTP 429 or 5xx."""


def fetch_with_retry(
    url: str,
    *,
    params: dict[str, Any] | None = None,
    timeout: float = 20.0,
    headers: dict[str, str] | None = None,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    backoff_base: float = DEFAULT_BACKOFF_BASE,
) -> httpx.Response:
    """GET ``url`` with exponential backoff on transient failures.

    Non-retryable 4xx responses raise :class:`httpx.HTTPStatusError`
    immediately; exhausted retries re-raise :class:`TransientError`.
    """

    @retry(
        reraise=True,
        stop=stop_after_attempt(max(1, max_attempts)),
        wait=wait_exponential(multiplier=backoff_base, min=1, max=30),
        retry=retry_if_exception_type(TransientError),
        before_sleep=lambda state: logger.warning(
            "retry %d/%d after error: %s",
            state.attempt_number,
            max_attempts,
            state.outcome.exception() if state.outcome else "unknown",
        ),
    )
    def _get() -> httpx.Response:
        try:
            response = httpx.get(
                url,
                params=params,
                timeout=timeout,
                headers=headers,
                follow_redirects=True,
            )
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            raise TransientError(f"GET {url} failed: {exc}") from exc
        if response.status_code == 429 or response.status_code >= 500:
            raise TransientError(f"HTTP {response.status_code} from {url}")
        response.raise_for_status()
        return response

    return _get()


class RateLimiter:
    """Minimum-interval pacer (e.g. NVD advises ~6 requests/minute)."""

    def __init__(self, requests_per_minute: float) -> None:
        self.interval = 60.0 / requests_per_minute if requests_per_minute > 0 else 0.0
        self._last: float | None = None

    def wait(self) -> None:
        if self.interval <= 0:
            return
        if self._last is not None:
            remaining = self.interval - (time.monotonic() - self._last)
            if remaining > 0:
                time.sleep(remaining)
        self._last = time.monotonic()
