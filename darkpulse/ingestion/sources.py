"""Public source connectors: NVD API 2.0, CISA KEV catalog and RSS/Atom feeds."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Any

import feedparser
import httpx

from ..config import Settings, SourceConfig
from ..models import NormalizedRecord, RawRecord, SourceKind, stable_id
from ..storage.base import BaseStore
from ..utils import parse_dt, utcnow
from .retry import RateLimiter, TransientError, fetch_with_retry

logger = logging.getLogger(__name__)

USER_AGENT = "DarkPulse/0.1 (+https://github.com/darkpulse)"
NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

DEFAULT_FEEDS = (
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.bleepingcomputer.com/feed/",
    "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "https://krebsonsecurity.com/feed/",
    "https://threatpost.com/feed/",
    "https://blog.malwarebytes.com/feed/",
)


def _json_object(response: httpx.Response) -> dict[str, Any]:
    """Decode a JSON object response, rejecting malformed or non-object bodies."""
    try:
        payload = response.json()
    except ValueError as exc:
        raise ValueError(f"invalid JSON from {response.url}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"expected a JSON object from {response.url}")
    return payload


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


class BaseConnector(ABC):
    """Fetches source payloads, stores them raw and yields normalized records."""

    kind: SourceKind

    def __init__(
        self, store: BaseStore, settings: Settings, config: SourceConfig
    ) -> None:
        self.store = store
        self.settings = settings
        self.config = config
        self.limiter = RateLimiter(config.requests_per_minute)

    @abstractmethod
    def fetch(self) -> list[NormalizedRecord]:
        """Fetch, persist raw payloads and return normalized records."""

    def _request(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        self.limiter.wait()
        return fetch_with_retry(
            url,
            params=params,
            timeout=self.config.timeout,
            headers={"User-Agent": USER_AGENT, **(headers or {})},
            max_attempts=self.config.max_retries,
            backoff_base=self.config.backoff_base,
        )

    def _save_raw(self, source_record_id: str, payload: dict[str, Any]) -> str:
        raw_id = stable_id(self.kind.value, source_record_id)
        self.store.save_raw(
            RawRecord(
                id=raw_id,
                source=self.kind,
                source_record_id=source_record_id,
                payload=payload,
            )
        )
        return raw_id

    def _normalized(
        self,
        *,
        source_record_id: str,
        raw_id: str,
        record_type: str,
        title: str,
        text: str,
        published: datetime | None,
        url: str | None = None,
        labels: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> NormalizedRecord:
        return NormalizedRecord(
            id=stable_id(self.kind.value, source_record_id),
            source=self.kind,
            source_record_id=source_record_id,
            record_type=record_type,
            title=title,
            text=text,
            published_at=published,
            url=url,
            labels=labels or [],
            metadata=metadata or {},
            raw_id=raw_id,
        )


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000")


def _extract_cvss(metrics: Any) -> float | None:
    if not isinstance(metrics, dict):
        return None
    for pool in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for entry in _as_list(metrics.get(pool)):
            score = (entry.get("cvssData") or {}).get("baseScore")
            if score is None:
                continue
            try:
                return float(score)
            except (TypeError, ValueError):
                continue
    return None


def _english_description(cve: dict[str, Any]) -> str:
    for description in _as_list(cve.get("descriptions")):
        if description.get("lang") == "en":
            return description.get("value", "")
    return ""


class NvdConnector(BaseConnector):
    """NVD CVE API 2.0 connector with API-key support and request pacing."""

    kind = SourceKind.NVD

    def fetch(
        self,
        *,
        days_back: int = 7,
        results_per_page: int = 50,
        max_pages: int = 3,
    ) -> list[NormalizedRecord]:
        headers = {"apiKey": self.settings.nvd_api_key} if self.settings.nvd_api_key else {}
        end = utcnow()
        start = end - timedelta(days=days_back)
        records: list[NormalizedRecord] = []

        for page in range(max_pages):
            start_index = page * results_per_page
            try:
                response = self._request(
                    NVD_BASE,
                    params={
                        "resultsPerPage": results_per_page,
                        "startIndex": start_index,
                        "lastModStartDate": _iso(start),
                        "lastModEndDate": _iso(end),
                    },
                    headers=headers,
                )
                payload = _json_object(response)
            except (TransientError, httpx.HTTPError, ValueError) as exc:
                logger.error("NVD page %d failed: %s", page, exc)
                break

            raw_id = self._save_raw(f"page-{start_index}", payload)
            for item in _as_list(payload.get("vulnerabilities")):
                record = self._normalize_cve(item.get("cve") or {}, raw_id)
                if record is not None:
                    records.append(record)

            total = payload.get("totalResults", 0)
            if not isinstance(total, int) or start_index + results_per_page >= total:
                break

        logger.info("NVD connector: %d normalized records", len(records))
        return records

    def _normalize_cve(
        self, cve: dict[str, Any], raw_id: str
    ) -> NormalizedRecord | None:
        cve_id = cve.get("id")
        if not isinstance(cve_id, str) or not cve_id:
            return None
        description = _english_description(cve)
        published = parse_dt(cve.get("published"))
        references = [
            ref["url"] for ref in _as_list(cve.get("references")) if ref.get("url")
        ]
        return self._normalized(
            source_record_id=cve_id,
            raw_id=raw_id,
            record_type="vulnerability",
            title=f"{cve_id}: {description[:80]}".strip(),
            text=description,
            published=published,
            url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            labels=["cve"] + (["kev"] if cve.get("isKevApplied") else []),
            metadata={
                "cvss": _extract_cvss(cve.get("metrics")),
                "references": references[:5],
                "status": cve.get("vulnStatus"),
            },
        )


class KevConnector(BaseConnector):
    """CISA Known Exploited Vulnerabilities catalog connector."""

    kind = SourceKind.CISA_KEV

    def fetch(self) -> list[NormalizedRecord]:
        try:
            payload = _json_object(self._request(self.config.url))
        except (TransientError, httpx.HTTPError, ValueError) as exc:
            logger.error("KEV fetch failed: %s", exc)
            return []

        raw_id = self._save_raw("catalog", payload)
        records: list[NormalizedRecord] = []
        for vuln in _as_list(payload.get("vulnerabilities")):
            cve_id = vuln.get("cveID")
            if not isinstance(cve_id, str) or not cve_id:
                continue
            vendor = vuln.get("vendorProject", "")
            product = vuln.get("product", "")
            records.append(
                self._normalized(
                    source_record_id=cve_id,
                    raw_id=raw_id,
                    record_type="exploited",
                    title=f"KEV: {cve_id} - {vendor} {product}".strip(),
                    text=(
                        f"{vendor} {product} {vuln.get('vulnerabilityName', '')}. "
                        f"{vuln.get('shortDescription', '')} "
                        f"Required action: {vuln.get('requiredAction', '')}"
                    ),
                    published=parse_dt(vuln.get("dateAdded")),
                    labels=["kev", "exploited"],
                    metadata={
                        "vendor": vendor,
                        "product": product,
                        "due_date": vuln.get("dueDate"),
                        "known_ransomware": vuln.get("knownRansomwareCampaignUse"),
                        "notes": vuln.get("notes"),
                    },
                )
            )
        logger.info("KEV connector: %d normalized records", len(records))
        return records


class FeedConnector(BaseConnector):
    """RSS/Atom threat-intel feeds, fetched through the shared retry policy."""

    kind = SourceKind.RSS

    def fetch(
        self, feeds: list[str] | None = None, max_per_feed: int = 20
    ) -> list[NormalizedRecord]:
        feed_urls = feeds or list(DEFAULT_FEEDS)
        records: list[NormalizedRecord] = []

        for url in feed_urls:
            try:
                response = self._request(url)
            except (TransientError, httpx.HTTPError) as exc:
                logger.warning("feed %s failed: %s", url, exc)
                continue

            parsed = feedparser.parse(response.content)
            entries = list(parsed.entries)[:max_per_feed]
            if not entries:
                if parsed.bozo:
                    logger.warning("feed %s unparseable: %s", url, parsed.bozo_exception)
                else:
                    logger.debug("feed %s returned no entries", url)
                continue

            for entry in entries:
                title = getattr(entry, "title", "") or ""
                summary = (
                    getattr(entry, "summary", "")
                    or getattr(entry, "description", "")
                    or ""
                )
                link = getattr(entry, "link", None)
                guid = getattr(entry, "id", None) or link or title
                if not guid:
                    continue
                records.append(
                    self._normalized(
                        source_record_id=str(guid),
                        raw_id=self._save_raw(str(guid), _entry_payload(entry)),
                        record_type="article",
                        title=title,
                        text=summary,
                        published=parse_dt(
                            getattr(entry, "published", None)
                            or getattr(entry, "updated", None)
                        ),
                        url=link,
                        labels=["feed"],
                        metadata={"feed": url},
                    )
                )

        logger.info(
            "Feed connector: %d normalized records from %d feeds",
            len(records),
            len(feed_urls),
        )
        return records


def _entry_payload(entry: Any) -> dict[str, str]:
    fields = ("title", "link", "id", "published", "updated", "summary", "author")
    return {
        name: value
        for name in fields
        if (value := getattr(entry, name, None))
    }
