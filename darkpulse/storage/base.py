"""Dual-collection storage: raw provenance plus normalized records."""

from __future__ import annotations

import json
import logging
import threading
from abc import ABC, abstractmethod
from pathlib import Path

from ..config import Settings
from ..models import NormalizedRecord, RawRecord

logger = logging.getLogger(__name__)


class BaseStore(ABC):
    """Interface for the raw/normalized record store.

    ``save_raw`` writes to raw_records (immutable provenance) and
    ``save_normalized`` to normalized_records; they are never mixed.
    """

    @abstractmethod
    def save_raw(self, record: RawRecord) -> str: ...

    @abstractmethod
    def save_normalized(self, record: NormalizedRecord) -> str: ...

    @abstractmethod
    def list_raw(
        self, source: str | None = None, limit: int | None = None
    ) -> list[RawRecord]: ...

    @abstractmethod
    def list_normalized(
        self, source: str | None = None, limit: int | None = None
    ) -> list[NormalizedRecord]: ...

    @abstractmethod
    def count_raw(self) -> int: ...

    @abstractmethod
    def count_normalized(self) -> int: ...

    @abstractmethod
    def clear(self) -> None: ...


class InMemoryStore(BaseStore):
    """Thread-safe in-memory store with optional JSON snapshot persistence."""

    def __init__(self, snapshot_dir: str | Path | None = None) -> None:
        self.snapshot_dir = Path(snapshot_dir) if snapshot_dir else None
        self._raw: dict[str, RawRecord] = {}
        self._normalized: dict[str, NormalizedRecord] = {}
        self._lock = threading.RLock()

    # -- raw ---------------------------------------------------------------
    def save_raw(self, record: RawRecord) -> str:
        with self._lock:
            self._raw[record.id] = record  # idempotent upsert
        return record.id

    def list_raw(
        self, source: str | None = None, limit: int | None = None
    ) -> list[RawRecord]:
        with self._lock:
            items = [
                record
                for record in self._raw.values()
                if source is None or record.source.value == source
            ]
        items.sort(key=lambda record: record.fetched_at, reverse=True)
        return _apply_limit(items, limit)

    def count_raw(self) -> int:
        with self._lock:
            return len(self._raw)

    # -- normalized --------------------------------------------------------
    def save_normalized(self, record: NormalizedRecord) -> str:
        with self._lock:
            self._normalized[record.id] = record
        return record.id

    def list_normalized(
        self, source: str | None = None, limit: int | None = None
    ) -> list[NormalizedRecord]:
        with self._lock:
            items = [
                record
                for record in self._normalized.values()
                if source is None or record.source.value == source
            ]
        items.sort(key=lambda record: record.ingested_at, reverse=True)
        return _apply_limit(items, limit)

    def count_normalized(self) -> int:
        with self._lock:
            return len(self._normalized)

    def clear(self) -> None:
        with self._lock:
            self._raw.clear()
            self._normalized.clear()

    # -- persistence -------------------------------------------------------
    def save_snapshot(self, path: str | Path) -> Path:
        """Persist both collections to a single JSON file."""
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            data = {
                "raw_records": [
                    record.model_dump(mode="json") for record in self._raw.values()
                ],
                "normalized_records": [
                    record.model_dump(mode="json")
                    for record in self._normalized.values()
                ],
            }
        target.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        logger.info("snapshot written: %s", target)
        return target

    @classmethod
    def load_snapshot(cls, path: str | Path) -> "InMemoryStore":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        store = cls()
        for item in data.get("raw_records", []):
            record = RawRecord.model_validate(item)
            store._raw[record.id] = record
        for item in data.get("normalized_records", []):
            record = NormalizedRecord.model_validate(item)
            store._normalized[record.id] = record
        logger.info(
            "snapshot loaded: %s (raw=%d normalized=%d)",
            path,
            len(store._raw),
            len(store._normalized),
        )
        return store


def _apply_limit(items: list, limit: int | None) -> list:
    if limit is None:
        return items
    return items[: max(limit, 0)]


def create_store(settings: Settings) -> BaseStore:
    """Return MongoDB when configured and reachable, otherwise in-memory."""
    if settings.mongo.enabled:
        from .mongo_store import MongoStore

        try:
            store = MongoStore(settings.mongo)
            store.connect()
            return store
        except Exception as exc:  # driver/connection errors vary by backend
            logger.error(
                "MongoDB unavailable (%s); falling back to in-memory store", exc
            )
    return InMemoryStore(snapshot_dir=settings.snapshot_dir)
