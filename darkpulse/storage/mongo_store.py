"""MongoDB backend for raw/normalized dual storage (optional dependency)."""

from __future__ import annotations

import logging
from typing import Any

from ..config import MongoConfig
from ..models import NormalizedRecord, RawRecord
from .base import BaseStore

logger = logging.getLogger(__name__)


class MongoStore(BaseStore):
    RAW = "raw_records"
    NORMALIZED = "normalized_records"

    def __init__(self, config: MongoConfig) -> None:
        self.config = config
        self._client: Any = None
        self._db: Any = None

    def connect(self) -> None:
        import pymongo

        self._client = pymongo.MongoClient(
            self.config.uri, serverSelectionTimeoutMS=4000
        )
        self._client.admin.command("ping")  # fail fast when unreachable
        self._db = self._client[self.config.database]
        self._db[self.RAW].create_index("id", unique=True)
        self._db[self.NORMALIZED].create_index("id", unique=True)
        self._db[self.NORMALIZED].create_index("source")
        logger.info(
            "connected to MongoDB at %s db=%s", self.config.uri, self.config.database
        )

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None
            self._db = None

    # -- raw ---------------------------------------------------------------
    def save_raw(self, record: RawRecord) -> str:
        self._db[self.RAW].replace_one(
            {"id": record.id}, record.model_dump(mode="json"), upsert=True
        )
        return record.id

    def list_raw(
        self, source: str | None = None, limit: int | None = None
    ) -> list[RawRecord]:
        query = {"source": source} if source else {}
        cursor = self._db[self.RAW].find(query).sort("fetched_at", -1)
        if limit is not None:
            cursor = cursor.limit(limit)
        return [RawRecord.model_validate(doc) for doc in cursor]

    def count_raw(self) -> int:
        return int(self._db[self.RAW].count_documents({}))

    # -- normalized --------------------------------------------------------
    def save_normalized(self, record: NormalizedRecord) -> str:
        self._db[self.NORMALIZED].replace_one(
            {"id": record.id}, record.model_dump(mode="json"), upsert=True
        )
        return record.id

    def list_normalized(
        self, source: str | None = None, limit: int | None = None
    ) -> list[NormalizedRecord]:
        query = {"source": source} if source else {}
        cursor = self._db[self.NORMALIZED].find(query).sort("ingested_at", -1)
        if limit is not None:
            cursor = cursor.limit(limit)
        return [NormalizedRecord.model_validate(doc) for doc in cursor]

    def count_normalized(self) -> int:
        return int(self._db[self.NORMALIZED].count_documents({}))

    def clear(self) -> None:
        self._db[self.RAW].delete_many({})
        self._db[self.NORMALIZED].delete_many({})
