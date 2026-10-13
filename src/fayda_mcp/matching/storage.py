"""Storage contracts and adapters for temporary expected identity details."""

from datetime import datetime, timezone
import json
from typing import Any, Dict, Optional, Protocol, runtime_checkable
from fayda_mcp.matching.schemas import ExpectedDetailsRecord
from fayda_mcp.storage.protocols import SessionStore


@runtime_checkable
class ExpectedDetailsStore(Protocol):
    """Storage contract for temporary expected details records."""

    async def save_expected_details(
        self,
        ref: str,
        record: ExpectedDetailsRecord,
        ttl_seconds: int,
    ) -> None:
        """Store an expected details record with an expiration TTL."""
        ...

    async def get_expected_details(
        self,
        ref: str,
    ) -> Optional[ExpectedDetailsRecord]:
        """Retrieve an expected details record by opaque reference."""
        ...

    async def delete_expected_details(
        self,
        ref: str,
    ) -> bool:
        """Delete an expected details record. Returns True if deleted."""
        ...

    async def close(self) -> None:
        """Close underlying connection pools and resources."""
        ...


class MemoryExpectedDetailsStore:
    """In-memory reference implementation of ExpectedDetailsStore with TTL expiration."""

    def __init__(self) -> None:
        self._records: Dict[str, Dict[str, Any]] = {}

    async def save_expected_details(
        self,
        ref: str,
        record: ExpectedDetailsRecord,
        ttl_seconds: int,
    ) -> None:
        raw = record.model_dump()
        self._records[ref] = raw

    async def get_expected_details(
        self,
        ref: str,
    ) -> Optional[ExpectedDetailsRecord]:
        raw = self._records.get(ref)
        if not raw:
            return None
        return ExpectedDetailsRecord(**raw)

    async def delete_expected_details(
        self,
        ref: str,
    ) -> bool:
        return self._records.pop(ref, None) is not None

    async def close(self) -> None:
        self._records.clear()


class SessionExpectedDetailsStore:
    """Adapts any SessionStore (e.g. RedisSessionStore, MemorySessionStore) to ExpectedDetailsStore."""

    def __init__(self, session_store: SessionStore, prefix: str = "edr:") -> None:
        self._session_store = session_store
        self._prefix = prefix

    def _key(self, ref: str) -> str:
        return f"{self._prefix}{ref}"

    async def save_expected_details(
        self,
        ref: str,
        record: ExpectedDetailsRecord,
        ttl_seconds: int,
    ) -> None:
        data = record.model_dump()
        await self._session_store.save_session(self._key(ref), data, ttl_seconds)

    async def get_expected_details(
        self,
        ref: str,
    ) -> Optional[ExpectedDetailsRecord]:
        data = await self._session_store.get_session(self._key(ref))
        if not data:
            return None
        return ExpectedDetailsRecord(**data)

    async def delete_expected_details(
        self,
        ref: str,
    ) -> bool:
        return await self._session_store.delete_session(self._key(ref))

    async def close(self) -> None:
        await self._session_store.close()
