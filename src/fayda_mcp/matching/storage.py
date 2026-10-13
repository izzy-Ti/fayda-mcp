"""Storage contracts and adapters for temporary expected identity details.

Enforces encryption at rest for retained details and short TTL expiration semantics.
"""

from datetime import datetime, timezone
import time
from typing import Any, Dict, Optional, Protocol, runtime_checkable

from fayda_mcp.matching.crypto import DetailsEncryptor
from fayda_mcp.matching.schemas import ExpectedDetails, ExpectedDetailsRecord
from fayda_mcp.storage.protocols import SessionStore


@runtime_checkable
class ExpectedDetailsStore(Protocol):
    """Storage contract for temporary expected details records with encryption and TTL."""

    async def save_expected_details(
        self,
        ref: str,
        record: ExpectedDetailsRecord,
        ttl_seconds: int,
    ) -> None:
        """Store an expected details record with an expiration TTL, encrypting details at rest."""
        ...

    async def get_expected_details(
        self,
        ref: str,
    ) -> Optional[ExpectedDetailsRecord]:
        """Retrieve and decrypt an expected details record by opaque reference."""
        ...

    async def delete_expected_details(
        self,
        ref: str,
    ) -> bool:
        """Delete an expected details record. Returns True if deleted."""
        ...

    async def get_ref_by_request_id(
        self,
        request_id: str,
    ) -> Optional[str]:
        """Retrieve bound expected_details_ref by verification request_id."""
        ...

    async def close(self) -> None:
        """Close underlying connection pools and resources."""
        ...


class MemoryExpectedDetailsStore:
    """In-memory reference implementation of ExpectedDetailsStore with encryption and TTL."""

    def __init__(self, encryptor: Optional[DetailsEncryptor] = None) -> None:
        self.encryptor = encryptor or DetailsEncryptor()
        self._records: Dict[str, Dict[str, Any]] = {}
        self._expirations: Dict[str, float] = {}
        self._request_index: Dict[str, str] = {}

    async def save_expected_details(
        self,
        ref: str,
        record: ExpectedDetailsRecord,
        ttl_seconds: int,
    ) -> None:
        raw = record.model_dump()
        # Encrypt retained citizen details before persisting
        if record.expected_details is not None:
            raw["encrypted_details"] = self.encryptor.encrypt_details(record.expected_details)
            raw["expected_details"] = None

        self._records[ref] = raw
        self._expirations[ref] = time.time() + max(1, ttl_seconds)

        if record.bound_request_id:
            self._request_index[record.bound_request_id] = ref

    async def get_expected_details(
        self,
        ref: str,
    ) -> Optional[ExpectedDetailsRecord]:
        raw = self._records.get(ref)
        if not raw:
            return None

        # Check in-memory TTL expiration
        expiry_ts = self._expirations.get(ref, 0)
        if expiry_ts and time.time() >= expiry_ts:
            await self.delete_expected_details(ref)
            return None

        # Decrypt retained details if encrypted
        data = dict(raw)
        enc_blob = data.get("encrypted_details")
        if enc_blob:
            decrypted = self.encryptor.decrypt_details(enc_blob)
            data["expected_details"] = decrypted

        return ExpectedDetailsRecord(**data)

    async def delete_expected_details(
        self,
        ref: str,
    ) -> bool:
        self._expirations.pop(ref, None)
        raw = self._records.pop(ref, None)
        if raw and raw.get("bound_request_id"):
            self._request_index.pop(raw["bound_request_id"], None)
        return raw is not None

    async def get_ref_by_request_id(
        self,
        request_id: str,
    ) -> Optional[str]:
        ref = self._request_index.get(request_id)
        if not ref:
            return None

        expiry_ts = self._expirations.get(ref, 0)
        if expiry_ts and time.time() >= expiry_ts:
            await self.delete_expected_details(ref)
            return None
        return ref

    async def close(self) -> None:
        self._records.clear()
        self._expirations.clear()
        self._request_index.clear()


class SessionExpectedDetailsStore:
    """Adapts any SessionStore (e.g. RedisSessionStore, MemorySessionStore) with encryption and TTL."""

    def __init__(
        self,
        session_store: SessionStore,
        prefix: str = "edr:",
        encryptor: Optional[DetailsEncryptor] = None,
    ) -> None:
        self._session_store = session_store
        self._prefix = prefix
        self.encryptor = encryptor or DetailsEncryptor()

    def _key(self, ref: str) -> str:
        return f"{self._prefix}{ref}"

    def _req_key(self, request_id: str) -> str:
        return f"{self._prefix}req:{request_id}"

    async def save_expected_details(
        self,
        ref: str,
        record: ExpectedDetailsRecord,
        ttl_seconds: int,
    ) -> None:
        data = record.model_dump()
        # Encrypt retained citizen details before persisting
        if record.expected_details is not None:
            data["encrypted_details"] = self.encryptor.encrypt_details(record.expected_details)
            data["expected_details"] = None

        await self._session_store.save_session(self._key(ref), data, ttl_seconds)

        if record.bound_request_id:
            await self._session_store.save_session(
                self._req_key(record.bound_request_id),
                {"ref": ref},
                ttl_seconds,
            )

    async def get_expected_details(
        self,
        ref: str,
    ) -> Optional[ExpectedDetailsRecord]:
        data = await self._session_store.get_session(self._key(ref))
        if not data:
            return None

        # Decrypt retained details if encrypted
        record_data = dict(data)
        enc_blob = record_data.get("encrypted_details")
        if enc_blob:
            decrypted = self.encryptor.decrypt_details(enc_blob)
            record_data["expected_details"] = decrypted

        return ExpectedDetailsRecord(**record_data)

    async def delete_expected_details(
        self,
        ref: str,
    ) -> bool:
        # Check if record has bound_request_id to clean up reverse index
        data = await self._session_store.get_session(self._key(ref))
        if data and data.get("bound_request_id"):
            await self._session_store.delete_session(self._req_key(data["bound_request_id"]))

        return await self._session_store.delete_session(self._key(ref))

    async def get_ref_by_request_id(
        self,
        request_id: str,
    ) -> Optional[str]:
        data = await self._session_store.get_session(self._req_key(request_id))
        if not data or not data.get("ref"):
            return None
        return str(data["ref"])

    async def close(self) -> None:
        await self._session_store.close()
