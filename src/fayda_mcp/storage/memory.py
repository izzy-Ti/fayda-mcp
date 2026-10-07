"""Thread-safe in-memory storage adapter implementing storage protocols."""

import asyncio
import time
from typing import Any, Dict, List, Optional, Tuple
from fayda_mcp.schemas import VerificationResult


class MemorySessionStore:
    """In-memory session store with TTL expiry and atomic consumption."""

    def __init__(self) -> None:
        self._sessions: Dict[str, Tuple[Dict[str, Any], float]] = {}
        self._lock = asyncio.Lock()

    async def save_session(self, state: str, data: Dict[str, Any], ttl_seconds: int = 600) -> None:
        async with self._lock:
            expires_at = time.time() + ttl_seconds
            self._sessions[state] = (dict(data), expires_at)

    async def consume_session(self, state: str) -> Optional[Dict[str, Any]]:
        """Atomically pop the session so state cannot be reused.

        Returns None if expired or already consumed.
        """
        async with self._lock:
            entry = self._sessions.pop(state, None)
            if entry is None:
                return None
            data, expires_at = entry
            if time.time() >= expires_at:
                return None
            return data

    async def get_session(self, state: str) -> Optional[Dict[str, Any]]:
        async with self._lock:
            entry = self._sessions.get(state)
            if entry is None:
                return None
            data, expires_at = entry
            if time.time() >= expires_at:
                self._sessions.pop(state, None)
                return None
            return dict(data)

    async def delete_session(self, state: str) -> bool:
        async with self._lock:
            return self._sessions.pop(state, None) is not None


class MemoryResultRepository:
    """In-memory verification request and result repository with idempotency and atomic finalization."""

    def __init__(self) -> None:
        self._requests: Dict[str, Tuple[Dict[str, Any], float]] = {}
        self._results: Dict[str, Tuple[VerificationResult, float]] = {}
        self._idempotency_index: Dict[Tuple[str, str, str], str] = {}
        self._lock = asyncio.Lock()

    async def save_request(self, request_id: str, data: Dict[str, Any], ttl_seconds: int = 900) -> None:
        async with self._lock:
            expires_at = time.time() + ttl_seconds
            req_copy = dict(data)
            self._requests[request_id] = (req_copy, expires_at)

            # Update idempotency index if keys exist
            tenant_id = req_copy.get("tenant_id")
            principal_id = req_copy.get("principal_id")
            idempotency_key = req_copy.get("idempotency_key")
            if tenant_id and principal_id and idempotency_key:
                self._idempotency_index[(str(tenant_id), str(principal_id), str(idempotency_key))] = request_id

    async def get_request(self, request_id: str) -> Optional[Dict[str, Any]]:
        async with self._lock:
            entry = self._requests.get(request_id)
            if entry is None:
                return None
            data, expires_at = entry
            if time.time() >= expires_at:
                self._requests.pop(request_id, None)
                return None
            return dict(data)

    async def find_by_idempotency_key(
        self, tenant_id: str, principal_id: str, idempotency_key: str
    ) -> Optional[Dict[str, Any]]:
        async with self._lock:
            key = (str(tenant_id), str(principal_id), str(idempotency_key))
            request_id = self._idempotency_index.get(key)
            if not request_id:
                return None

            entry = self._requests.get(request_id)
            if entry is None:
                self._idempotency_index.pop(key, None)
                return None
            data, expires_at = entry
            if time.time() >= expires_at:
                self._requests.pop(request_id, None)
                self._idempotency_index.pop(key, None)
                return None
            return dict(data)

    async def update_status(self, request_id: str, status: str) -> None:
        async with self._lock:
            entry = self._requests.get(request_id)
            if entry is not None:
                data, expires_at = entry
                data["status"] = status
                self._requests[request_id] = (data, expires_at)

    async def finalize_result(
        self, request_id: str, result: VerificationResult, ttl_seconds: int = 900
    ) -> bool:
        """Atomically finalize verification outcome.

        Returns True if transitioning from non-terminal state to result.status.
        Returns False if the request does not exist or has already been finalized.
        """
        async with self._lock:
            entry = self._requests.get(request_id)
            if entry is None:
                return False
            data, req_expires = entry

            # Terminal states that cannot be finalized twice
            terminal_states = {"verified", "rejected", "failed", "cancelled"}
            current_status = data.get("status")
            if current_status in terminal_states:
                return False

            # Atomically update request status and record final result
            data["status"] = result.status
            self._requests[request_id] = (data, req_expires)

            res_expires = time.time() + ttl_seconds
            self._results[request_id] = (result, res_expires)
            return True

    async def save_result(self, request_id: str, result: VerificationResult, ttl_seconds: int = 900) -> None:
        async with self._lock:
            expires_at = time.time() + ttl_seconds
            self._results[request_id] = (result, expires_at)
            entry = self._requests.get(request_id)
            if entry is not None:
                data, req_exp = entry
                data["status"] = result.status
                self._requests[request_id] = (data, req_exp)

    async def get_result(self, request_id: str) -> Optional[VerificationResult]:
        async with self._lock:
            entry = self._results.get(request_id)
            if entry is None:
                return None
            result, expires_at = entry
            if time.time() >= expires_at:
                self._results.pop(request_id, None)
                return None
            return result

    async def cleanup(self) -> int:
        """Purge expired requests and results. Returns count of purged records."""
        now = time.time()
        purged = 0
        async with self._lock:
            expired_reqs = [req_id for req_id, (_, exp) in self._requests.items() if now >= exp]
            for req_id in expired_reqs:
                self._requests.pop(req_id, None)
                purged += 1

            # Clean up idempotency index pointing to purged or missing requests
            stale_keys = [
                key for key, req_id in self._idempotency_index.items()
                if req_id not in self._requests
            ]
            for key in stale_keys:
                self._idempotency_index.pop(key, None)

            expired_results = [req_id for req_id, (_, exp) in self._results.items() if now >= exp]
            for req_id in expired_results:
                self._results.pop(req_id, None)
                purged += 1

        return purged

    async def close(self) -> None:
        """Lifecycle close: release resources."""
        async with self._lock:
            self._requests.clear()
            self._results.clear()
            self._idempotency_index.clear()


class MemoryAuditLogger:
    """In-memory safe audit trail."""

    def __init__(self) -> None:
        self._events: List[Dict[str, Any]] = []
        self._lock = asyncio.Lock()

    async def record_event(self, event_type: str, safe_metadata: Dict[str, Any]) -> None:
        async with self._lock:
            self._events.append(
                {
                    "event_type": event_type,
                    "metadata": dict(safe_metadata),
                    "timestamp": time.time(),
                }
            )

    async def get_events(self, request_id: Optional[str] = None) -> List[Dict[str, Any]]:
        async with self._lock:
            if request_id is None:
                return [dict(e) for e in self._events]
            return [
                dict(e)
                for e in self._events
                if e.get("metadata", {}).get("request_id") == request_id
            ]
