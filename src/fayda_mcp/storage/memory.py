"""In-memory storage adapters for development, demos, and testing."""

import asyncio
from typing import Any, Dict, List, Optional
from fayda_mcp.schemas import VerificationResult


class MemorySessionStore:
    """Thread-safe in-memory OIDC session store with atomic consumption."""

    def __init__(self) -> None:
        self._sessions: Dict[str, Dict[str, Any]] = {}
        self._lock = asyncio.Lock()

    async def save_session(self, state: str, data: Dict[str, Any], ttl_seconds: int = 600) -> None:
        async with self._lock:
            self._sessions[state] = dict(data)

    async def consume_session(self, state: str) -> Optional[Dict[str, Any]]:
        """Atomically pop the session so state cannot be reused."""
        async with self._lock:
            return self._sessions.pop(state, None)

    async def get_session(self, state: str) -> Optional[Dict[str, Any]]:
        async with self._lock:
            val = self._sessions.get(state)
            return dict(val) if val else None


class MemoryResultRepository:
    """In-memory verification request and result repository."""

    def __init__(self) -> None:
        self._requests: Dict[str, Dict[str, Any]] = {}
        self._results: Dict[str, VerificationResult] = {}
        self._lock = asyncio.Lock()

    async def save_request(self, request_id: str, data: Dict[str, Any], ttl_seconds: int = 900) -> None:
        async with self._lock:
            self._requests[request_id] = dict(data)

    async def get_request(self, request_id: str) -> Optional[Dict[str, Any]]:
        async with self._lock:
            val = self._requests.get(request_id)
            return dict(val) if val else None

    async def update_status(self, request_id: str, status: str) -> None:
        async with self._lock:
            if request_id in self._requests:
                self._requests[request_id]["status"] = status

    async def save_result(self, request_id: str, result: VerificationResult, ttl_seconds: int = 900) -> None:
        async with self._lock:
            self._results[request_id] = result
            if request_id in self._requests:
                self._requests[request_id]["status"] = result.status

    async def get_result(self, request_id: str) -> Optional[VerificationResult]:
        async with self._lock:
            return self._results.get(request_id)


class MemoryAuditLogger:
    """In-memory audit logger."""

    def __init__(self) -> None:
        self.events: List[Dict[str, Any]] = []
        self._lock = asyncio.Lock()

    async def record_event(self, event_type: str, safe_metadata: Dict[str, Any]) -> None:
        async with self._lock:
            self.events.append({"event_type": event_type, "metadata": dict(safe_metadata)})
