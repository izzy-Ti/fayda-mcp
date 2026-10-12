"""Storage protocols for OIDC sessions, verification requests, and results."""

from typing import Any, Dict, List, Optional, Protocol, Tuple, runtime_checkable
from fayda_mcp.schemas import VerificationResult


@runtime_checkable
class SessionStore(Protocol):
    """Stores temporary OIDC state, nonce, and PKCE verifier."""

    async def save_session(self, state: str, data: Dict[str, Any], ttl_seconds: int) -> None:
        """Store OIDC session data keyed by state with a TTL."""
        ...

    async def consume_session(self, state: str) -> Optional[Dict[str, Any]]:
        """Atomically consume and delete session data once.

        Returns session data on first call. Returns None if already consumed,
        nonexistent, or expired.
        """
        ...

    async def get_session(self, state: str) -> Optional[Dict[str, Any]]:
        """Read session data without consuming (for status inspection)."""
        ...

    async def delete_session(self, state: str) -> bool:
        """Explicitly delete a session. Returns True if deleted."""
        ...

    async def close(self) -> None:
        """Close underlying connection pools and resources."""
        ...


@runtime_checkable
class ResultRepository(Protocol):
    """Durable store for verification requests and minimal evaluated results."""

    async def save_request(self, request_id: str, data: Dict[str, Any], ttl_seconds: int) -> None:
        """Create or update verification request record."""
        ...

    async def reserve_request(
        self, request_id: str, data: Dict[str, Any], ttl_seconds: int
    ) -> Tuple[bool, Dict[str, Any]]:
        """Atomically reserve a request using unique insert.

        Returns (True, data) if successfully reserved.
        Returns (False, existing_record) if a request with the same idempotency key already exists.
        """
        ...

    async def get_request(self, request_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve verification request record by ID. Returns None if expired or not found."""
        ...

    async def find_by_idempotency_key(
        self, tenant_id: str, principal_id: str, idempotency_key: str
    ) -> Optional[Dict[str, Any]]:
        """Retrieve existing request matching tenant, principal, and caller idempotency key."""
        ...

    async def update_status(self, request_id: str, status: str) -> None:
        """Update request status (pending, processing, cancelled, etc.)."""
        ...

    async def finalize_result(
        self,
        request_id: str,
        result: Union[VerificationResult, Any],
        ttl_seconds: int,
        audit_event: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Atomically finalize verification outcome.

        Returns True if this invocation successfully transitions and finalizes the
        request; returns False if the request has already been finalized.
        Prevents concurrent callbacks from finalizing twice.
        """
        ...

    async def save_result(self, request_id: str, result: Union[VerificationResult, Any], ttl_seconds: int) -> None:
        """Store final evaluated verification result."""
        ...

    async def get_result(self, request_id: str) -> Optional[VerificationResult]:
        """Retrieve final evaluated verification result."""
        ...

    async def cleanup(self) -> int:
        """Purge expired requests and results according to retention timestamps. Returns count of purged records."""
        ...

    async def close(self) -> None:
        """Close underlying connection pools and resources."""
        ...


@runtime_checkable
class AuditLogger(Protocol):
    """Safe audit trail recorder without PII or credentials."""

    async def record_event(self, event_type: str, safe_metadata: Dict[str, Any]) -> None:
        """Append safe audit log record."""
        ...

    async def get_events(self, request_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve recorded audit events, optionally filtered by request_id."""
        ...
