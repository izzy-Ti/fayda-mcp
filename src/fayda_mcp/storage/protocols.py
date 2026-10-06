"""Storage protocols for OIDC sessions, verification requests, and results."""

from typing import Any, Dict, Optional, Protocol, runtime_checkable
from fayda_mcp.schemas import VerificationResult


@runtime_checkable
class SessionStore(Protocol):
    """Stores temporary OIDC state, nonce, and PKCE verifier."""

    async def save_session(self, state: str, data: Dict[str, Any], ttl_seconds: int) -> None:
        """Store OIDC session data keyed by state with a TTL."""
        ...

    async def consume_session(self, state: str) -> Optional[Dict[str, Any]]:
        """Atomically consume and delete session data once. Returns None if already consumed/expired."""
        ...

    async def get_session(self, state: str) -> Optional[Dict[str, Any]]:
        """Read session data without consuming (for status inspection)."""
        ...


@runtime_checkable
class ResultRepository(Protocol):
    """Durable store for verification requests and minimal evaluated results."""

    async def save_request(self, request_id: str, data: Dict[str, Any], ttl_seconds: int) -> None:
        """Create or update verification request record."""
        ...

    async def get_request(self, request_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve verification request record by ID."""
        ...

    async def update_status(self, request_id: str, status: str) -> None:
        """Update request status (pending, processing, verified, rejected, etc.)."""
        ...

    async def save_result(self, request_id: str, result: VerificationResult, ttl_seconds: int) -> None:
        """Store final evaluated verification result."""
        ...

    async def get_result(self, request_id: str) -> Optional[VerificationResult]:
        """Retrieve final evaluated verification result."""
        ...


@runtime_checkable
class AuditLogger(Protocol):
    """Safe audit trail recorder without PII or credentials."""

    async def record_event(self, event_type: str, safe_metadata: Dict[str, Any]) -> None:
        """Append safe audit log record."""
        ...
