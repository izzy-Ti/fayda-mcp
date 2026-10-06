"""Permission checks for tenants, tools, and verification purposes."""

from typing import List
from app.core.errors import AuthorizationError, PolicyViolationError
from app.core.auth import Principal


def require_scope(principal: Principal, required_scope: str) -> None:
    """Ensure the principal holds the required OAuth scope."""
    if required_scope not in principal.scopes:
        raise AuthorizationError(f"Missing required scope: {required_scope}")


def validate_purpose_allowed(tenant_id: str, purpose: str, allowed_purposes: List[str]) -> None:
    """Validate that the requested purpose is allowed by tenant policy."""
    if purpose not in allowed_purposes:
        raise PolicyViolationError(f"Purpose '{purpose}' is not authorized for tenant '{tenant_id}'")
