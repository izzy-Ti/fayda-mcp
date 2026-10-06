"""Safe domain errors and error mappings for Fayda MCP Bridge."""

from typing import Any, Dict, Optional


class BridgeError(Exception):
    """Base class for all bridge domain errors."""

    def __init__(
        self,
        message: str,
        code: str = "internal_error",
        status_code: int = 500,
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert error to a safe client response payload without leaking secrets."""
        return {
            "error": self.code,
            "message": self.message,
            "details": self.details,
        }


class AuthenticationError(BridgeError):
    """Raised when authentication credentials or token validation fails."""

    def __init__(self, message: str = "Invalid or expired authentication credentials", details: Optional[Dict[str, Any]] = None):
        super().__init__(message=message, code="unauthenticated", status_code=401, details=details)


class AuthorizationError(BridgeError):
    """Raised when access to a resource, tool, or tenant is denied."""

    def __init__(self, message: str = "Access denied", details: Optional[Dict[str, Any]] = None):
        super().__init__(message=message, code="forbidden", status_code=403, details=details)


class TenantNotFoundError(BridgeError):
    """Raised when the requested tenant does not exist."""

    def __init__(self, message: str = "Tenant not found", details: Optional[Dict[str, Any]] = None):
        super().__init__(message=message, code="tenant_not_found", status_code=404, details=details)


class VerificationNotFoundError(BridgeError):
    """Raised when a verification request cannot be found."""

    def __init__(self, message: str = "Verification request not found", details: Optional[Dict[str, Any]] = None):
        super().__init__(message=message, code="verification_not_found", status_code=404, details=details)


class PolicyViolationError(BridgeError):
    """Raised when a request violates configured tenant policy or claim scopes."""

    def __init__(self, message: str = "Requested purpose or checks violate tenant policy", details: Optional[Dict[str, Any]] = None):
        super().__init__(message=message, code="policy_violation", status_code=400, details=details)


class ProviderCommunicationError(BridgeError):
    """Raised when external provider communication fails or times out."""

    def __init__(self, message: str = "Provider communication failed", details: Optional[Dict[str, Any]] = None):
        super().__init__(message=message, code="provider_unavailable", status_code=502, details=details)


class InvalidStateError(BridgeError):
    """Raised when state, nonce, or PKCE verifier mismatch or expire."""

    def __init__(self, message: str = "Invalid or expired verification session", details: Optional[Dict[str, Any]] = None):
        super().__init__(message=message, code="invalid_state", status_code=400, details=details)
