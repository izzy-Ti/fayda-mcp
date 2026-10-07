"""Typed domain exceptions for Fayda MCP."""

from typing import Any, Dict, Optional


class FaydaMCPError(Exception):
    """Base exception for all Fayda MCP errors."""

    def __init__(
        self,
        message: str,
        code: str = "fayda_mcp_error",
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert error to a safe representation without leaking secrets."""
        return {
            "error": self.code,
            "message": self.message,
            "details": self.details,
        }


class ConfigurationError(FaydaMCPError):
    """Raised when configuration is missing or invalid."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message=message, code="configuration_error", details=details)


class AuthenticationError(FaydaMCPError):
    """Raised when authentication credentials or token validation fails."""

    def __init__(self, message: str = "Authentication failed", details: Optional[Dict[str, Any]] = None):
        super().__init__(message=message, code="authentication_error", details=details)


class AuthorizationError(FaydaMCPError):
    """Raised when caller lacks required permissions or scopes."""

    def __init__(self, message: str = "Access denied", details: Optional[Dict[str, Any]] = None):
        super().__init__(message=message, code="forbidden", details=details)


class VerificationNotFoundError(FaydaMCPError):
    """Raised when a verification request cannot be located."""

    def __init__(self, message: str = "Verification request not found", details: Optional[Dict[str, Any]] = None):
        super().__init__(message=message, code="verification_not_found", details=details)


class InvalidStateError(FaydaMCPError):
    """Raised when OIDC state is missing, expired, or invalid."""

    def __init__(self, message: str = "Invalid or expired verification session", details: Optional[Dict[str, Any]] = None):
        super().__init__(message=message, code="invalid_state", details=details)


class StateConsumedError(InvalidStateError):
    """Raised when OIDC state has already been consumed (replay prevention)."""

    def __init__(self, message: str = "Verification session has already been used", details: Optional[Dict[str, Any]] = None):
        super().__init__(message=message, details=details)
        self.code = "state_consumed"


class PolicyViolationError(FaydaMCPError):
    """Raised when requested checks or purpose violate tenant policy."""

    def __init__(self, message: str = "Verification violates configured policy", details: Optional[Dict[str, Any]] = None):
        super().__init__(message=message, code="policy_violation", details=details)


class ProviderError(FaydaMCPError):
    """Raised when communication with Fayda eSignet fails."""

    def __init__(self, message: str = "Fayda eSignet provider error", details: Optional[Dict[str, Any]] = None):
        super().__init__(message=message, code="provider_error", details=details)


class TokenValidationError(FaydaMCPError):
    """Raised when ID token or UserInfo JWT validation fails."""

    def __init__(self, message: str = "Token validation failed", details: Optional[Dict[str, Any]] = None):
        super().__init__(message=message, code="token_validation_error", details=details)


class IdempotencyConflictError(FaydaMCPError):
    """Raised when an idempotency key is reused with different request parameters."""

    def __init__(
        self,
        message: str = "Idempotency key has already been used with different parameters",
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message=message, code="idempotency_conflict", details=details)
