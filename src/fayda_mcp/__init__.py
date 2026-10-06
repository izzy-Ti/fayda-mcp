"""Fayda MCP Python Library.

Importable package providing Model Context Protocol (MCP) tools and reusable
identity-verification services for Ethiopian National ID (Fayda eSignet).
"""

from fayda_mcp.config import FaydaConfig
from fayda_mcp.context import (
    CallerAuthorizationAdapter,
    CallerContext,
    SimpleCallerAdapter,
)
from fayda_mcp.exceptions import (
    AuthenticationError,
    AuthorizationError,
    ConfigurationError,
    FaydaMCPError,
    InvalidStateError,
    PolicyViolationError,
    ProviderError,
    StateConsumedError,
    TokenValidationError,
    VerificationNotFoundError,
)
from fayda_mcp.policy import VerificationPolicy
from fayda_mcp.schemas import (
    CancelVerificationResponse,
    StartVerificationRequest,
    StartVerificationResponse,
    VerificationResult,
    VerificationStatusResponse,
)
from fayda_mcp.service import FaydaVerificationService
from fayda_mcp.mcp.factory import create_mcp_server

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "FaydaConfig",
    "CallerContext",
    "CallerAuthorizationAdapter",
    "SimpleCallerAdapter",
    "FaydaMCPError",
    "ConfigurationError",
    "AuthenticationError",
    "AuthorizationError",
    "InvalidStateError",
    "StateConsumedError",
    "PolicyViolationError",
    "ProviderError",
    "TokenValidationError",
    "VerificationNotFoundError",
    "VerificationPolicy",
    "StartVerificationRequest",
    "StartVerificationResponse",
    "VerificationStatusResponse",
    "VerificationResult",
    "CancelVerificationResponse",
    "FaydaVerificationService",
    "create_mcp_server",
]
