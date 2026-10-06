"""Schemas for verification requests and status."""

from typing import List, Literal
from pydantic import BaseModel, Field


VerificationStatusType = Literal[
    "pending",
    "processing",
    "verified",
    "rejected",
    "failed",
    "expired",
    "cancelled",
]


class StartVerificationInput(BaseModel):
    """Input parameters for start_verification MCP tool."""

    purpose: str = Field(..., description="Business purpose for verification (e.g., account_opening)")
    checks: List[str] = Field(..., description="List of requested identity checks (e.g., ['identity_verified', 'age_over_18'])")
    application_user_ref: str = Field(..., description="Opaque application user reference")
    idempotency_key: str = Field(..., description="Unique caller idempotency key")


class StartVerificationResponse(BaseModel):
    """Output for start_verification."""

    request_id: str = Field(..., description="Opaque verification request ID")
    verification_url: str = Field(..., description="Short-lived verification link for the user")
    expires_at: str = Field(..., description="ISO 8601 timestamp when link expires")


class VerificationStatusResponse(BaseModel):
    """Output for get_verification_status."""

    request_id: str = Field(..., description="Verification request ID")
    status: VerificationStatusType = Field(..., description="Current request status")


class CancelVerificationResponse(BaseModel):
    """Output for cancel_verification."""

    request_id: str = Field(..., description="Verification request ID")
    status: Literal["cancelled"] = Field(..., description="Cancelled status")
