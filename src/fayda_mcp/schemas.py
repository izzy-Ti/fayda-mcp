"""Public request and result schemas for Fayda MCP verification."""

from typing import Dict, List, Literal, Optional
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


class StartVerificationRequest(BaseModel):
    """Input payload to initiate an identity verification."""

    purpose: str = Field(..., description="Business purpose (e.g., 'onboarding', 'kyc')")
    checks: List[str] = Field(..., description="Requested checks (e.g., ['identity_verified', 'age_over_18'])")
    application_user_ref: str = Field(..., description="Opaque application user reference")
    idempotency_key: str = Field(..., description="Unique caller idempotency key")


class StartVerificationResponse(BaseModel):
    """Returned when verification is successfully initiated."""

    request_id: str = Field(..., description="Unique verification request identifier")
    authorization_url: str = Field(..., description="Fayda eSignet authorization URL for the user")
    expires_at: str = Field(..., description="ISO 8601 expiry timestamp")


class VerificationStatusResponse(BaseModel):
    """Current status of a verification request."""

    request_id: str = Field(..., description="Verification request identifier")
    status: VerificationStatusType = Field(..., description="Current status")


class VerificationResult(BaseModel):
    """Final minimal verification result with boolean predicates."""

    request_id: str = Field(..., description="Verification request identifier")
    status: str = Field(..., description="Final outcome status ('verified', 'rejected', etc.)")
    checks: Dict[str, bool] = Field(default_factory=dict, description="Boolean outcomes of evaluated checks")
    verified_at: Optional[str] = Field(None, description="ISO 8601 timestamp when verification completed")
    expires_at: Optional[str] = Field(None, description="ISO 8601 timestamp when result expires")
    evidence_ref: Optional[str] = Field(None, description="Opaque reference to safe audit log record")
    policy_version: Optional[str] = Field(None, description="Evaluated policy version")


class CancelVerificationResponse(BaseModel):
    """Outcome of cancelling a verification request."""

    request_id: str = Field(..., description="Verification request identifier")
    status: Literal["cancelled"] = Field(default="cancelled")
