"""Public request and result schemas for Fayda MCP verification."""

from typing import Dict, List, Literal, Optional, Union
from pydantic import BaseModel, ConfigDict, Field

VerificationStatusType = Literal[
    "pending",
    "processing",
    "verified",
    "rejected",
    "failed",
    "expired",
    "cancelled",
    "incomplete",
]

CheckOutcomeType = Union[bool, Literal["unavailable"], None]


class StartVerificationRequest(BaseModel):
    """Input payload to initiate an identity verification."""

    model_config = ConfigDict(extra="forbid")

    purpose: str = Field(..., description="Business purpose (e.g., 'onboarding', 'kyc')")
    checks: List[str] = Field(..., description="Requested checks (e.g., ['identity_verified', 'age_over_18'])")
    optional_checks: Optional[List[str]] = Field(
        default=None,
        description="Optional checks that do not block policy completion if unavailable",
    )
    application_user_ref: str = Field(..., description="Opaque application user reference")
    idempotency_key: str = Field(..., description="Unique caller idempotency key")


class StartVerificationResponse(BaseModel):
    """Returned when verification is successfully initiated."""

    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(..., description="Unique verification request identifier")
    authorization_url: str = Field(..., description="Fayda eSignet authorization URL for the user")
    expires_at: str = Field(..., description="ISO 8601 expiry timestamp")


class VerificationStatusResponse(BaseModel):
    """Current status of a verification request."""

    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(..., description="Verification request identifier")
    status: VerificationStatusType = Field(..., description="Current status")


class VerificationResult(BaseModel):
    """Final minimal verification result with boolean predicates.

    Strictly forbids demographic payloads, raw tokens, or biometric data.
    """

    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(..., description="Verification request identifier")
    status: str = Field(
        ...,
        description="Final outcome status ('verified', 'rejected', 'incomplete', 'failed', etc.)",
    )
    checks: Dict[str, CheckOutcomeType] = Field(
        default_factory=dict,
        description="Outcomes of evaluated checks: True, False, or null/'unavailable'",
    )
    reasons: Dict[str, str] = Field(
        default_factory=dict,
        description="Safe reason codes for unavailable checks (e.g. {'phone_verified': 'provider_claim_unavailable'})",
    )
    verified_at: Optional[str] = Field(default=None, description="ISO 8601 timestamp when verification completed")
    expires_at: Optional[str] = Field(default=None, description="ISO 8601 timestamp when result expires")
    evidence_ref: Optional[str] = Field(default=None, description="Opaque reference to safe audit log record")
    policy_version: Optional[str] = Field(default=None, description="Evaluated policy version")


class CancelVerificationResponse(BaseModel):
    """Outcome of cancelling a verification request."""

    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(..., description="Verification request identifier")
    status: Literal["cancelled"] = Field(default="cancelled")

