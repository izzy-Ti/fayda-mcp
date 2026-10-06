"""Schemas for verification results."""

from typing import Dict, Optional
from pydantic import BaseModel, Field


class VerificationResultResponse(BaseModel):
    """Output for get_verification_result."""

    request_id: str = Field(..., description="Verification request ID")
    status: str = Field(..., description="Verification outcome status")
    checks: Dict[str, bool] = Field(default_factory=dict, description="Evaluated minimal check outcomes")
    verified_at: Optional[str] = Field(None, description="ISO 8601 timestamp of verification")
    expires_at: Optional[str] = Field(None, description="ISO 8601 timestamp when result expires")
    evidence_ref: Optional[str] = Field(None, description="Opaque audit evidence reference")
    policy_version: Optional[str] = Field(None, description="Version of the evaluated policy")
