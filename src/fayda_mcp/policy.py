"""Verification policy and permitted purposes/claims validation."""

from typing import List, Optional
from pydantic import BaseModel, Field
from fayda_mcp.exceptions import PolicyViolationError


class VerificationPolicy(BaseModel):
    """Enforces allowed purposes, checks, and claim scopes."""

    allowed_purposes: List[str] = Field(
        default_factory=lambda: ["onboarding", "kyc", "account_opening", "age_verification"],
        description="List of permitted business purposes",
    )
    allowed_checks: List[str] = Field(
        default_factory=lambda: ["identity_verified", "age_over_18"],
        description="List of permitted checks",
    )
    version: str = Field(default="v1", description="Policy version identifier")

    def validate_request(self, purpose: str, checks: List[str]) -> None:
        """Validate requested purpose and checks against policy."""
        if purpose not in self.allowed_purposes:
            raise PolicyViolationError(
                f"Purpose '{purpose}' is not permitted by policy. Allowed: {self.allowed_purposes}"
            )
        for check in checks:
            if check not in self.allowed_checks:
                raise PolicyViolationError(
                    f"Check '{check}' is not permitted by policy. Allowed: {self.allowed_checks}"
                )
