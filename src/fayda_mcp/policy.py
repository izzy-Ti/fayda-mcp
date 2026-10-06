"""Verification policy and permitted purposes/claims validation."""

from typing import Any, Dict, List, Set, Tuple
from pydantic import BaseModel, Field
from fayda_mcp.exceptions import PolicyViolationError

CHECK_SCOPE_MAPPING: Dict[str, List[str]] = {
    "identity_verified": ["openid"],
    "age_over_18": ["openid", "profile"],
}

CHECK_CLAIM_MAPPING: Dict[str, List[str]] = {
    "identity_verified": ["sub"],
    "age_over_18": ["birthdate"],
}


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
        """Validate requested purpose and checks against policy before redirect.

        Raises PolicyViolationError on any unsupported or empty purpose/check.
        """
        if not purpose or not purpose.strip():
            raise PolicyViolationError("Verification purpose must not be empty")

        if purpose not in self.allowed_purposes:
            raise PolicyViolationError(
                f"Unsupported purpose: '{purpose}'. Permitted purposes: {self.allowed_purposes}"
            )

        if not checks:
            raise PolicyViolationError("At least one verification check must be requested")

        for check in checks:
            if check not in self.allowed_checks:
                raise PolicyViolationError(
                    f"Unsupported check: '{check}'. Permitted checks: {self.allowed_checks}"
                )

    def resolve_scopes_and_claims(self, checks: List[str]) -> Tuple[List[str], Dict[str, Any]]:
        """Resolve minimal OIDC scopes and essential claims needed for the requested checks."""
        scopes: Set[str] = {"openid"}
        userinfo_claims: Dict[str, Any] = {}

        for check in checks:
            for s in CHECK_SCOPE_MAPPING.get(check, []):
                scopes.add(s)
            for claim_name in CHECK_CLAIM_MAPPING.get(check, []):
                userinfo_claims[claim_name] = {"essential": True}

        claims_param = {"userinfo": userinfo_claims} if userinfo_claims else {}
        return sorted(list(scopes)), claims_param
