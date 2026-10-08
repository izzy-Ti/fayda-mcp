"""Verification policy and permitted purposes/claims validation backed by shared PredicateRegistry."""

from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, ConfigDict, Field
from fayda_mcp.exceptions import PolicyViolationError
from fayda_mcp.predicates import DEFAULT_PREDICATE_REGISTRY, PredicateRegistry

# Backward compatibility mappings dynamically generated from shared predicate registry
CHECK_SCOPE_MAPPING: Dict[str, List[str]] = {
    name: pred.required_scopes for name, pred in DEFAULT_PREDICATE_REGISTRY.all_predicates().items()
}

CHECK_CLAIM_MAPPING: Dict[str, List[str]] = {
    name: pred.required_claims for name, pred in DEFAULT_PREDICATE_REGISTRY.all_predicates().items()
}


class VerificationPolicy(BaseModel):
    """Enforces allowed purposes, checks, and claim scopes backed by shared predicate registry."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    allowed_purposes: List[str] = Field(
        default_factory=lambda: ["onboarding", "kyc", "account_opening", "age_verification"],
        description="List of permitted business purposes",
    )
    allowed_checks: List[str] = Field(
        default_factory=lambda: DEFAULT_PREDICATE_REGISTRY.supported_checks(),
        description="List of permitted checks",
    )
    registry: Optional[PredicateRegistry] = Field(
        default=None,
        description="Predicate registry instance (defaults to shared DEFAULT_PREDICATE_REGISTRY)",
    )
    version: str = Field(default="v1", description="Policy version identifier")
    evaluation_timezone: str = Field(
        default="Africa/Addis_Ababa",
        description="Host timezone for evaluation dates (default: Africa/Addis_Ababa)",
    )
    february_29_anniversary: str = Field(
        default="march_1",
        description="Anniversary rule for Feb 29 birthdates in common years ('march_1' or 'february_28')",
    )

    def get_registry(self) -> PredicateRegistry:
        """Return the active predicate registry."""
        return self.registry or DEFAULT_PREDICATE_REGISTRY

    def validate_request(self, purpose: str, checks: List[str]) -> None:
        """Validate requested purpose and checks against policy before state creation or redirect.

        Raises PolicyViolationError on any unsupported or empty purpose/check.
        Ensures policy acceptance and evaluation cannot diverge.
        """
        if not purpose or not purpose.strip():
            raise PolicyViolationError("Verification purpose must not be empty")

        if purpose not in self.allowed_purposes:
            raise PolicyViolationError(
                f"Unsupported purpose: '{purpose}'. Permitted purposes: {self.allowed_purposes}"
            )

        if not checks:
            raise PolicyViolationError("At least one verification check must be requested")

        reg = self.get_registry()
        for check in checks:
            if check not in self.allowed_checks:
                raise PolicyViolationError(
                    f"Unsupported check: '{check}'. Permitted checks: {self.allowed_checks}"
                )
            if not reg.is_supported(check):
                raise PolicyViolationError(
                    f"Unsupported check: '{check}'. Not registered in predicate registry"
                )

    def resolve_scopes_and_claims(self, checks: List[str]) -> Tuple[List[str], Dict[str, Any]]:
        """Resolve minimal OIDC scopes and essential claims needed for the requested checks using registry."""
        reg = self.get_registry()
        return reg.resolve_scopes_and_claims(checks)

