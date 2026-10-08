"""Verification policy and permitted purposes/claims validation backed by shared PredicateRegistry."""

from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union
from pydantic import BaseModel, ConfigDict, Field, model_validator
from fayda_mcp.exceptions import PolicyViolationError
from fayda_mcp.predicates import (
    DEFAULT_PREDICATE_REGISTRY,
    AgeThresholdRule,
    PredicateRegistry,
    parse_age_check,
)

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
    # Host-approved age threshold bounds
    min_age_threshold: int = Field(default=1, description="Host-approved minimum age threshold")
    max_age_threshold: int = Field(default=120, description="Host-approved maximum age threshold")
    purpose_age_thresholds: Dict[str, Union[Tuple[int, int], List[int]]] = Field(
        default_factory=dict,
        description="Per-purpose allowed age thresholds (range tuple or explicit list)",
    )

    @model_validator(mode="after")
    def populate_purpose_allowlist(self) -> "VerificationPolicy":
        """Ensure purposes configured with age thresholds are admitted to allowed_purposes."""
        if self.purpose_age_thresholds:
            for p in self.purpose_age_thresholds.keys():
                if p not in self.allowed_purposes:
                    self.allowed_purposes.append(p)
        return self

    def get_registry(self) -> PredicateRegistry:
        """Return the active predicate registry."""
        return self.registry or DEFAULT_PREDICATE_REGISTRY

    def validate_request(
        self,
        purpose: str,
        checks: Sequence[Union[str, AgeThresholdRule]],
    ) -> List[str]:
        """Validate requested purpose and checks against policy before state creation or redirect.

        Rejects negative, decimal, malformed, enormous, and disallowed thresholds.
        Ensures policy acceptance and evaluation cannot diverge.
        Returns list of resolved canonical check names.
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
        resolved_checks: List[str] = []

        for raw_check in checks:
            check_str = (
                raw_check.check_name
                if isinstance(raw_check, AgeThresholdRule)
                else str(raw_check)
            )

            # Check if this is an age predicate
            parsed_age = parse_age_check(
                check_str,
                min_age=self.min_age_threshold,
                max_age=self.max_age_threshold,
            )

            if parsed_age is not None:
                threshold = int(parsed_age.parameters["threshold"])

                # Enforce per-purpose permitted age thresholds
                if self.purpose_age_thresholds and purpose in self.purpose_age_thresholds:
                    allowed = self.purpose_age_thresholds[purpose]
                    if isinstance(allowed, tuple) and len(allowed) == 2:
                        p_min, p_max = allowed
                        if not (p_min <= threshold <= p_max):
                            raise PolicyViolationError(
                                f"Age threshold {threshold} is outside permitted range ({p_min}-{p_max}) for purpose '{purpose}'"
                            )
                    elif isinstance(allowed, (list, set)):
                        if threshold not in allowed:
                            raise PolicyViolationError(
                                f"Age threshold {threshold} is not permitted for purpose '{purpose}'. Permitted thresholds: {list(allowed)}"
                            )

                # Ensure dynamic registration in the active registry
                reg.ensure_age_predicate(check_str, threshold)
                resolved_checks.append(check_str)
                continue

            # Non-age predicate check
            if check_str not in self.allowed_checks:
                raise PolicyViolationError(
                    f"Unsupported check: '{check_str}'. Permitted checks: {self.allowed_checks}"
                )
            if not reg.is_supported(check_str):
                raise PolicyViolationError(
                    f"Unsupported check: '{check_str}'. Not registered in predicate registry"
                )
            resolved_checks.append(check_str)

        return resolved_checks

    def resolve_scopes_and_claims(
        self, checks: Sequence[Union[str, AgeThresholdRule]]
    ) -> Tuple[List[str], Dict[str, Any]]:
        """Resolve minimal OIDC scopes and essential claims needed for the requested checks using registry."""
        resolved: List[str] = [
            c.check_name if isinstance(c, AgeThresholdRule) else str(c) for c in checks
        ]
        reg = self.get_registry()
        return reg.resolve_scopes_and_claims(resolved)


