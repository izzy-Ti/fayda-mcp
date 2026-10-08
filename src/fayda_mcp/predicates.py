"""Shared Predicate Registry linking check name, parser, claims, scopes, evaluators, and availability rules.

Ensures verification policy acceptance, scope/claim resolution, and claims evaluation cannot diverge.
"""

from dataclasses import dataclass, field
from datetime import date
from typing import Any, Callable, Dict, List, Literal, Optional, Sequence, Set, Tuple, Union

from fayda_mcp.exceptions import PolicyViolationError

CheckOutcome = Union[bool, Literal["unavailable"]]


@dataclass(frozen=True)
class PredicateContext:
    """Evaluation context for predicates."""

    as_of: Optional[date] = None
    timezone_name: str = "Africa/Addis_Ababa"
    february_29_anniversary: str = "march_1"


@dataclass(frozen=True)
class ParsedPredicate:
    """Structured representation of a parsed predicate check."""

    name: str
    target_claim: str
    parameters: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PredicateEvaluation:
    """Outcome of evaluating a predicate against claims and context."""

    outcome: CheckOutcome
    reason: Optional[str] = None


@dataclass
class PredicateDefinition:
    """Complete specification linking check metadata, parsing, requirements, availability, and evaluation."""

    name: str
    description: str
    required_claims: List[str]
    required_scopes: List[str]
    parser: Callable[[str], ParsedPredicate]
    availability_rule: Callable[[Dict[str, Any], ParsedPredicate], Tuple[bool, Optional[str]]]
    evaluator: Callable[
        [Dict[str, Any], PredicateContext, ParsedPredicate],
        PredicateEvaluation,
    ]


# ---------------------------------------------------------------------------
# Default Evaluators and Availability Rules
# ---------------------------------------------------------------------------


def _identity_parser(check_name: str) -> ParsedPredicate:
    if check_name != "identity_verified":
        raise ValueError(f"Invalid check name for identity_verified: '{check_name}'")
    return ParsedPredicate(name="identity_verified", target_claim="sub")


def _identity_availability_rule(
    claims: Dict[str, Any], parsed: ParsedPredicate
) -> Tuple[bool, Optional[str]]:
    sub = claims.get("sub")
    if not sub or not str(sub).strip():
        return False, "missing_sub_claim"
    return True, None


def _identity_evaluator(
    claims: Dict[str, Any], context: PredicateContext, parsed: ParsedPredicate
) -> PredicateEvaluation:
    is_avail, reason = _identity_availability_rule(claims, parsed)
    if not is_avail:
        return PredicateEvaluation(outcome="unavailable", reason=reason)
    return PredicateEvaluation(outcome=True, reason=None)


def _create_age_parser(check_name_expected: str, threshold: int) -> Callable[[str], ParsedPredicate]:
    def parser(check_name: str) -> ParsedPredicate:
        if check_name != check_name_expected:
            raise ValueError(f"Invalid check name: expected '{check_name_expected}', got '{check_name}'")
        return ParsedPredicate(
            name=check_name_expected,
            target_claim="birthdate",
            parameters={"threshold": threshold},
        )

    return parser


def _age_availability_rule(
    claims: Dict[str, Any], parsed: ParsedPredicate
) -> Tuple[bool, Optional[str]]:
    raw_dob = claims.get("birthdate")
    if not raw_dob or not isinstance(raw_dob, str) or not raw_dob.strip():
        return False, "missing_dob"
    # Basic structural check for date components
    cleaned = raw_dob.strip()
    if cleaned.count("-") < 2 and cleaned.count("/") < 2:
        return False, "partial_or_malformed_dob"
    return True, None


def _age_evaluator(
    claims: Dict[str, Any], context: PredicateContext, parsed: ParsedPredicate
) -> PredicateEvaluation:
    from fayda_mcp.claims import calculate_age

    raw_dob = claims.get("birthdate")
    threshold = int(parsed.parameters.get("threshold", 18))

    if not raw_dob or not isinstance(raw_dob, str):
        return PredicateEvaluation(outcome="unavailable", reason="missing_dob")

    age = calculate_age(
        raw_dob,
        as_of=context.as_of,
        timezone_name=context.timezone_name,
        february_29_anniversary=context.february_29_anniversary,
    )

    if age is None:
        return PredicateEvaluation(outcome="unavailable", reason="invalid_or_partial_dob")

    return PredicateEvaluation(outcome=age >= threshold, reason=None)


# ---------------------------------------------------------------------------
# Predicate Registry Implementation
# ---------------------------------------------------------------------------


class PredicateRegistry:
    """Central registry linking check names, parsers, claims, scopes, evaluators, and availability rules."""

    def __init__(self) -> None:
        self._predicates: Dict[str, PredicateDefinition] = {}

    def register(self, predicate: PredicateDefinition) -> None:
        """Register a predicate definition."""
        self._predicates[predicate.name] = predicate

    def get(self, name: str) -> Optional[PredicateDefinition]:
        """Get registered predicate definition by name."""
        return self._predicates.get(name)

    def is_supported(self, name: str) -> bool:
        """Check whether a check name is supported by the registry."""
        return name in self._predicates

    def supported_checks(self) -> List[str]:
        """Return list of supported check names."""
        return list(self._predicates.keys())

    def all_predicates(self) -> Dict[str, PredicateDefinition]:
        """Return shallow copy of all registered predicates."""
        return dict(self._predicates)

    def validate_checks(self, checks: Sequence[str]) -> None:
        """Validate that all requested checks are supported by the registry.

        Raises PolicyViolationError on the first unsupported check.
        """
        for check in checks:
            if not self.is_supported(check):
                raise PolicyViolationError(
                    f"Unsupported check: '{check}'. Permitted checks: {self.supported_checks()}"
                )

    def resolve_scopes_and_claims(self, checks: Sequence[str]) -> Tuple[List[str], Dict[str, Any]]:
        """Resolve minimal scopes and essential userinfo claims for requested checks."""
        scopes: Set[str] = {"openid"}
        userinfo_claims: Dict[str, Any] = {}

        for check in checks:
            pred = self.get(check)
            if not pred:
                raise PolicyViolationError(f"Unsupported check: '{check}'")
            for scope in pred.required_scopes:
                scopes.add(scope)
            for claim_name in pred.required_claims:
                userinfo_claims[claim_name] = {"essential": True}

        claims_param = {"userinfo": userinfo_claims} if userinfo_claims else {}
        return sorted(list(scopes)), claims_param

    def evaluate_check(
        self,
        check: str,
        claims: Dict[str, Any],
        context: Optional[PredicateContext] = None,
    ) -> PredicateEvaluation:
        """Evaluate a single check against claims and context."""
        pred = self.get(check)
        if not pred:
            return PredicateEvaluation(outcome="unavailable", reason="unsupported_predicate")

        ctx = context or PredicateContext()
        try:
            parsed = pred.parser(check)
        except Exception:
            return PredicateEvaluation(outcome="unavailable", reason="malformed_predicate")

        # Check availability rule first
        is_avail, avail_reason = pred.availability_rule(claims, parsed)
        if not is_avail:
            return PredicateEvaluation(outcome="unavailable", reason=avail_reason)

        return pred.evaluator(claims, ctx, parsed)

    def evaluate_all(
        self,
        claims: Dict[str, Any],
        checks: Sequence[str],
        context: Optional[PredicateContext] = None,
    ) -> Dict[str, CheckOutcome]:
        """Evaluate all requested checks and return dict of check name to outcome."""
        results: Dict[str, CheckOutcome] = {}
        for check in checks:
            eval_res = self.evaluate_check(check, claims, context)
            results[check] = eval_res.outcome
        return results

    def evaluate_all_with_reasons(
        self,
        claims: Dict[str, Any],
        checks: Sequence[str],
        context: Optional[PredicateContext] = None,
    ) -> Tuple[Dict[str, CheckOutcome], Dict[str, str]]:
        """Evaluate all requested checks, returning outcomes and reasons dicts."""
        outcomes: Dict[str, CheckOutcome] = {}
        reasons: Dict[str, str] = {}
        for check in checks:
            eval_res = self.evaluate_check(check, claims, context)
            outcomes[check] = eval_res.outcome
            if eval_res.reason:
                reasons[check] = eval_res.reason
        return outcomes, reasons


def create_default_predicate_registry() -> PredicateRegistry:
    """Create and initialize the default shared predicate registry."""
    registry = PredicateRegistry()

    # 1. Identity Verified
    registry.register(
        PredicateDefinition(
            name="identity_verified",
            description="Verified citizen identity presence (OIDC sub claim)",
            required_claims=["sub"],
            required_scopes=["openid"],
            parser=_identity_parser,
            availability_rule=_identity_availability_rule,
            evaluator=_identity_evaluator,
        )
    )

    # 2. Age Over 18
    registry.register(
        PredicateDefinition(
            name="age_over_18",
            description="Citizen age is at least 18 years on anniversary date",
            required_claims=["birthdate"],
            required_scopes=["openid", "profile"],
            parser=_create_age_parser("age_over_18", 18),
            availability_rule=_age_availability_rule,
            evaluator=_age_evaluator,
        )
    )

    # 3. Age Over 21
    registry.register(
        PredicateDefinition(
            name="age_over_21",
            description="Citizen age is at least 21 years on anniversary date",
            required_claims=["birthdate"],
            required_scopes=["openid", "profile"],
            parser=_create_age_parser("age_over_21", 21),
            availability_rule=_age_availability_rule,
            evaluator=_age_evaluator,
        )
    )

    return registry


DEFAULT_PREDICATE_REGISTRY: PredicateRegistry = create_default_predicate_registry()
