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


def _create_contact_parser(expected_name: str) -> Callable[[str], ParsedPredicate]:
    def parser(check_name: str) -> ParsedPredicate:
        if check_name != expected_name:
            raise ValueError(f"Invalid check name: expected '{expected_name}', got '{check_name}'")
        target_claim = "phone_number_verified" if expected_name == "phone_verified" else "email_verified"
        return ParsedPredicate(name=expected_name, target_claim=target_claim)

    return parser


def _contact_flag_evaluator(
    claims: Dict[str, Any],
    flag_claim: str,
    contact_claim: str,
    assurance_key: str,
) -> PredicateEvaluation:
    """Strictly evaluate verified contact flags (P3).

    Rules:
    - Strict True produces True.
    - Strict False produces False.
    - Absent, null, wrong-type flags (including strings "false", "true", integers 0, 1) produce 'unavailable'.
    - A populated contact value alone (e.g. phone_number or email) NEVER produces verified.
    - If provider supplies equivalent assurance metadata rather than standard flags, maps documented signed metadata.
    """
    val = claims.get(flag_claim)

    # 1. Strict boolean check on standard OIDC claim
    if isinstance(val, bool):
        return PredicateEvaluation(outcome=val, reason=None)

    # 2. Check documented provider assurance metadata fallback if standard flag is absent
    assurance = claims.get("assurance_metadata") or claims.get("fayda_assurance")
    if isinstance(assurance, dict):
        meta_val = assurance.get(assurance_key)
        if isinstance(meta_val, bool):
            return PredicateEvaluation(outcome=meta_val, reason=None)

    # 3. Acceptance rule: A populated contact value alone never produces verified.
    # Non-boolean types (e.g. "false", "true", integers, None, missing) yield 'unavailable'.
    return PredicateEvaluation(
        outcome="unavailable",
        reason="provider_claim_unavailable",
    )


def _phone_availability_rule(
    claims: Dict[str, Any], parsed: ParsedPredicate
) -> Tuple[bool, Optional[str]]:
    val = claims.get("phone_number_verified")
    if isinstance(val, bool):
        return True, None
    assurance = claims.get("assurance_metadata") or claims.get("fayda_assurance")
    if isinstance(assurance, dict) and isinstance(assurance.get("phone_verified"), bool):
        return True, None
    return False, "provider_claim_unavailable"


def _phone_evaluator(
    claims: Dict[str, Any], context: PredicateContext, parsed: ParsedPredicate
) -> PredicateEvaluation:
    return _contact_flag_evaluator(
        claims=claims,
        flag_claim="phone_number_verified",
        contact_claim="phone_number",
        assurance_key="phone_verified",
    )


def _email_availability_rule(
    claims: Dict[str, Any], parsed: ParsedPredicate
) -> Tuple[bool, Optional[str]]:
    val = claims.get("email_verified")
    if isinstance(val, bool):
        return True, None
    assurance = claims.get("assurance_metadata") or claims.get("fayda_assurance")
    if isinstance(assurance, dict) and isinstance(assurance.get("email_verified"), bool):
        return True, None
    return False, "provider_claim_unavailable"


def _email_evaluator(
    claims: Dict[str, Any], context: PredicateContext, parsed: ParsedPredicate
) -> PredicateEvaluation:
    return _contact_flag_evaluator(
        claims=claims,
        flag_claim="email_verified",
        contact_claim="email",
        assurance_key="email_verified",
    )


def _sig_parser(check_name: str) -> ParsedPredicate:
    if check_name != "credential_signature_valid":
        raise ValueError(f"Invalid check name: '{check_name}'")
    return ParsedPredicate(name="credential_signature_valid", target_claim="credential_signature_valid")


def _sig_availability_rule(
    claims: Dict[str, Any], parsed: ParsedPredicate
) -> Tuple[bool, Optional[str]]:
    val = claims.get("credential_signature_valid")
    if val is None:
        return False, "missing_signature_claim"
    return True, None


def _sig_evaluator(
    claims: Dict[str, Any], context: PredicateContext, parsed: ParsedPredicate
) -> PredicateEvaluation:
    is_avail, reason = _sig_availability_rule(claims, parsed)
    if not is_avail:
        return PredicateEvaluation(outcome="unavailable", reason=reason)
    return PredicateEvaluation(outcome=bool(claims.get("credential_signature_valid")), reason=None)


@dataclass(frozen=True)
class AgeThresholdRule:
    """Typed rule for age verification thresholds.

    Naming convention:
    - 'age_over_18' is maintained as the existing backwards-compatibility alias for age >= 18.
    - 'age_at_least' is the preferred prefix for new structured rules (e.g. age_at_least_21).
    - Both evaluate whether calculated age is at least the threshold.
    """

    threshold: int
    rule_type: Literal["age_at_least", "age_over"] = "age_at_least"

    def __post_init__(self) -> None:
        if isinstance(self.threshold, bool) or not isinstance(self.threshold, int):
            raise PolicyViolationError(f"Age threshold must be an integer, got: {self.threshold}")
        if self.threshold < 1:
            raise PolicyViolationError(f"Age threshold must be at least 1, got: {self.threshold}")
        if self.threshold > 120:
            raise PolicyViolationError(f"Age threshold {self.threshold} exceeds maximum allowed (120)")

    @property
    def check_name(self) -> str:
        return f"{self.rule_type}_{self.threshold}"

    def __str__(self) -> str:
        return self.check_name


def parse_age_check(
    check_str: str,
    min_age: int = 1,
    max_age: int = 120,
) -> Optional[ParsedPredicate]:
    """Strictly parse an age verification check string.

    Supports:
    - Legacy alias: 'age_over_N' (e.g. 'age_over_18', compatibility alias for age >= 18)
    - Preferred structured rule: 'age_at_least_N' (e.g. 'age_at_least_21')

    Strict validation:
    - Rejects negative thresholds (e.g., 'age_over_-5', 'age_at_least_-1')
    - Rejects decimal thresholds (e.g., 'age_over_18.5', 'age_at_least_20.0')
    - Rejects malformed thresholds (e.g., 'age_over_', 'age_over_abc', 'age_over_018')
    - Rejects enormous thresholds (e.g., 'age_over_999' > max_age)
    - Rejects thresholds below min_age (e.g., 'age_over_0' < min_age)
    - Returns None if check_str is not an age predicate (e.g., 'identity_verified')
    """
    if not isinstance(check_str, str):
        return None

    if check_str.startswith("age_over_"):
        rule_type = "age_over"
        suffix = check_str[len("age_over_"):]
    elif check_str.startswith("age_at_least_"):
        rule_type = "age_at_least"
        suffix = check_str[len("age_at_least_"):]
    else:
        return None

    if not suffix:
        raise PolicyViolationError(f"Malformed age threshold (empty value): '{check_str}'")

    # Reject negative
    if suffix.startswith("-") or "-" in suffix:
        raise PolicyViolationError(f"Negative age threshold is not allowed: '{check_str}'")

    # Reject decimal
    if "." in suffix or "," in suffix:
        raise PolicyViolationError(f"Decimal age threshold is not allowed: '{check_str}'")

    # Reject non-numeric / malformed
    if not suffix.isdigit():
        raise PolicyViolationError(f"Malformed age threshold (non-numeric): '{check_str}'")

    # Reject leading zero formatting like '018' (unless single '0')
    if len(suffix) > 1 and suffix.startswith("0"):
        raise PolicyViolationError(f"Malformed age threshold (leading zero): '{check_str}'")

    try:
        threshold = int(suffix)
    except ValueError:
        raise PolicyViolationError(f"Malformed age threshold: '{check_str}'")

    # Reject below min_age
    if threshold < min_age:
        raise PolicyViolationError(
            f"Age threshold {threshold} is below host minimum ({min_age}): '{check_str}'"
        )

    # Reject enormous (above max_age)
    if threshold > max_age:
        raise PolicyViolationError(
            f"Enormous age threshold {threshold} exceeds host maximum ({max_age}): '{check_str}'"
        )

    return ParsedPredicate(
        name=check_str,
        target_claim="birthdate",
        parameters={"threshold": threshold, "rule_type": rule_type},
    )


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

    def ensure_age_predicate(self, name: str, threshold: int) -> PredicateDefinition:
        """Register or return a dynamically constructed age predicate definition."""
        if name in self._predicates:
            return self._predicates[name]

        desc = f"Citizen age is at least {threshold} years on anniversary date"
        pred = PredicateDefinition(
            name=name,
            description=desc,
            required_claims=["birthdate"],
            required_scopes=["openid", "profile"],
            parser=_create_age_parser(name, threshold),
            availability_rule=_age_availability_rule,
            evaluator=_age_evaluator,
        )
        self._predicates[name] = pred
        return pred

    def get(self, name: str) -> Optional[PredicateDefinition]:
        """Get registered predicate definition by name, resolving dynamic age rules."""
        if name in self._predicates:
            return self._predicates[name]
        try:
            parsed = parse_age_check(name)
            if parsed is not None:
                threshold = int(parsed.parameters["threshold"])
                return self.ensure_age_predicate(name, threshold)
        except Exception:
            pass
        return None

    def is_supported(self, name: str) -> bool:
        """Check whether a check name is supported by the registry."""
        return self.get(name) is not None

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

    # 4. Phone Verified
    registry.register(
        PredicateDefinition(
            name="phone_verified",
            description="Verified citizen phone number flag (phone_number_verified)",
            required_claims=["phone_number_verified"],
            required_scopes=["openid", "phone"],
            parser=_create_contact_parser("phone_verified"),
            availability_rule=_phone_availability_rule,
            evaluator=_phone_evaluator,
        )
    )

    # 5. Email Verified
    registry.register(
        PredicateDefinition(
            name="email_verified",
            description="Verified citizen email address flag (email_verified)",
            required_claims=["email_verified"],
            required_scopes=["openid", "email"],
            parser=_create_contact_parser("email_verified"),
            availability_rule=_email_availability_rule,
            evaluator=_email_evaluator,
        )
    )

    # 6. Credential Signature Valid (QR verification)
    registry.register(
        PredicateDefinition(
            name="credential_signature_valid",
            description="Cryptographic issuer signature verification validity flag",
            required_claims=["credential_signature_valid"],
            required_scopes=["openid"],
            parser=_sig_parser,
            availability_rule=_sig_availability_rule,
            evaluator=_sig_evaluator,
        )
    )

    return registry


DEFAULT_PREDICATE_REGISTRY: PredicateRegistry = create_default_predicate_registry()

