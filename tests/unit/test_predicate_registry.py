"""Unit tests for P1: Shared Predicate Registry and policy/evaluation alignment."""

from datetime import date
from typing import Any, Dict
import pytest

from fayda_mcp import (
    CallerContext,
    FaydaConfig,
    FaydaVerificationService,
    PolicyViolationError,
    VerificationPolicy,
)
from fayda_mcp.claims import evaluate_checks
from fayda_mcp.predicates import (
    DEFAULT_PREDICATE_REGISTRY,
    ParsedPredicate,
    PredicateContext,
    PredicateDefinition,
    PredicateEvaluation,
    PredicateRegistry,
)
from fayda_mcp.policy import CHECK_CLAIM_MAPPING, CHECK_SCOPE_MAPPING
from fayda_mcp.storage.memory import MemoryResultRepository, MemorySessionStore


def create_test_service(policy: VerificationPolicy | None = None) -> FaydaVerificationService:
    config = FaydaConfig(
        client_id="test-client-id",
        redirect_uri="https://developer-app.example/auth/fayda/callback",
        issuer="https://esignet.sandbox.fayda.et",
        authorization_endpoint="https://esignet.sandbox.fayda.et/authorize",
        token_endpoint="https://esignet.sandbox.fayda.et/oauth/token",
        userinfo_endpoint="https://esignet.sandbox.fayda.et/oidc/userinfo",
        jwks_uri="https://esignet.sandbox.fayda.et/jwks.json",
        session_ttl_seconds=300,
    )
    return FaydaVerificationService(
        config=config,
        sessions=MemorySessionStore(),
        results=MemoryResultRepository(),
        policy=policy,
    )


class TestPredicateRegistryStructure:
    """Verifies that the registry links name, parser, claims, scopes, evaluator, and availability rules."""

    def test_registry_links_all_required_attributes(self) -> None:
        """Every registered check must link name, parser, claims, scopes, evaluator, and availability rules."""
        for check_name in ["identity_verified", "age_over_18", "age_over_21"]:
            pred = DEFAULT_PREDICATE_REGISTRY.get(check_name)
            assert pred is not None, f"Check '{check_name}' must be registered"
            assert pred.name == check_name
            assert isinstance(pred.description, str) and len(pred.description) > 0
            assert isinstance(pred.required_claims, list) and len(pred.required_claims) > 0
            assert isinstance(pred.required_scopes, list) and len(pred.required_scopes) > 0
            assert callable(pred.parser)
            assert callable(pred.availability_rule)
            assert callable(pred.evaluator)

    def test_include_age_over_21(self) -> None:
        """Requirement P1: Include age_over_21 in the shared registry."""
        pred = DEFAULT_PREDICATE_REGISTRY.get("age_over_21")
        assert pred is not None
        assert pred.required_claims == ["birthdate"]
        assert pred.required_scopes == ["openid", "profile"]

        # Parse check name
        parsed = pred.parser("age_over_21")
        assert parsed.name == "age_over_21"
        assert parsed.parameters["threshold"] == 21

        # Check age evaluation boundaries
        eval_date = date(2026, 10, 8)
        ctx = PredicateContext(as_of=eval_date)

        # 22 years old -> True
        claims_22 = {"birthdate": "2004-10-07"}
        res_22 = pred.evaluator(claims_22, ctx, parsed)
        assert res_22.outcome is True
        assert res_22.reason is None

        # Exactly 21 years old on anniversary -> True
        claims_21 = {"birthdate": "2005-10-08"}
        res_21 = pred.evaluator(claims_21, ctx, parsed)
        assert res_21.outcome is True

        # Day before 21st birthday -> False (distinct from unavailable)
        claims_under_21 = {"birthdate": "2005-10-09"}
        res_under = pred.evaluator(claims_under_21, ctx, parsed)
        assert res_under.outcome is False
        assert res_under.reason is None

        # Missing DOB -> unavailable with reason
        res_missing = pred.evaluator({}, ctx, parsed)
        assert res_missing.outcome == "unavailable"
        assert res_missing.reason == "missing_dob"

    def test_backward_compatibility_mappings(self) -> None:
        """Module-level CHECK_SCOPE_MAPPING and CHECK_CLAIM_MAPPING reflect registry."""
        assert "identity_verified" in CHECK_SCOPE_MAPPING
        assert "age_over_18" in CHECK_SCOPE_MAPPING
        assert "age_over_21" in CHECK_SCOPE_MAPPING

        assert CHECK_SCOPE_MAPPING["age_over_21"] == ["openid", "profile"]
        assert CHECK_CLAIM_MAPPING["age_over_21"] == ["birthdate"]


class TestPolicyEvaluationAlignment:
    """Acceptance requirement: Policy acceptance and evaluation cannot diverge."""

    def test_policy_default_includes_all_registered_checks(self) -> None:
        """VerificationPolicy defaults to all supported checks in the registry."""
        policy = VerificationPolicy()
        assert "identity_verified" in policy.allowed_checks
        assert "age_over_18" in policy.allowed_checks
        assert "age_over_21" in policy.allowed_checks

    def test_scope_and_claim_resolution_derives_from_registry(self) -> None:
        """resolve_scopes_and_claims pulls requirements strictly from registered predicates."""
        policy = VerificationPolicy()
        scopes, claims = policy.resolve_scopes_and_claims(["identity_verified", "age_over_21"])

        assert "openid" in scopes
        assert "profile" in scopes
        assert claims == {
            "userinfo": {
                "sub": {"essential": True},
                "birthdate": {"essential": True},
            }
        }

    def test_evaluation_uses_same_predicates_as_policy(self) -> None:
        """evaluate_checks delegates to the shared registry without duplicated allowlists."""
        claims = {"sub": "user_123", "birthdate": "2000-01-01"}
        outcomes = evaluate_checks(
            claims,
            requested_checks=["identity_verified", "age_over_18", "age_over_21"],
            as_of=date(2026, 10, 8),
        )
        assert outcomes["identity_verified"] is True
        assert outcomes["age_over_18"] is True
        assert outcomes["age_over_21"] is True

    def test_custom_registered_predicate_automatically_shared(self) -> None:
        """A predicate added to a registry is immediately available to policy resolution and evaluation."""
        custom_registry = PredicateRegistry()
        for k, v in DEFAULT_PREDICATE_REGISTRY.all_predicates().items():
            custom_registry.register(v)

        # Register custom predicate: "phone_present"
        def _phone_parser(name: str) -> ParsedPredicate:
            if name != "phone_present":
                raise ValueError("Bad name")
            return ParsedPredicate(name="phone_present", target_claim="phone_number")

        def _phone_avail(claims: Dict[str, Any], parsed: ParsedPredicate):
            return bool(claims.get("phone_number")), "missing_phone"

        def _phone_eval(claims: Dict[str, Any], ctx: PredicateContext, parsed: ParsedPredicate):
            return PredicateEvaluation(outcome=True)

        custom_registry.register(
            PredicateDefinition(
                name="phone_present",
                description="Checks if phone number is present",
                required_claims=["phone_number"],
                required_scopes=["phone"],
                parser=_phone_parser,
                availability_rule=_phone_avail,
                evaluator=_phone_eval,
            )
        )

        custom_policy = VerificationPolicy(
            allowed_checks=custom_registry.supported_checks(),
            registry=custom_registry,
        )

        # 1. Accepted by policy
        custom_policy.validate_request("kyc", ["phone_present"])
        scopes, claims = custom_policy.resolve_scopes_and_claims(["phone_present"])
        assert "phone" in scopes
        assert "phone_number" in claims["userinfo"]

        # 2. Evaluated by claims engine
        eval_outcomes = evaluate_checks(
            {"phone_number": "+251911223344"},
            requested_checks=["phone_present"],
            registry=custom_registry,
        )
        assert eval_outcomes["phone_present"] is True


class TestUnsupportedChecksFailFast:
    """Acceptance requirement: Unsupported checks fail before creating sessions or requesting claims."""

    @pytest.mark.asyncio
    async def test_unsupported_checks_fail_before_session_creation(self) -> None:
        """Unsupported checks fail immediately with PolicyViolationError and store zero sessions."""
        service = create_test_service()
        ctx = CallerContext(tenant_id="t1", principal_id="p1")

        with pytest.raises(PolicyViolationError) as exc_info:
            await service.start_verification(
                context=ctx,
                purpose="kyc",
                checks=["identity_verified", "unsupported_check_xyz"],
                application_user_ref="usr-fail",
                idempotency_key="idemp-fail-1",
            )
        assert "Unsupported check: 'unsupported_check_xyz'" in str(exc_info.value)

        # Verify NO session was saved in session store
        assert isinstance(service.sessions, MemorySessionStore)
        assert len(service.sessions._sessions) == 0

        # Verify NO reservation was saved in result repository
        assert isinstance(service.results, MemoryResultRepository)
        assert len(service.results._requests) == 0

    def test_policy_validate_request_rejects_unregistered_checks(self) -> None:
        """VerificationPolicy.validate_request rejects unregistered checks."""
        policy = VerificationPolicy()

        with pytest.raises(PolicyViolationError, match="Unsupported check: 'arbitrary_predicate'"):
            policy.validate_request("kyc", ["arbitrary_predicate"])

    def test_unregistered_check_evaluates_to_unavailable(self) -> None:
        """Direct evaluation of unregistered check returns 'unavailable'."""
        eval_res = DEFAULT_PREDICATE_REGISTRY.evaluate_check(
            "unregistered_check",
            claims={"sub": "user_123"},
        )
        assert eval_res.outcome == "unavailable"
        assert eval_res.reason == "unsupported_predicate"
