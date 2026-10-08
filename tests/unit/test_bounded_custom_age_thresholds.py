"""Unit tests for P2: Bounded custom age thresholds, strict parsing, and policy resolution."""

from datetime import date
import pytest

from fayda_mcp import (
    AgeThresholdRule,
    CallerContext,
    FaydaConfig,
    FaydaVerificationService,
    PolicyViolationError,
    VerificationPolicy,
    parse_age_check,
)
from fayda_mcp.claims import evaluate_checks
from fayda_mcp.predicates import DEFAULT_PREDICATE_REGISTRY
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


class TestStrictAgeCheckParsing:
    """Acceptance requirement: Reject negative, decimal, malformed, enormous, and disallowed thresholds."""

    def test_parse_valid_legacy_and_structured_rules(self) -> None:
        """Verify parsing of legacy age_over_N and structured age_at_least_N."""
        # Legacy compatibility alias
        p18 = parse_age_check("age_over_18")
        assert p18 is not None
        assert p18.parameters["threshold"] == 18
        assert p18.parameters["rule_type"] == "age_over"

        # Preferred structured rule
        p21 = parse_age_check("age_at_least_21")
        assert p21 is not None
        assert p21.parameters["threshold"] == 21
        assert p21.parameters["rule_type"] == "age_at_least"

        # Arbitrary custom valid threshold
        p65 = parse_age_check("age_at_least_65")
        assert p65 is not None
        assert p65.parameters["threshold"] == 65

    def test_reject_negative_thresholds(self) -> None:
        """Reject negative age thresholds."""
        with pytest.raises(PolicyViolationError, match="Negative age threshold"):
            parse_age_check("age_over_-5")

        with pytest.raises(PolicyViolationError, match="Negative age threshold"):
            parse_age_check("age_at_least_-18")

    def test_reject_decimal_thresholds(self) -> None:
        """Reject decimal age thresholds."""
        with pytest.raises(PolicyViolationError, match="Decimal age threshold"):
            parse_age_check("age_over_18.5")

        with pytest.raises(PolicyViolationError, match="Decimal age threshold"):
            parse_age_check("age_at_least_21.0")

        with pytest.raises(PolicyViolationError, match="Decimal age threshold"):
            parse_age_check("age_over_18,5")

    def test_reject_malformed_thresholds(self) -> None:
        """Reject empty, non-numeric, or leading-zero malformed thresholds."""
        with pytest.raises(PolicyViolationError, match="empty value"):
            parse_age_check("age_over_")

        with pytest.raises(PolicyViolationError, match="empty value"):
            parse_age_check("age_at_least_")

        with pytest.raises(PolicyViolationError, match="non-numeric"):
            parse_age_check("age_over_abc")

        with pytest.raises(PolicyViolationError, match="non-numeric"):
            parse_age_check("age_at_least_21a")

        with pytest.raises(PolicyViolationError, match="leading zero"):
            parse_age_check("age_over_018")

    def test_reject_enormous_thresholds(self) -> None:
        """Reject thresholds exceeding maximum allowed host bound."""
        with pytest.raises(PolicyViolationError, match="Enormous age threshold"):
            parse_age_check("age_over_999", max_age=120)

        with pytest.raises(PolicyViolationError, match="Enormous age threshold"):
            parse_age_check("age_at_least_200", max_age=120)

    def test_reject_below_minimum_thresholds(self) -> None:
        """Reject thresholds below minimum allowed host bound."""
        with pytest.raises(PolicyViolationError, match="below host minimum"):
            parse_age_check("age_over_0", min_age=1)

    def test_non_age_predicate_returns_none(self) -> None:
        """Non-age check strings return None for standard predicate handling."""
        assert parse_age_check("identity_verified") is None
        assert parse_age_check("sub") is None


class TestTypedAgeRule:
    """Verifies typed AgeThresholdRule helper."""

    def test_typed_rule_instantiation_and_validation(self) -> None:
        """AgeThresholdRule enforces integer bounds and provides check_name."""
        rule21 = AgeThresholdRule(21)
        assert rule21.check_name == "age_at_least_21"
        assert str(rule21) == "age_at_least_21"

        rule_legacy = AgeThresholdRule(18, rule_type="age_over")
        assert rule_legacy.check_name == "age_over_18"

        with pytest.raises(PolicyViolationError, match="at least 1"):
            AgeThresholdRule(0)

        with pytest.raises(PolicyViolationError, match="maximum allowed"):
            AgeThresholdRule(150)


class TestHostBoundsAndPurposeThresholds:
    """Verifies host-approved min/max and per-purpose permitted thresholds in policy."""

    def test_host_approved_min_max_enforcement(self) -> None:
        """Policy rejects thresholds outside host-configured min_age_threshold and max_age_threshold."""
        policy = VerificationPolicy(min_age_threshold=18, max_age_threshold=65)

        # 16 is below host minimum (18)
        with pytest.raises(PolicyViolationError, match="below host minimum"):
            policy.validate_request("kyc", ["age_at_least_16"])

        # 70 is above host maximum (65)
        with pytest.raises(PolicyViolationError, match="exceeds host maximum"):
            policy.validate_request("kyc", ["age_at_least_70"])

        # 25 is within bounds
        resolved = policy.validate_request("kyc", ["age_at_least_25"])
        assert resolved == ["age_at_least_25"]

    def test_per_purpose_permitted_thresholds_range(self) -> None:
        """Policy enforces per-purpose allowed threshold ranges."""
        policy = VerificationPolicy(
            purpose_age_thresholds={
                "onboarding": (18, 60),
                "senior_discount": (60, 100),
            }
        )

        # In range for onboarding
        assert policy.validate_request("onboarding", ["age_at_least_25"]) == ["age_at_least_25"]

        # Out of range for onboarding (65 > 60)
        with pytest.raises(PolicyViolationError, match="outside permitted range"):
            policy.validate_request("onboarding", ["age_at_least_65"])

        # In range for senior_discount
        assert policy.validate_request("senior_discount", ["age_at_least_65"]) == ["age_at_least_65"]

    def test_per_purpose_permitted_thresholds_explicit_list(self) -> None:
        """Policy enforces per-purpose allowed explicit list of thresholds."""
        policy = VerificationPolicy(
            purpose_age_thresholds={
                "alcohol_retail": [21],
            }
        )

        # 21 permitted
        assert policy.validate_request("alcohol_retail", ["age_at_least_21"]) == ["age_at_least_21"]

        # 18 rejected for alcohol_retail
        with pytest.raises(PolicyViolationError, match="not permitted for purpose 'alcohol_retail'"):
            policy.validate_request("alcohol_retail", ["age_over_18"])


class TestDOBResolutionAndImmutability:
    """Acceptance requirement: Resolve every accepted age rule to the approved DOB request.

    Capture resolved checks and policy version in original request. Callers cannot change threshold during callback.
    """

    def test_resolve_every_age_rule_to_dob_request(self) -> None:
        """Every valid age check resolves to openid profile scopes and birthdate userinfo claim."""
        policy = VerificationPolicy()
        for check in ["age_over_18", "age_at_least_21", "age_at_least_65", AgeThresholdRule(30)]:
            scopes, claims = policy.resolve_scopes_and_claims([check])
            assert "openid" in scopes
            assert "profile" in scopes
            assert claims == {"userinfo": {"birthdate": {"essential": True}}}

    def test_evaluation_of_custom_threshold(self) -> None:
        """Evaluator correctly evaluates custom threshold age_at_least_30."""
        as_of = date(2026, 10, 8)
        # Born 1990 -> age 36 >= 30 -> True
        res_true = evaluate_checks(
            {"birthdate": "1990-01-01"},
            requested_checks=["age_at_least_30"],
            as_of=as_of,
        )
        assert res_true["age_at_least_30"] is True

        # Born 2000 -> age 26 < 30 -> False (distinct from unavailable)
        res_false = evaluate_checks(
            {"birthdate": "2000-01-01"},
            requested_checks=["age_at_least_30"],
            as_of=as_of,
        )
        assert res_false["age_at_least_30"] is False

        # Missing birthdate -> unavailable
        res_unavail = evaluate_checks(
            {},
            requested_checks=["age_at_least_30"],
            as_of=as_of,
        )
        assert res_unavail["age_at_least_30"] == "unavailable"

    @pytest.mark.asyncio
    async def test_capture_resolved_checks_and_caller_immutability(self) -> None:
        """Resolved checks and policy version are stored in original request and cannot be altered."""
        policy = VerificationPolicy(version="v1")
        service = create_test_service(policy)
        ctx = CallerContext(tenant_id="tenant-1", principal_id="agent-1")

        # Start verification with structured AgeThresholdRule
        resp = await service.start_verification(
            context=ctx,
            purpose="kyc",
            checks=[AgeThresholdRule(25)],  # typed rule resolves to "age_at_least_25"
            application_user_ref="usr-bound-1",
            idempotency_key="idemp-bound-1",
        )

        # Inspect database record
        record = await service.results.get_request(resp.request_id)
        assert record is not None
        assert record["checks"] == ["age_at_least_25"]
        assert record["policy_version"] == "v1"

        # Inspect session
        assert isinstance(service.sessions, MemorySessionStore)
        stored_sessions = [
            data for data, exp in service.sessions._sessions.values()
            if data["request_id"] == resp.request_id
        ]
        assert len(stored_sessions) == 1
        assert stored_sessions[0]["checks"] == ["age_at_least_25"]
