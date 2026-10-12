"""Unit tests for P3: Verified contact flags mapping, scopes, strict booleans, and assurance metadata."""

import pytest

from fayda_mcp import (
    CallerContext,
    FaydaConfig,
    FaydaVerificationService,
    PolicyViolationError,
    VerificationPolicy,
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


class TestContactScopeAndClaimMapping:
    """Verifies that phone and email scopes/claims are only requested when approved and requested."""

    def test_scope_and_claim_requirements(self) -> None:
        """phone_verified maps to phone_number_verified and openid+phone scopes; email_verified to email_verified and openid+email."""
        phone_pred = DEFAULT_PREDICATE_REGISTRY.get("phone_verified")
        assert phone_pred is not None
        assert phone_pred.required_claims == ["phone_number_verified"]
        assert phone_pred.required_scopes == ["openid", "phone"]

        email_pred = DEFAULT_PREDICATE_REGISTRY.get("email_verified")
        assert email_pred is not None
        assert email_pred.required_claims == ["email_verified"]
        assert email_pred.required_scopes == ["openid", "email"]

    def test_scopes_requested_only_when_approved_and_requested(self) -> None:
        """openid plus phone/email scopes are requested only when approved and requested."""
        policy = VerificationPolicy()

        # Only identity check -> no phone or email scope
        scopes_id, claims_id = policy.resolve_scopes_and_claims(["identity_verified"])
        assert scopes_id == ["openid"]
        assert "phone_number_verified" not in claims_id.get("userinfo", {})
        assert "email_verified" not in claims_id.get("userinfo", {})

        # Phone verified check -> openid and phone scopes only
        scopes_phone, claims_phone = policy.resolve_scopes_and_claims(["phone_verified"])
        assert sorted(scopes_phone) == ["openid", "phone"]
        assert claims_phone["userinfo"] == {"phone_number_verified": {"essential": True}}

        # Email verified check -> openid and email scopes only
        scopes_email, claims_email = policy.resolve_scopes_and_claims(["email_verified"])
        assert sorted(scopes_email) == ["email", "openid"]
        assert claims_email["userinfo"] == {"email_verified": {"essential": True}}

        # Both contact checks -> openid, phone, email
        scopes_both, claims_both = policy.resolve_scopes_and_claims(["phone_verified", "email_verified"])
        assert sorted(scopes_both) == ["email", "openid", "phone"]
        assert "phone_number_verified" in claims_both["userinfo"]
        assert "email_verified" in claims_both["userinfo"]

    @pytest.mark.asyncio
    async def test_unapproved_contact_check_fails_before_request(self) -> None:
        """If host policy does not approve phone/email checks, request fails fast."""
        # Policy restricted to identity and age only
        restricted_policy = VerificationPolicy(allowed_checks=["identity_verified", "age_over_18"])
        service = create_test_service(restricted_policy)
        ctx = CallerContext()

        with pytest.raises(PolicyViolationError, match="Unsupported check: 'phone_verified'"):
            await service.start_verification(
                context=ctx,
                purpose="kyc",
                checks=["phone_verified"],
                application_user_ref="u1",
                idempotency_key="k1",
            )


class TestStrictBooleanEvaluation:
    """Acceptance requirement: Strict true produces true, strict false produces false,

    absent/null/wrong-type flags produce unavailable.
    """

    def test_strict_true_produces_true(self) -> None:
        """Strict boolean True produces True."""
        claims = {
            "phone_number_verified": True,
            "email_verified": True,
        }
        res = evaluate_checks(claims, requested_checks=["phone_verified", "email_verified"])
        assert res["phone_verified"] is True
        assert res["email_verified"] is True

    def test_strict_false_produces_false(self) -> None:
        """Strict boolean False produces False (not unavailable)."""
        claims = {
            "phone_number_verified": False,
            "email_verified": False,
        }
        res = evaluate_checks(claims, requested_checks=["phone_verified", "email_verified"])
        assert res["phone_verified"] is False
        assert res["phone_verified"] != "unavailable"
        assert res["email_verified"] is False
        assert res["email_verified"] != "unavailable"

    def test_populated_contact_value_alone_never_produces_verified(self) -> None:
        """Acceptance requirement: A populated contact value alone never produces verified."""
        # Phone number present but verified flag missing
        claims_phone_only = {"phone_number": "+251911223344"}
        res_phone = evaluate_checks(claims_phone_only, requested_checks=["phone_verified"])
        assert res_phone["phone_verified"] == "unavailable"
        assert res_phone["phone_verified"] is not True

        # Email address present but verified flag missing
        claims_email_only = {"email": "citizen@example.et"}
        res_email = evaluate_checks(claims_email_only, requested_checks=["email_verified"])
        assert res_email["email_verified"] == "unavailable"
        assert res_email["email_verified"] is not True

    def test_wrong_type_and_string_flags_produce_unavailable(self) -> None:
        """Strings like 'false', 'true', numbers 1/0, null, or objects produce unavailable."""
        invalid_values = [
            "true",
            "false",
            "True",
            "False",
            1,
            0,
            None,
            "",
            ["true"],
            {"verified": True},
        ]

        for val in invalid_values:
            claims = {
                "phone_number_verified": val,
                "email_verified": val,
            }
            res = evaluate_checks(claims, requested_checks=["phone_verified", "email_verified"])
            assert res["phone_verified"] == "unavailable", f"Failed for phone_number_verified={val!r}"
            assert res["email_verified"] == "unavailable", f"Failed for email_verified={val!r}"


class TestAssuranceMetadataMapping:
    """Verifies documented provider assurance metadata fallback when standard flags are absent."""

    def test_fayda_assurance_metadata_boolean_mapping(self) -> None:
        """Documented assurance metadata dictionary provides valid boolean outcomes."""
        claims_true = {
            "fayda_assurance": {
                "phone_verified": True,
                "email_verified": True,
            }
        }
        res_true = evaluate_checks(claims_true, requested_checks=["phone_verified", "email_verified"])
        assert res_true["phone_verified"] is True
        assert res_true["email_verified"] is True

        claims_false = {
            "assurance_metadata": {
                "phone_verified": False,
                "email_verified": False,
            }
        }
        res_false = evaluate_checks(claims_false, requested_checks=["phone_verified", "email_verified"])
        assert res_false["phone_verified"] is False
        assert res_false["email_verified"] is False

    def test_invalid_assurance_metadata_produces_unavailable(self) -> None:
        """Invalid types within assurance metadata dictionary produce unavailable."""
        claims_bad_meta = {
            "assurance_metadata": {
                "phone_verified": "false",
                "email_verified": 1,
            }
        }
        res = evaluate_checks(claims_bad_meta, requested_checks=["phone_verified", "email_verified"])
        assert res["phone_verified"] == "unavailable"
        assert res["email_verified"] == "unavailable"

    def test_evaluate_reasons_reports_provider_claim_unavailable(self) -> None:
        """When flags are missing or invalid, evaluation returns safe reason code."""
        outcomes, reasons = DEFAULT_PREDICATE_REGISTRY.evaluate_all_with_reasons(
            claims={"phone_number": "+251911223344"},
            checks=["phone_verified", "email_verified"],
        )
        assert outcomes["phone_verified"] == "unavailable"
        assert outcomes["email_verified"] == "unavailable"
        assert reasons["phone_verified"] == "provider_claim_unavailable"
        assert reasons["email_verified"] == "provider_claim_unavailable"
