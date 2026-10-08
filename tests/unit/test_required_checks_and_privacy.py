"""Unit tests for P4: Required vs optional checks, incomplete status, and privacy contract."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch
import pytest
from pydantic import ValidationError

from fayda_mcp import (
    CallerContext,
    FaydaConfig,
    FaydaVerificationService,
    VerificationPolicy,
    VerificationResult,
)
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
        result_ttl_seconds=86400,
    )
    return FaydaVerificationService(
        config=config,
        sessions=MemorySessionStore(),
        results=MemoryResultRepository(),
        policy=policy,
    )


class TestRequiredAndOptionalChecks:
    """Acceptance requirement: identity_verified=true with required email_verified unavailable does not complete policy."""

    @pytest.mark.asyncio
    async def test_required_email_verified_unavailable_yields_incomplete(self) -> None:
        """When email_verified is required but unavailable, policy outcome is 'incomplete' (not verified)."""
        policy = VerificationPolicy(version="v2")
        service = create_test_service(policy)
        ctx = CallerContext()

        # Start verification requiring identity_verified and email_verified
        resp = await service.start_verification(
            context=ctx,
            purpose="onboarding",
            checks=["identity_verified", "email_verified"],  # Both required by default
            application_user_ref="usr-1",
            idempotency_key="idemp-1",
        )

        state = resp.authorization_url.split("state=")[1].split("&")[0]

        # Simulate provider claims: identity (sub) is present, email_verified is missing/unavailable
        mock_id_claims = {"sub": "fayda:user:123"}
        mock_userinfo_claims = {"email": "user@example.com"}  # Populated email without verified flag

        with patch.object(service, "_get_private_key", return_value="fake_pem"), \
             patch("fayda_mcp.service.create_client_assertion", return_value="fake.client.assertion"), \
             patch.object(service.jwks, "get_signing_key_for_token", AsyncMock(return_value="fake_key")), \
             patch.object(service._http, "exchange_code", AsyncMock(return_value={"id_token": "mock.id.jwt", "access_token": "at"})), \
             patch("fayda_mcp.service.validate_id_token", return_value=mock_id_claims), \
             patch.object(service._http, "fetch_userinfo", AsyncMock(return_value={})), \
             patch("fayda_mcp.service.validate_userinfo_response", return_value=mock_userinfo_claims):

            result = await service.complete_verification(code="test_code", state=state)

        # Acceptance assertion: does not complete the requested policy
        assert result.status == "incomplete"
        assert result.checks["identity_verified"] is True
        assert result.checks["email_verified"] is None  # Represented as null / None
        assert result.reasons.get("email_verified") == "provider_claim_unavailable"
        assert result.policy_version == "v2"
        assert result.verified_at is not None
        assert result.expires_at is not None
        assert result.evidence_ref == f"ev_{resp.request_id}"

    @pytest.mark.asyncio
    async def test_optional_phone_verified_unavailable_allows_verified(self) -> None:
        """When phone_verified is optional and unavailable, policy outcome is 'verified' if required checks pass."""
        policy = VerificationPolicy(version="v2", optional_checks=["phone_verified"])
        service = create_test_service(policy)
        ctx = CallerContext()

        resp = await service.start_verification(
            context=ctx,
            purpose="onboarding",
            checks=["identity_verified", "phone_verified"],
            optional_checks=["phone_verified"],
            application_user_ref="usr-2",
            idempotency_key="idemp-2",
        )

        state = resp.authorization_url.split("state=")[1].split("&")[0]

        # Simulate claims: identity present, phone_verified absent
        mock_id_claims = {"sub": "fayda:user:456"}
        mock_userinfo_claims = {"phone_number": "+251911223344"}

        with patch.object(service, "_get_private_key", return_value="fake_pem"), \
             patch("fayda_mcp.service.create_client_assertion", return_value="fake.client.assertion"), \
             patch.object(service.jwks, "get_signing_key_for_token", AsyncMock(return_value="fake_key")), \
             patch.object(service._http, "exchange_code", AsyncMock(return_value={"id_token": "mock.id.jwt", "access_token": "at"})), \
             patch("fayda_mcp.service.validate_id_token", return_value=mock_id_claims), \
             patch.object(service._http, "fetch_userinfo", AsyncMock(return_value={})), \
             patch("fayda_mcp.service.validate_userinfo_response", return_value=mock_userinfo_claims):

            result = await service.complete_verification(code="test_code", state=state)

        assert result.status == "verified"
        assert result.checks["identity_verified"] is True
        assert result.checks["phone_verified"] is None
        assert result.reasons.get("phone_verified") == "provider_claim_unavailable"

    @pytest.mark.asyncio
    async def test_optional_check_explicit_false_yields_rejected(self) -> None:
        """When an optional check explicitly fails (False), policy outcome is 'rejected'."""
        policy = VerificationPolicy(version="v2")
        service = create_test_service(policy)
        ctx = CallerContext()

        resp = await service.start_verification(
            context=ctx,
            purpose="onboarding",
            checks=["identity_verified", "optional:phone_verified"],
            application_user_ref="usr-3",
            idempotency_key="idemp-3",
        )

        state = resp.authorization_url.split("state=")[1].split("&")[0]

        # Explicit False in phone_number_verified
        mock_id_claims = {"sub": "fayda:user:789"}
        mock_userinfo_claims = {"phone_number_verified": False}

        with patch.object(service, "_get_private_key", return_value="fake_pem"), \
             patch("fayda_mcp.service.create_client_assertion", return_value="fake.client.assertion"), \
             patch.object(service.jwks, "get_signing_key_for_token", AsyncMock(return_value="fake_key")), \
             patch.object(service._http, "exchange_code", AsyncMock(return_value={"id_token": "mock.id.jwt", "access_token": "at"})), \
             patch("fayda_mcp.service.validate_id_token", return_value=mock_id_claims), \
             patch.object(service._http, "fetch_userinfo", AsyncMock(return_value={})), \
             patch("fayda_mcp.service.validate_userinfo_response", return_value=mock_userinfo_claims):

            result = await service.complete_verification(code="test_code", state=state)

        assert result.status == "rejected"
        assert result.checks["identity_verified"] is True
        assert result.checks["phone_verified"] is False


class TestPrivacyContractAndOutputSchema:
    """Acceptance requirement: Raw phone, email, DOB, and tokens never enter agent outputs."""

    def test_example_response_contract_serialization(self) -> None:
        """Verifies exact JSON shape matching the prompt's example response contract."""
        now_iso = datetime.now(timezone.utc).isoformat()
        res = VerificationResult(
            request_id="vr_example_123",
            status="incomplete",
            checks={
                "identity_verified": True,
                "age_over_21": True,
                "phone_verified": None,
            },
            reasons={"phone_verified": "provider_claim_unavailable"},
            policy_version="v2",
            expires_at=now_iso,
            evidence_ref="ev_vr_example_123",
            verified_at=now_iso,
        )

        dumped = res.model_dump()
        assert dumped["status"] == "incomplete"
        assert dumped["checks"]["identity_verified"] is True
        assert dumped["checks"]["age_over_21"] is True
        assert dumped["checks"]["phone_verified"] is None
        assert dumped["reasons"] == {"phone_verified": "provider_claim_unavailable"}
        assert dumped["policy_version"] == "v2"
        assert dumped["expires_at"] == now_iso

    def test_forbidden_demographic_and_credential_fields(self) -> None:
        """VerificationResult strictly rejects raw demographics, tokens, and credentials."""
        forbidden_fields = {
            "phone_number": "+251911223344",
            "email": "user@example.et",
            "birthdate": "1995-05-12",
            "dob": "1995-05-12",
            "name": "Almaz Ayana",
            "access_token": "secret_token_val",
            "id_token": "raw.jwt.token",
            "refresh_token": "refresh_val",
            "biometrics": "raw_biometric_data",
        }

        for field_name, sample_val in forbidden_fields.items():
            with pytest.raises(ValidationError):
                VerificationResult(
                    request_id="req_test",
                    status="verified",
                    checks={"identity_verified": True},
                    **{field_name: sample_val},  # type: ignore
                )
