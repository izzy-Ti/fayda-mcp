"""Unit tests for B1 OIDC authorization."""

import json
import urllib.parse
import pytest
from fayda_mcp import (
    CallerContext,
    FaydaConfig,
    FaydaVerificationService,
    PolicyViolationError,
    VerificationPolicy,
)
from fayda_mcp.storage.memory import MemoryResultRepository, MemorySessionStore
from fayda_mcp.oidc.authorization import (
    build_authorization_url,
    generate_pkce_pair,
    generate_secure_token,
)


def create_test_service(policy: VerificationPolicy = None) -> FaydaVerificationService:
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


def test_pkce_generation_rfc7636():
    """Verify PKCE S256 code_verifier and code_challenge comply with RFC 7636."""
    import base64
    import hashlib

    verifier, challenge = generate_pkce_pair()

    assert len(verifier) >= 43
    assert "=" not in challenge

    # Re-compute challenge from verifier
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    expected_challenge = base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")
    assert challenge == expected_challenge


@pytest.mark.asyncio
async def test_each_request_has_unique_short_lived_state():
    """Acceptance requirement: Each request has unique short-lived state."""
    service = create_test_service()
    ctx = CallerContext(tenant_id="tenant-1", principal_id="agent-1")

    states = set()
    nonces = set()
    request_ids = set()

    for i in range(50):
        resp = await service.start_verification(
            context=ctx,
            purpose="onboarding",
            checks=["identity_verified"],
            application_user_ref=f"user-{i}",
            idempotency_key=f"idemp-{i}",
        )
        request_ids.add(resp.request_id)

        parsed = urllib.parse.urlparse(resp.authorization_url)
        params = urllib.parse.parse_qs(parsed.query)

        state = params["state"][0]
        nonce = params["nonce"][0]
        challenge = params["code_challenge"][0]

        assert state not in states, "State must be globally unique per request"
        assert nonce not in nonces, "Nonce must be globally unique per request"

        states.add(state)
        nonces.add(nonce)

        # Verify session was stored in session store with correct bindings
        session_data = await service.sessions.get_session(state)
        assert session_data is not None
        assert session_data["request_id"] == resp.request_id
        assert session_data["tenant_id"] == "tenant-1"
        assert session_data["principal_id"] == "agent-1"
        assert session_data["application_user_ref"] == f"user-{i}"
        assert session_data["nonce"] == nonce

    assert len(states) == 50
    assert len(nonces) == 50
    assert len(request_ids) == 50


@pytest.mark.asyncio
async def test_unsupported_purpose_fails_before_redirect():
    """Acceptance requirement: Unsupported purpose requests fail before redirect."""
    service = create_test_service()
    ctx = CallerContext()

    # Purpose not in allowed_purposes
    with pytest.raises(PolicyViolationError, match="Unsupported purpose"):
        await service.start_verification(
            context=ctx,
            purpose="unauthorized_marketing",
            checks=["identity_verified"],
            application_user_ref="u1",
            idempotency_key="k1",
        )

    # Empty purpose
    with pytest.raises(PolicyViolationError, match="must not be empty"):
        await service.start_verification(
            context=ctx,
            purpose="",
            checks=["identity_verified"],
            application_user_ref="u1",
            idempotency_key="k2",
        )


@pytest.mark.asyncio
async def test_unsupported_check_fails_before_redirect():
    """Acceptance requirement: Unsupported claim/check requests fail before redirect."""
    service = create_test_service()
    ctx = CallerContext()

    # Unsupported check (e.g. biometric_fingerprint, credit_score)
    with pytest.raises(PolicyViolationError, match="Unsupported check"):
        await service.start_verification(
            context=ctx,
            purpose="kyc",
            checks=["biometric_fingerprint"],
            application_user_ref="u1",
            idempotency_key="k3",
        )

    # Empty checks
    with pytest.raises(PolicyViolationError, match="At least one verification check"):
        await service.start_verification(
            context=ctx,
            purpose="kyc",
            checks=[],
            application_user_ref="u1",
            idempotency_key="k4",
        )


@pytest.mark.asyncio
async def test_authorization_url_scopes_and_claims_binding():
    """Verify authorization URL properly encodes approved scopes and essential claims."""
    service = create_test_service()
    ctx = CallerContext()

    resp = await service.start_verification(
        context=ctx,
        purpose="kyc",
        checks=["identity_verified", "age_over_18"],
        application_user_ref="user-xyz",
        idempotency_key="key-xyz",
    )

    parsed = urllib.parse.urlparse(resp.authorization_url)
    params = urllib.parse.parse_qs(parsed.query)

    # Base query params
    assert params["response_type"][0] == "code"
    assert params["client_id"][0] == "test-client-id"
    assert params["redirect_uri"][0] == "https://developer-app.example/auth/fayda/callback"
    assert params["code_challenge_method"][0] == "S256"

    # Scopes
    scopes = set(params["scope"][0].split())
    assert "openid" in scopes
    assert "profile" in scopes

    # Claims parameter
    assert "claims" in params
    claims_obj = json.loads(params["claims"][0])
    assert "userinfo" in claims_obj
    assert "birthdate" in claims_obj["userinfo"]
    assert claims_obj["userinfo"]["birthdate"]["essential"] is True
