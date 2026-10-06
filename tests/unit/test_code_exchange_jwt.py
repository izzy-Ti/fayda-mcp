"""Unit tests for B2 Code exchange and JWT validation."""

import time
import uuid
import pytest
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import httpx
from fayda_mcp import (
    FaydaConfig,
    FaydaVerificationService,
    InvalidStateError,
    TokenValidationError,
    AuthenticationError,
)
from fayda_mcp.storage.memory import MemoryResultRepository, MemorySessionStore
from fayda_mcp.oidc.assertions import create_client_assertion
from fayda_mcp.oidc.tokens import validate_id_token, validate_userinfo_response
from fayda_mcp.oidc.jwks import JwksCache


@pytest.fixture
def rsa_key_pair():
    """Generate temporary RSA keypair for tests."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key


@pytest.fixture
def default_config():
    return FaydaConfig(
        client_id="test-client-id",
        redirect_uri="https://developer-app.example/auth/fayda/callback",
        issuer="https://esignet.sandbox.fayda.et",
        authorization_endpoint="https://esignet.sandbox.fayda.et/authorize",
        token_endpoint="https://esignet.sandbox.fayda.et/oauth/token",
        userinfo_endpoint="https://esignet.sandbox.fayda.et/oidc/userinfo",
        jwks_uri="https://esignet.sandbox.fayda.et/jwks.json",
        allowed_algorithms=["RS256"],
        jwt_clock_skew_seconds=0,
    )


def build_id_token(
    private_key,
    config: FaydaConfig,
    sub: str = "citizen_123",
    aud: str = None,
    iss: str = None,
    nonce: str = "valid-nonce",
    exp_delta: int = 300,
    algorithm: str = "RS256",
    headers: dict = None,
) -> str:
    now = int(time.time())
    payload = {
        "iss": iss if iss is not None else config.issuer,
        "aud": aud if aud is not None else config.client_id,
        "sub": sub,
        "nonce": nonce,
        "iat": now,
        "exp": now + exp_delta,
    }
    jwt_headers = {"alg": algorithm, "typ": "JWT", "kid": "key-1"}
    if headers:
        jwt_headers.update(headers)
    return jwt.encode(payload, private_key, algorithm=algorithm, headers=jwt_headers)


def test_private_key_jwt_client_assertion(rsa_key_pair, default_config):
    """Verify private_key_jwt client assertion conforms to RFC 7523."""
    priv, pub = rsa_key_pair
    assertion = create_client_assertion(config=default_config, private_key=priv)

    decoded = jwt.decode(
        assertion,
        pub,
        algorithms=["RS256"],
        audience=default_config.token_endpoint,
        issuer=default_config.client_id,
    )
    assert decoded["sub"] == default_config.client_id
    assert decoded["aud"] == default_config.token_endpoint
    assert "jti" in decoded
    assert decoded["exp"] > decoded["iat"]


def test_wrong_issuer_fails(rsa_key_pair, default_config):
    """Acceptance requirement: Wrong issuer fails."""
    priv, pub = rsa_key_pair
    bad_token = build_id_token(priv, default_config, iss="https://imposter.example.com")

    with pytest.raises(TokenValidationError, match="Invalid ID token signature or claims"):
        validate_id_token(bad_token, default_config, signing_key=pub)


def test_wrong_audience_fails(rsa_key_pair, default_config):
    """Acceptance requirement: Wrong audience fails."""
    priv, pub = rsa_key_pair
    bad_token = build_id_token(priv, default_config, aud="other-client-id")

    with pytest.raises(TokenValidationError, match="Invalid ID token signature or claims"):
        validate_id_token(bad_token, default_config, signing_key=pub)


def test_expired_jwt_fails(rsa_key_pair, default_config):
    """Acceptance requirement: Expired JWT fails."""
    priv, pub = rsa_key_pair
    # Expired 60 seconds ago
    bad_token = build_id_token(priv, default_config, exp_delta=-60)

    with pytest.raises(TokenValidationError, match="Invalid ID token signature or claims"):
        validate_id_token(bad_token, default_config, signing_key=pub)


def test_unsigned_jwt_fails(rsa_key_pair, default_config):
    """Acceptance requirement: Expired or unsigned JWT fails."""
    # alg=none token
    header = {"alg": "none", "typ": "JWT"}
    payload = {
        "iss": default_config.issuer,
        "aud": default_config.client_id,
        "sub": "user_none",
        "exp": int(time.time()) + 300,
    }
    # Unsigned token string
    raw_token = f"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJ7ZGVmYXVsdF9jb25maWcuaXNzdWVyfSIsInN1YiI6InVzZXJibm9uZSJ9."

    with pytest.raises(TokenValidationError, match="Unsigned JWT"):
        validate_id_token(raw_token, default_config, signing_key="dummy")


def test_incorrect_nonce_fails(rsa_key_pair, default_config):
    """Acceptance requirement: Incorrect nonce fails."""
    priv, pub = rsa_key_pair
    token = build_id_token(priv, default_config, nonce="token-nonce-123")

    with pytest.raises(TokenValidationError, match="nonce 'token-nonce-123' does not match"):
        validate_id_token(
            token, default_config, signing_key=pub, expected_nonce="expected-nonce-999"
        )


def test_mismatched_sub_fails(rsa_key_pair, default_config):
    """Acceptance requirement: Mismatched sub fails."""
    # UserInfo with sub different from ID token
    userinfo_data = {"sub": "imposter_sub", "name": "Abebe"}

    with pytest.raises(TokenValidationError, match="UserInfo subject 'imposter_sub' does not match"):
        validate_userinfo_response(
            userinfo=userinfo_data,
            config=default_config,
            expected_sub="original_citizen_sub",
        )


@pytest.mark.asyncio
async def test_reused_state_fails(default_config):
    """Acceptance requirement: Reused state fails."""
    sessions = MemorySessionStore()
    results = MemoryResultRepository()
    service = FaydaVerificationService(
        config=default_config, sessions=sessions, results=results
    )

    state = "state_reused_test"
    session_data = {
        "request_id": "vr_reuse_1",
        "code_verifier": "pkce_verifier_1",
        "nonce": "nonce_1",
        "checks": ["identity_verified"],
    }
    await sessions.save_session(state, session_data, ttl_seconds=60)
    await results.save_request("vr_reuse_1", {"status": "pending"}, ttl_seconds=60)

    # 1st call consumes state (fails after consuming due to missing signing key)
    with pytest.raises(Exception):
        await service.complete_verification(code="code_1", state=state)

    # 2nd call with same state fails with InvalidStateError
    with pytest.raises(InvalidStateError, match="invalid, expired, or already used"):
        await service.complete_verification(code="code_1", state=state)


@pytest.mark.asyncio
async def test_bad_pkce_code_exchange_fails(default_config):
    """Acceptance requirement: Bad PKCE fails during code exchange."""
    from fayda_mcp.oidc.client import FaydaHttpClient

    # Mock transport returning 400 invalid_grant for bad PKCE verifier
    def handler(request: httpx.Request) -> httpx.Response:
        data = urllib_parse_body(request.read().decode())
        if data.get("code_verifier") == "bad_verifier":
            return httpx.Response(
                400,
                json={"error": "invalid_grant", "error_description": "PKCE verification failed"},
            )
        return httpx.Response(200, json={"access_token": "at", "id_token": "it"})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        http_client = FaydaHttpClient(config=default_config, client=client)
        with pytest.raises(AuthenticationError, match="PKCE verification failed"):
            await http_client.exchange_code(
                code="auth_code_1",
                code_verifier="bad_verifier",
                client_assertion="assertion_jwt",
            )


def urllib_parse_body(body_str: str) -> dict:
    import urllib.parse
    return {k: v[0] for k, v in urllib.parse.parse_qs(body_str).items()}
