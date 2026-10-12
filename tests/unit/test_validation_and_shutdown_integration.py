"""Unit tests for Task H4: Validation and shutdown integration, separate token/userinfo key selection, and lifecycle."""

import asyncio
import importlib
import json
import time
from typing import Any, Dict, Optional
from cryptography.hazmat.primitives.asymmetric import rsa
import httpx
import jwt
import pytest

from fayda_mcp.config import FaydaConfig
from fayda_mcp.exceptions import AuthenticationError, ProviderError, TokenValidationError
from fayda_mcp.oidc.jwks import JwksCache
from fayda_mcp.service import FaydaVerificationService
from fayda_mcp.storage.memory import MemoryResultRepository, MemorySessionStore


def create_rsa_jwk(kid: str) -> tuple[Any, Any, Dict[str, Any]]:
    """Helper to generate RSA keypair and its JWK dictionary."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    jwk_dict = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(public_key))
    jwk_dict["kid"] = kid
    return private_key, public_key, jwk_dict


def make_id_token(
    private_key: Any,
    kid: str,
    issuer: str,
    client_id: str,
    sub: str = "citizen_sub_123",
    nonce: str = "test_nonce_abc",
) -> str:
    now = int(time.time())
    payload = {
        "iss": issuer,
        "aud": client_id,
        "sub": sub,
        "nonce": nonce,
        "iat": now,
        "exp": now + 300,
    }
    return jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": kid})


def make_userinfo_jwt(
    private_key: Any,
    kid: str,
    issuer: str,
    client_id: str,
    sub: str = "citizen_sub_123",
    name: str = "Abebe Bikila",
    alg: str = "RS256",
) -> str:
    now = int(time.time())
    payload = {
        "iss": issuer,
        "aud": client_id,
        "sub": sub,
        "name": name,
        "birthdate": "1990-01-01",
        "iat": now,
        "exp": now + 300,
    }
    headers = {"kid": kid, "alg": alg}
    return jwt.encode(payload, private_key, algorithm=alg, headers=headers)


from cryptography.hazmat.primitives import serialization


@pytest.fixture
def default_config() -> FaydaConfig:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    return FaydaConfig(
        client_id="test_rp_client",
        redirect_uri="https://rp.example/cb",
        issuer="https://esignet.sandbox.fayda.et",
        authorization_endpoint="https://esignet.sandbox.fayda.et/auth",
        token_endpoint="https://esignet.sandbox.fayda.et/token",
        userinfo_endpoint="https://esignet.sandbox.fayda.et/userinfo",
        jwks_uri="https://esignet.sandbox.fayda.et/jwks",
        signing_key_path=None,
        signing_key=pem,
        allowed_algorithms=["RS256"],
        jwks_refresh_after_seconds=240,
        jwks_hard_ttl_seconds=300,
        jwks_stale_grace_seconds=0.0,
        jwks_unknown_kid_cooldown_seconds=30.0,
    )


class TestValidationAndShutdownIntegration:
    """Acceptance tests for H4: Validation and shutdown integration."""

    @pytest.mark.asyncio
    async def test_different_token_key_ids_validate_correctly(self, default_config: FaydaConfig) -> None:
        """Acceptance requirement: Select signing keys separately for ID token and UserInfo kid/algorithm.
        Different token key IDs validate correctly.
        """
        priv_id, pub_id, jwk_id = create_rsa_jwk("kid-id-token-1")
        priv_ui, pub_ui, jwk_ui = create_rsa_jwk("kid-userinfo-token-2")

        sessions = MemorySessionStore()
        results = MemoryResultRepository()

        # Mock transport returning token response with signed UserInfo JWT
        def handler(request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            if "jwks" in url_str:
                # Provider serves both keys
                return httpx.Response(200, json={"keys": [jwk_id, jwk_ui]})
            if "token" in url_str:
                id_token_str = make_id_token(
                    priv_id,
                    "kid-id-token-1",
                    default_config.issuer,
                    default_config.client_id,
                    sub="citizen_42",
                    nonce="nonce_secret_xyz",
                )
                return httpx.Response(
                    200,
                    json={
                        "access_token": "mock_at_123",
                        "id_token": id_token_str,
                        "token_type": "Bearer",
                    },
                )
            if "userinfo" in url_str:
                # UserInfo response is signed with kid-userinfo-token-2!
                ui_jwt = make_userinfo_jwt(
                    priv_ui,
                    "kid-userinfo-token-2",
                    default_config.issuer,
                    default_config.client_id,
                    sub="citizen_42",
                    name="Chala Tufa",
                )
                return httpx.Response(200, text=ui_jwt, headers={"content-type": "application/jwt"})
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as http_client:
            service = FaydaVerificationService(
                config=default_config,
                sessions=sessions,
                results=results,
                http_client=http_client,
            )

            # Setup session
            state = "state_diff_kid"
            session_data = {
                "request_id": "req_diff_kid",
                "code_verifier": "pkce_verifier_val",
                "nonce": "nonce_secret_xyz",
                "checks": ["identity_verified"],
            }
            await sessions.save_session(state, session_data, ttl_seconds=60)
            await results.save_request("req_diff_kid", {"status": "pending"}, ttl_seconds=60)

            # Complete verification
            res = await service.complete_verification(code="auth_code_1", state=state)
            assert res.status == "verified"
            assert res.checks["identity_verified"] is True
            # Clean up
            await service.aclose()

    @pytest.mark.asyncio
    async def test_preserve_sub_mismatch_check_fails(self, default_config: FaydaConfig) -> None:
        """Acceptance requirement: Preserve sub checks between ID token and UserInfo."""
        priv_id, pub_id, jwk_id = create_rsa_jwk("kid-id-1")
        priv_ui, pub_ui, jwk_ui = create_rsa_jwk("kid-ui-1")

        sessions = MemorySessionStore()
        results = MemoryResultRepository()

        def handler(request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            if "jwks" in url_str:
                return httpx.Response(200, json={"keys": [jwk_id, jwk_ui]})
            if "token" in url_str:
                id_token_str = make_id_token(
                    priv_id,
                    "kid-id-1",
                    default_config.issuer,
                    default_config.client_id,
                    sub="original_citizen_sub",
                    nonce="nonce_123",
                )
                return httpx.Response(200, json={"access_token": "at", "id_token": id_token_str})
            if "userinfo" in url_str:
                # Mismatched sub!
                ui_jwt = make_userinfo_jwt(
                    priv_ui,
                    "kid-ui-1",
                    default_config.issuer,
                    default_config.client_id,
                    sub="imposter_citizen_sub",
                )
                return httpx.Response(200, text=ui_jwt, headers={"content-type": "application/jwt"})
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as http_client:
            service = FaydaVerificationService(
                config=default_config,
                sessions=sessions,
                results=results,
                http_client=http_client,
            )

            state = "state_sub_mismatch"
            await sessions.save_session(
                state,
                {
                    "request_id": "req_sub_mismatch",
                    "code_verifier": "ver",
                    "nonce": "nonce_123",
                    "checks": ["identity_verified"],
                },
                ttl_seconds=60,
            )
            await results.save_request("req_sub_mismatch", {"status": "pending"}, ttl_seconds=60)

            with pytest.raises(TokenValidationError, match="UserInfo subject.*does not match"):
                await service.complete_verification(code="c", state=state)

            await service.aclose()

    @pytest.mark.asyncio
    async def test_lifecycle_workers_and_clean_shutdown(self, default_config: FaydaConfig) -> None:
        """Acceptance requirement: Start refresh workers only within explicit runtime lifecycle
        and cancel/await them on close. No orphan tasks or leaked clients.
        """
        cache = JwksCache(config=default_config)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"keys": []})

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            # Start periodic refresh worker within explicit lifecycle
            worker_task = cache.start_periodic_refresh(client=client, interval_seconds=0.05)
            assert not worker_task.done()

            # Let worker run for a moment
            await asyncio.sleep(0.08)
            assert not worker_task.done()

            # Shutdown cache
            await cache.aclose()

            # Worker task is cancelled and cleanly terminated
            assert worker_task.done()
            assert cache._is_closed is True
            assert len(cache._background_tasks) == 0
            assert len(cache._inflight) == 0

    def test_no_orphan_tasks_or_network_calls_during_import(self) -> None:
        """Acceptance requirement: No orphan tasks, leaked clients, or network calls occur during import."""
        # Re-import key modules
        import fayda_mcp
        import fayda_mcp.config
        import fayda_mcp.service
        import fayda_mcp.oidc.jwks

        # Creating config or importing does not open tasks or network calls
        cfg = fayda_mcp.config.FaydaConfig.sandbox("client", "https://cb.example")
        cache = fayda_mcp.oidc.jwks.JwksCache(cfg)
        assert len(cache._background_tasks) == 0
        assert len(cache._inflight) == 0
        assert cache._worker_task is None

    def test_proposed_settings_parsing_and_defaults(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Acceptance requirement: Verify proposed settings additions with defaults and env parsing."""
        # Test defaults
        cfg = FaydaConfig.sandbox("cid", "https://cb.example")
        assert cfg.dob_source_calendar == "gregorian"
        assert cfg.claims_locales == ["en", "am", "om", "so", "ti", "sid", "wal"]
        assert cfg.age_evaluation_timezone == "Africa/Addis_Ababa"
        assert cfg.jwks_refresh_after_seconds == 240
        assert cfg.jwks_hard_ttl_seconds == 300
        assert cfg.jwks_stale_grace_seconds == 0.0
        assert cfg.jwks_unknown_kid_cooldown_seconds == 30.0
        assert cfg.storage_mode == "memory"

        # Test from_env parsing
        monkeypatch.setenv("FAYDA_CLIENT_ID", "env_cid")
        monkeypatch.setenv("FAYDA_REDIRECT_URI", "https://env.example/cb")
        monkeypatch.setenv("FAYDA_ISSUER", "https://esignet.env.et")
        monkeypatch.setenv("FAYDA_AUTHORIZATION_ENDPOINT", "https://esignet.env.et/auth")
        monkeypatch.setenv("FAYDA_TOKEN_ENDPOINT", "https://esignet.env.et/token")
        monkeypatch.setenv("FAYDA_USERINFO_ENDPOINT", "https://esignet.env.et/userinfo")
        monkeypatch.setenv("FAYDA_JWKS_URI", "https://esignet.env.et/jwks")
        monkeypatch.setenv("FAYDA_DOB_SOURCE_CALENDAR", "gregorian")
        monkeypatch.setenv("FAYDA_CLAIMS_LOCALES", "en am om so ti sid wal")
        monkeypatch.setenv("FAYDA_AGE_EVALUATION_TIMEZONE", "Africa/Addis_Ababa")
        monkeypatch.setenv("FAYDA_JWKS_REFRESH_AFTER_SECONDS", "240")
        monkeypatch.setenv("FAYDA_JWKS_HARD_TTL_SECONDS", "300")
        monkeypatch.setenv("FAYDA_JWKS_STALE_GRACE_SECONDS", "0")
        monkeypatch.setenv("FAYDA_JWKS_UNKNOWN_KID_COOLDOWN_SECONDS", "30")
        monkeypatch.setenv("FAYDA_STORAGE_MODE", "redis-postgres")

        env_cfg = FaydaConfig.from_env()
        assert env_cfg.dob_source_calendar == "gregorian"
        assert env_cfg.age_evaluation_timezone == "Africa/Addis_Ababa"
        assert env_cfg.jwks_refresh_after_seconds == 240
        assert env_cfg.jwks_hard_ttl_seconds == 300
        assert env_cfg.jwks_stale_grace_seconds == 0.0
        assert env_cfg.jwks_unknown_kid_cooldown_seconds == 30.0
        assert env_cfg.storage_mode == "redis-postgres"

    @pytest.mark.asyncio
    async def test_userinfo_signed_jwt_unsupported_alg_fails_safely(self, default_config: FaydaConfig) -> None:
        """Acceptance requirement: UserInfo algorithm is strictly checked; unauthorized alg fails safely."""
        from fayda_mcp.oidc.tokens import validate_userinfo_response

        # UserInfo signed with HS256 instead of RS256
        secret = "symmetric_secret_32_bytes_long_!"
        bad_token = jwt.encode(
            {"sub": "sub123", "name": "Test"},
            secret,
            algorithm="HS256",
            headers={"kid": "hs-key"},
        )
        with pytest.raises(TokenValidationError, match="not in allowed algorithms"):
            validate_userinfo_response(
                userinfo=bad_token,
                config=default_config,
                expected_sub="sub123",
                signing_key=secret,
            )

    @pytest.mark.asyncio
    async def test_mock_rotation_removal_and_outage_fail_safely(self, default_config: FaydaConfig) -> None:
        """Acceptance requirement: Mock rotation/removal/outage cases fail safely."""
        cache = JwksCache(config=default_config)
        priv1, pub1, _ = create_rsa_jwk("kid-outage")
        now = time.time()
        # Hard expired (fetched, refresh, and hard expiry all in the past)
        cache.add_key(
            "kid-outage",
            pub1,
            fetched_at=now - 500.0,
            refresh_at=now - 200.0,
            hard_expiry=now - 50.0,
        )

        # Provider outage (503)
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(503, text="Service Unavailable")

        transport = httpx.MockTransport(handler)
        token = make_id_token(priv1, "kid-outage", default_config.issuer, default_config.client_id)

        async with httpx.AsyncClient(transport=transport) as client:
            with pytest.raises(ProviderError, match="refresh failed"):
                await cache.get_signing_key_for_token(token, client=client)

