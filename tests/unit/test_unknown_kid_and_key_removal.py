"""Unit tests for Task H3: Unknown kid, negative cache, cooldown, key removal, and stale-while-revalidate."""

import asyncio
import json
import time
from typing import Any, Dict
from cryptography.hazmat.primitives.asymmetric import rsa
import httpx
import jwt
import pytest

from fayda_mcp.config import FaydaConfig
from fayda_mcp.exceptions import ProviderError, TokenValidationError
from fayda_mcp.oidc.jwks import JwksCache


def create_rsa_jwk(kid: str) -> tuple[Any, Any, Dict[str, Any]]:
    """Helper to generate RSA keypair and its JWK dictionary."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    jwk_dict = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(public_key))
    jwk_dict["kid"] = kid
    return private_key, public_key, jwk_dict


def make_token(
    private_key: Any,
    kid: Optional[str],
    issuer: str,
    client_id: str,
    headers: Optional[Dict[str, Any]] = None,
    alg: str = "RS256",
) -> str:
    """Helper to create a signed test JWT."""
    now = int(time.time())
    payload = {
        "iss": issuer,
        "aud": client_id,
        "sub": "citizen_123",
        "iat": now,
        "exp": now + 300,
        "nonce": "test_nonce",
    }
    jwt_headers: Dict[str, Any] = {"alg": alg}
    if kid:
        jwt_headers["kid"] = kid
    if headers:
        jwt_headers.update(headers)

    if alg.lower() == "none":
        import base64
        h = base64.urlsafe_b64encode(json.dumps(jwt_headers).encode()).decode().rstrip("=")
        p = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        return f"{h}.{p}."

    return jwt.encode(payload, private_key, algorithm=alg, headers=jwt_headers)


@pytest.fixture
def test_config() -> FaydaConfig:
    return FaydaConfig(
        client_id="test_client_id",
        redirect_uri="https://app.example/cb",
        issuer="https://esignet.sandbox.fayda.et",
        authorization_endpoint="https://esignet.sandbox.fayda.et/auth",
        token_endpoint="https://esignet.sandbox.fayda.et/token",
        userinfo_endpoint="https://esignet.sandbox.fayda.et/userinfo",
        jwks_uri="https://esignet.sandbox.fayda.et/jwks",
        jwks_cache_ttl_seconds=300,
        jwks_unknown_kid_cooldown_seconds=5.0,
        jwks_negative_cache_ttl_seconds=10.0,
        jwks_stale_grace_seconds=0.0,
    )


class TestUnknownKidAndKeyRemoval:
    """Acceptance tests for H3: Unknown kid and key removal."""

    @pytest.mark.asyncio
    async def test_new_legitimate_keys_work_without_restart(self, test_config: FaydaConfig) -> None:
        """Acceptance requirement: New legitimate keys work without restart."""
        priv1, pub1, jwk1 = create_rsa_jwk("kid-old-1")
        priv2, pub2, jwk2 = create_rsa_jwk("kid-new-2")
        cache = JwksCache(config=test_config)

        # Pre-seed cache with only kid-old-1
        cache.add_key("kid-old-1", pub1)

        request_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal request_count
            request_count += 1
            # Provider now publishes both kid-old-1 and kid-new-2
            return httpx.Response(200, json={"keys": [jwk1, jwk2]})

        token_str = make_token(priv2, "kid-new-2", test_config.issuer, test_config.client_id)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            resolved_key = await cache.get_signing_key_for_token(token_str, client=client)

        assert resolved_key == pub2
        assert request_count == 1

    @pytest.mark.asyncio
    async def test_unknown_kid_floods_do_not_create_unbounded_network_calls(
        self, test_config: FaydaConfig
    ) -> None:
        """Acceptance requirement: Unknown-kid floods do not create unbounded network calls."""
        priv_fake, _, _ = create_rsa_jwk("fake")
        cache = JwksCache(config=test_config, unknown_kid_cooldown_seconds=10.0)

        network_calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal network_calls
            network_calls += 1
            # Empty keys returned
            return httpx.Response(200, json={"keys": []})

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            # Attacker sends 50 different unknown kids in rapid succession
            for i in range(50):
                bad_token = make_token(priv_fake, f"unknown-flood-{i}", test_config.issuer, test_config.client_id)
                with pytest.raises(TokenValidationError):
                    await cache.get_signing_key_for_token(bad_token, client=client)

        # The first request refreshed; remaining 49 requests were blocked by cooldown / negative cache
        assert network_calls == 1

    @pytest.mark.asyncio
    async def test_negative_cache_suppresses_repeated_bad_kid(self, test_config: FaydaConfig) -> None:
        """Verify negative cache rejects repeated requests for the same absent kid."""
        priv_fake, _, _ = create_rsa_jwk("absent-1")
        cache = JwksCache(config=test_config, unknown_kid_cooldown_seconds=0.0, negative_cache_ttl_seconds=30.0)

        network_calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal network_calls
            network_calls += 1
            return httpx.Response(200, json={"keys": []})

        transport = httpx.MockTransport(handler)
        token = make_token(priv_fake, "absent-1", test_config.issuer, test_config.client_id)

        async with httpx.AsyncClient(transport=transport) as client:
            # 1st call executes network refresh
            with pytest.raises(TokenValidationError):
                await cache.get_signing_key_for_token(token, client=client)
            assert network_calls == 1

            # 2nd and 3rd calls hit negative cache directly (0 network calls)
            for _ in range(5):
                with pytest.raises(TokenValidationError, match="negative cache"):
                    await cache.get_signing_key_for_token(token, client=client)
            assert network_calls == 1

    @pytest.mark.asyncio
    async def test_removed_keys_do_not_remain_indefinitely_trusted(self, test_config: FaydaConfig) -> None:
        """Acceptance requirement: Removed keys do not remain indefinitely trusted (atomic replacement)."""
        priv_old, pub_old, jwk_old = create_rsa_jwk("kid-revoked")
        priv_new, pub_new, jwk_new = create_rsa_jwk("kid-active")
        cache = JwksCache(config=test_config)

        # Initially, cache knows both keys
        cache.add_key("kid-revoked", pub_old)
        cache.add_key("kid-active", pub_new)

        # Provider revokes kid-revoked, publishing only kid-active
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"keys": [jwk_new]})

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            # Trigger refresh to replace authoritative set
            await cache.fetch_jwks(client)

            # Token signed with kid-active succeeds
            token_active = make_token(priv_new, "kid-active", test_config.issuer, test_config.client_id)
            key = await cache.get_signing_key_for_token(token_active, client=client)
            assert key == pub_new

            # Token signed with kid-revoked MUST be rejected
            token_revoked = make_token(priv_old, "kid-revoked", test_config.issuer, test_config.client_id)
            with pytest.raises(TokenValidationError):
                await cache.get_signing_key_for_token(token_revoked, client=client)

    @pytest.mark.asyncio
    async def test_zero_stale_grace_fails_closed_on_refresh_error(self, test_config: FaydaConfig) -> None:
        """Acceptance requirement: Use zero stale grace when required (fails closed on refresh error)."""
        priv1, pub1, _ = create_rsa_jwk("kid-stale-test")
        cache = JwksCache(config=test_config, stale_grace_seconds=0.0)

        now = time.time()
        # Key is past hard expiry
        cache.add_key(
            kid="kid-stale-test",
            key=pub1,
            fetched_at=now - 500.0,
            refresh_at=now - 200.0,
            hard_expiry=now - 10.0,
        )

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="Internal Server Error")

        token_str = make_token(priv1, "kid-stale-test", test_config.issuer, test_config.client_id)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            with pytest.raises(ProviderError, match="zero stale grace"):
                await cache.get_signing_key_for_token(token_str, client=client)

    @pytest.mark.asyncio
    async def test_bounded_hard_stale_window_permits_known_cached_key(self, test_config: FaydaConfig) -> None:
        """Acceptance requirement: Refresh error permits known cached keys inside approved hard-stale window."""
        priv1, pub1, _ = create_rsa_jwk("kid-stale-grace")
        # 60s hard-stale window approved by host policy
        cache = JwksCache(config=test_config, stale_grace_seconds=60.0)

        now = time.time()
        # Hard expiry was 10s ago, well within the 60s grace window
        cache.add_key(
            kid="kid-stale-grace",
            key=pub1,
            fetched_at=now - 500.0,
            refresh_at=now - 200.0,
            hard_expiry=now - 10.0,
        )

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(503, text="Service Unavailable")

        token_str = make_token(priv1, "kid-stale-grace", test_config.issuer, test_config.client_id)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            # Within the approved hard-stale window, known cached key is permitted
            key = await cache.get_signing_key_for_token(token_str, client=client)
            assert key == pub1

    @pytest.mark.asyncio
    async def test_exceeded_hard_stale_window_fails_closed(self, test_config: FaydaConfig) -> None:
        """Acceptance requirement: Beyond approved hard-stale window, fails closed even if known key."""
        priv1, pub1, _ = create_rsa_jwk("kid-stale-exceeded")
        cache = JwksCache(config=test_config, stale_grace_seconds=60.0)

        now = time.time()
        # Hard expiry was 100s ago, exceeding the 60s grace window
        cache.add_key(
            kid="kid-stale-exceeded",
            key=pub1,
            fetched_at=now - 500.0,
            refresh_at=now - 200.0,
            hard_expiry=now - 100.0,
        )

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="Internal Server Error")

        token_str = make_token(priv1, "kid-stale-exceeded", test_config.issuer, test_config.client_id)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            with pytest.raises(ProviderError):
                await cache.get_signing_key_for_token(token_str, client=client)

    @pytest.mark.asyncio
    async def test_unsigned_jwt_and_token_supplied_jku_rejected(self, test_config: FaydaConfig) -> None:
        """Acceptance requirement: Never fall back to unsigned decoding or token-supplied jku/x5u URLs."""
        priv1, pub1, jwk1 = create_rsa_jwk("kid-sec-1")
        cache = JwksCache(config=test_config)

        transport = httpx.MockTransport(lambda r: httpx.Response(200, json={"keys": [jwk1]}))
        async with httpx.AsyncClient(transport=transport) as client:
            # 1. Unsigned JWT (alg=none) is rejected
            unsigned_token = make_token(priv1, "kid-sec-1", test_config.issuer, test_config.client_id, alg="none")
            with pytest.raises(TokenValidationError, match="alg=none"):
                await cache.get_signing_key_for_token(unsigned_token, client=client)

            # 2. Token injecting attacker jku header
            attacker_requested = False

            def attacker_handler(request: httpx.Request) -> httpx.Response:
                nonlocal attacker_requested
                if "evil.attacker.com" in str(request.url):
                    attacker_requested = True
                    return httpx.Response(200, json={"keys": []})
                return httpx.Response(200, json={"keys": [jwk1]})

            trans_attacker = httpx.MockTransport(attacker_handler)
            async with httpx.AsyncClient(transport=trans_attacker) as client_sec:
                token_with_jku = make_token(
                    priv1,
                    "kid-sec-1",
                    test_config.issuer,
                    test_config.client_id,
                    headers={"jku": "https://evil.attacker.com/jwks.json"},
                )
                key = await cache.get_signing_key_for_token(token_with_jku, client=client_sec)
                assert key == pub1
                # Attacker's injected jku endpoint was NEVER requested
                assert attacker_requested is False
