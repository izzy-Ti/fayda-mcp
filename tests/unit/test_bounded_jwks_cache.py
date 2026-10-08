"""Unit tests for Task H2: Bounded JWKS cache, single-flight lock, background refresh, and backoff."""

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
from fayda_mcp.oidc.jwks import JwksCache, JwksCacheEntry


def create_rsa_jwk(kid: str) -> tuple[Any, Any, Dict[str, Any]]:
    """Helper to generate RSA keypair and its JWK dictionary."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    jwk_dict = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(public_key))
    jwk_dict["kid"] = kid
    return private_key, public_key, jwk_dict


def make_token(private_key: Any, kid: str, issuer: str, client_id: str) -> str:
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
    return jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": kid})


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
        jwks_refresh_factor=0.8,
        jwks_hard_expiry_factor=2.0,
        jwks_jitter_ratio=0.05,
        jwks_base_backoff_seconds=1.0,
        jwks_max_backoff_seconds=10.0,
        http_timeout_seconds=5.0,
    )


class TestBoundedJwksCache:
    """Acceptance tests for H2: Bounded JWKS cache."""

    @pytest.mark.asyncio
    async def test_concurrent_known_kid_validation_uses_cache(self, test_config: FaydaConfig) -> None:
        """Acceptance requirement: Concurrent known-kid validation uses cache (zero network calls)."""
        priv1, pub1, _ = create_rsa_jwk("kid-fresh-1")
        cache = JwksCache(config=test_config)

        # Manually register key in cache as fresh
        now = time.time()
        cache.add_key(
            kid="kid-fresh-1",
            key=pub1,
            fetched_at=now,
            refresh_at=now + 200.0,
            hard_expiry=now + 500.0,
        )

        request_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal request_count
            request_count += 1
            return httpx.Response(200, json={"keys": []})

        token_str = make_token(priv1, "kid-fresh-1", test_config.issuer, test_config.client_id)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            # Run 50 concurrent validation calls
            tasks = [
                cache.get_signing_key_for_token(token_str, client=client)
                for _ in range(50)
            ]
            results = await asyncio.gather(*tasks)

        # All 50 returned cached key
        assert len(results) == 50
        assert all(r == pub1 for r in results)
        # Zero network requests executed
        assert request_count == 0

    @pytest.mark.asyncio
    async def test_near_refresh_triggers_one_job_and_uses_cache(self, test_config: FaydaConfig) -> None:
        """Acceptance requirement: Near-refresh triggers one job. Concurrent requests use cache."""
        priv1, pub1, _ = create_rsa_jwk("kid-near-1")
        _, pub2, jwk2 = create_rsa_jwk("kid-near-1")  # refreshed key
        cache = JwksCache(config=test_config)

        now = time.time()
        # Near refresh: refresh_at is in the past, hard_expiry is in the future
        cache.add_key(
            kid="kid-near-1",
            key=pub1,
            fetched_at=now - 250.0,
            refresh_at=now - 10.0,
            hard_expiry=now + 200.0,
        )

        request_count = 0

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal request_count
            request_count += 1
            # Simulate slight network delay
            await asyncio.sleep(0.05)
            return httpx.Response(200, json={"keys": [jwk2]})

        token_str = make_token(priv1, "kid-near-1", test_config.issuer, test_config.client_id)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            # 20 concurrent requests during near-refresh window
            tasks = [
                cache.get_signing_key_for_token(token_str, client=client)
                for _ in range(20)
            ]
            results = await asyncio.gather(*tasks)

            # All 20 returned cached key immediately without waiting
            assert len(results) == 20
            assert all(r == pub1 for r in results)

            # Await background tasks to complete
            await asyncio.sleep(0.1)

        # Exactly ONE background refresh job was triggered
        assert request_count == 1

        # Cache entry was updated after background job finished
        entry = cache.get_entry()
        assert entry is not None
        assert entry.fetched_at > now - 5.0
        assert entry.refresh_at > now

    @pytest.mark.asyncio
    async def test_keys_past_hard_expiry_require_successful_refresh(self, test_config: FaydaConfig) -> None:
        """Acceptance requirement: Keys past hard expiry require successful refresh."""
        priv1, pub1, _ = create_rsa_jwk("kid-expired-1")
        priv_refreshed, pub_refreshed, jwk_refreshed = create_rsa_jwk("kid-expired-1")
        cache = JwksCache(config=test_config)

        now = time.time()
        # Past hard expiry: hard_expiry is in the past
        cache.add_key(
            kid="kid-expired-1",
            key=pub1,
            fetched_at=now - 700.0,
            refresh_at=now - 400.0,
            hard_expiry=now - 50.0,
        )

        request_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal request_count
            request_count += 1
            return httpx.Response(200, json={"keys": [jwk_refreshed]})

        token_str = make_token(priv_refreshed, "kid-expired-1", test_config.issuer, test_config.client_id)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            resolved_key = await cache.get_signing_key_for_token(token_str, client=client)

        # Successfully refreshed key was returned
        assert request_count == 1
        assert resolved_key is not None
        # Key must be the refreshed key, not the stale one
        assert resolved_key != pub1

    @pytest.mark.asyncio
    async def test_keys_past_hard_expiry_fail_closed_on_refresh_failure(self, test_config: FaydaConfig) -> None:
        """Acceptance requirement: Keys past hard expiry fail closed if refresh fails."""
        priv1, pub1, _ = create_rsa_jwk("kid-hard-fail-1")
        cache = JwksCache(config=test_config)

        now = time.time()
        # Past hard expiry
        cache.add_key(
            kid="kid-hard-fail-1",
            key=pub1,
            fetched_at=now - 1000.0,
            refresh_at=now - 600.0,
            hard_expiry=now - 10.0,
        )

        def handler(request: httpx.Request) -> httpx.Response:
            # Upstream 500 server error
            return httpx.Response(500, text="Internal Server Error")

        token_str = make_token(priv1, "kid-hard-fail-1", test_config.issuer, test_config.client_id)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            # Must raise ProviderError (fail closed) and NEVER return expired key
            with pytest.raises(ProviderError, match="past hard expiry.*refresh failed"):
                await cache.get_signing_key_for_token(token_str, client=client)

    @pytest.mark.asyncio
    async def test_concurrent_unknown_kid_uses_single_flight_lock(self, test_config: FaydaConfig) -> None:
        """Verify single-flight async lock prevents cache stampede on unknown kid."""
        priv1, pub1, jwk1 = create_rsa_jwk("kid-flight-1")
        cache = JwksCache(config=test_config)

        request_count = 0

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal request_count
            request_count += 1
            await asyncio.sleep(0.05)
            return httpx.Response(200, json={"keys": [jwk1]})

        token_str = make_token(priv1, "kid-flight-1", test_config.issuer, test_config.client_id)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            # 20 concurrent requests for unknown kid
            tasks = [
                cache.get_signing_key_for_token(token_str, client=client)
                for _ in range(20)
            ]
            results = await asyncio.gather(*tasks)

        assert len(results) == 20
        # Exactly one HTTP request occurred across all 20 coroutines
        assert request_count == 1

    @pytest.mark.asyncio
    async def test_per_issuer_jwks_uri_isolation(self, test_config: FaydaConfig) -> None:
        """Verify caching is isolated per (issuer, jwks_uri)."""
        priv_a, pub_a, jwk_a = create_rsa_jwk("kid-shared")
        priv_b, pub_b, jwk_b = create_rsa_jwk("kid-shared")

        cache = JwksCache(config=test_config)

        issuer_a = "https://issuer-a.example"
        jwks_a = "https://issuer-a.example/jwks"
        issuer_b = "https://issuer-b.example"
        jwks_b = "https://issuer-b.example/jwks"

        now = time.time()
        cache.add_key("kid-shared", pub_a, issuer=issuer_a, jwks_uri=jwks_a)
        cache.add_key("kid-shared", pub_b, issuer=issuer_b, jwks_uri=jwks_b)

        entry_a = cache.get_entry(issuer=issuer_a, jwks_uri=jwks_a)
        entry_b = cache.get_entry(issuer=issuer_b, jwks_uri=jwks_b)

        assert entry_a is not None
        assert entry_b is not None
        assert entry_a.keys["kid-shared"] == pub_a
        assert entry_b.keys["kid-shared"] == pub_b
        assert entry_a.keys["kid-shared"] != entry_b.keys["kid-shared"]

    @pytest.mark.asyncio
    async def test_backoff_state_recorded_on_failures(self, test_config: FaydaConfig) -> None:
        """Verify failure triggers backoff and prevents hammering during backoff window."""
        cache = JwksCache(config=test_config, base_backoff_seconds=2.0)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(503, text="Service Unavailable")

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            with pytest.raises(ProviderError):
                await cache.fetch_jwks(client)

        backoff = cache.get_backoff_state()
        assert backoff is not None
        assert backoff.consecutive_failures == 1
        assert backoff.next_allowed_attempt > time.time()

        # Immediate subsequent foreground call fails fast with backoff notice
        async with httpx.AsyncClient(transport=transport) as client:
            with pytest.raises(ProviderError, match="temporarily in backoff"):
                await cache.fetch_jwks(client)
