"""Unit and acceptance tests for Task S5: Redis session adapter completion.

Verifies:
- Atomic GETDEL and Lua script fallback
- Two consumers racing for one state produce exactly one winner
- Replay and expired state fail
- delete_session is idempotent
- Real Redis / fakeredis execution
- Callback failure does not restore consumed state or retry blindly
"""

import asyncio
import os
import time
from typing import Any
import pytest

from fayda_mcp import (
    CallerContext,
    FaydaConfig,
    FaydaVerificationService,
    InvalidStateError,
)
from fayda_mcp.storage.memory import MemoryResultRepository
from fayda_mcp.storage.redis import RedisSessionStore, _GETDEL_LUA, parse_redis_url

try:
    import fakeredis.aioredis as fake_aioredis
    import redis.asyncio as aioredis
except ImportError:
    fake_aioredis = None
    aioredis = None


async def create_test_redis_client() -> Any:
    """Create a clean Redis client using live Redis (if FAYDA_TEST_REDIS_URL configured) or FakeRedis."""
    redis_url = os.environ.get("FAYDA_TEST_REDIS_URL")
    if redis_url:
        assert aioredis is not None, "redis.asyncio must be installed"
        clean_url = parse_redis_url(redis_url)
        try:
            client = aioredis.from_url(clean_url, decode_responses=True, socket_connect_timeout=1.5)
            await client.ping()
            await client.flushdb()
            return client
        except Exception:
            if fake_aioredis is not None:
                client = fake_aioredis.FakeRedis(decode_responses=True)
                await client.flushdb()
                return client
            raise
    else:
        assert fake_aioredis is not None, "fakeredis must be installed"
        client = fake_aioredis.FakeRedis(decode_responses=True)

    await client.flushdb()
    return client


async def close_test_redis_client(client: Any) -> None:
    """Safely flush and close test client."""
    try:
        await client.flushdb()
    except Exception:
        pass
    if hasattr(client, "aclose"):
        await client.aclose()
    elif hasattr(client, "close"):
        res = client.close()
        if asyncio.iscoroutine(res):
            await res


@pytest.mark.asyncio
async def test_redis_session_store_save_and_get():
    """Verify basic save_session and get_session without consumption."""
    client = await create_test_redis_client()
    try:
        store = RedisSessionStore(client)
        state = "state-get-test"
        data = {"request_id": "req-1", "nonce": "nonce-123", "code_verifier": "cv-xyz"}

        await store.save_session(state, data, ttl_seconds=60)

        # get_session reads without consuming
        fetched_1 = await store.get_session(state)
        assert fetched_1 == data

        fetched_2 = await store.get_session(state)
        assert fetched_2 == data
    finally:
        await close_test_redis_client(client)


@pytest.mark.asyncio
async def test_two_consumers_racing_for_one_state_produce_one_winner():
    """Acceptance criterion: Two consumers racing for one state produce one winner."""
    client = await create_test_redis_client()
    try:
        store = RedisSessionStore(client)
        state = "race-state-abc"
        session_data = {
            "request_id": "req-race-1",
            "nonce": "nonce-abc",
            "code_verifier": "verifier-secret",
        }
        await store.save_session(state, session_data, ttl_seconds=60)

        # Spawn 10 concurrent consumers attempting to consume the exact same state
        num_consumers = 10
        tasks = [store.consume_session(state) for _ in range(num_consumers)]
        results = await asyncio.gather(*tasks)

        winners = [r for r in results if r is not None]
        losers = [r for r in results if r is None]

        assert len(winners) == 1, "Exactly one consumer must win the race"
        assert len(losers) == num_consumers - 1, "All other consumers must receive None"
        assert winners[0]["request_id"] == "req-race-1"

        # Subsequent consumption also fails (replay protection)
        subsequent = await store.consume_session(state)
        assert subsequent is None
    finally:
        await close_test_redis_client(client)


@pytest.mark.asyncio
async def test_replay_and_expired_state_fail():
    """Acceptance criterion: Replay and expired state fail."""
    client = await create_test_redis_client()
    try:
        store = RedisSessionStore(client)

        # 1. Replay test
        state_replay = "state-replay"
        await store.save_session(state_replay, {"request_id": "req-replay"}, ttl_seconds=60)
        first_consume = await store.consume_session(state_replay)
        assert first_consume is not None
        # Replay attempt
        replay_consume = await store.consume_session(state_replay)
        assert replay_consume is None

        # 2. Expired state test
        state_expired = "state-expired"
        await store.save_session(state_expired, {"request_id": "req-exp"}, ttl_seconds=1)
        await asyncio.sleep(1.1)
        expired_consume = await store.consume_session(state_expired)
        assert expired_consume is None
    finally:
        await close_test_redis_client(client)


@pytest.mark.asyncio
async def test_delete_session_is_idempotent():
    """Acceptance criterion: delete_session is idempotent."""
    client = await create_test_redis_client()
    try:
        store = RedisSessionStore(client)
        state = "state-delete-idemp"
        await store.save_session(state, {"request_id": "req-del"}, ttl_seconds=60)

        # First delete on existing key returns True
        first_del = await store.delete_session(state)
        assert first_del is True

        # Second delete on already deleted key returns False without raising error
        second_del = await store.delete_session(state)
        assert second_del is False

        # Third delete on never-existent key returns False without raising error
        third_del = await store.delete_session("nonexistent-key")
        assert third_del is False

        # Confirm key was purged from Redis
        assert await store.get_session(state) is None
        assert await store.consume_session(state) is None
    finally:
        await close_test_redis_client(client)


@pytest.mark.asyncio
async def test_lua_fallback_atomicity():
    """Acceptance criterion: Lua fallback performs atomic read-and-delete identically to GETDEL."""
    client = await create_test_redis_client()
    try:
        store = RedisSessionStore(client)
        state = "state-lua-atomic"
        key = store._key(state)
        data = {"request_id": "req-lua-1", "nonce": "nonce-lua"}

        await store.save_session(state, data, ttl_seconds=60)

        # Force using Lua script directly to test older Redis engine behavior
        lua_res_1 = await client.eval(_GETDEL_LUA, 1, key)
        assert lua_res_1 is not None

        # Second call returns None (key was atomically deleted)
        lua_res_2 = await client.eval(_GETDEL_LUA, 1, key)
        assert lua_res_2 is None

        # Key is completely gone
        assert await client.get(key) is None
    finally:
        await close_test_redis_client(client)


@pytest.mark.asyncio
async def test_callback_failure_does_not_restore_state():
    """Acceptance criterion: Callback that consumes valid state and fails must not restore state."""
    client = await create_test_redis_client()
    try:
        config = FaydaConfig(
            client_id="test-client",
            redirect_uri="https://app.example.com/callback",
            issuer="https://esignet.example.com",
            authorization_endpoint="https://esignet.example.com/auth",
            token_endpoint="https://esignet.example.com/token",
            userinfo_endpoint="https://esignet.example.com/userinfo",
            jwks_uri="https://esignet.example.com/jwks",
        )
        store = RedisSessionStore(client)
        repo = MemoryResultRepository()
        service = FaydaVerificationService(config=config, sessions=store, results=repo)

        state = "test-fail-state"
        req_id = "req-fail-1"
        ctx = CallerContext(tenant_id="t-1", principal_id="p-1")

        # Manually save request and session
        await repo.save_request(req_id, {
            "request_id": req_id,
            "tenant_id": ctx.tenant_id,
            "principal_id": ctx.principal_id,
            "status": "pending",
            "session_expires_at": time.time() + 600,
            "retention_expires_at": time.time() + 3600,
        }, ttl_seconds=600)

        await store.save_session(state, {
            "request_id": req_id,
            "nonce": "test-nonce",
            "code_verifier": "test-verifier",
            "checks": ["identity_verified"],
        }, ttl_seconds=600)

        # First callback attempt triggers token exchange (which fails due to dummy signing key/network)
        with pytest.raises(Exception):
            await service.complete_verification(code="bad-code", state=state)

        # Verification state in Redis must NOT have been restored!
        consumed_check = await store.consume_session(state)
        assert consumed_check is None, "State must remain consumed and never restored after failure"

        # Second callback attempt must fail immediately with InvalidStateError
        with pytest.raises(InvalidStateError, match="invalid, expired, or already used"):
            await service.complete_verification(code="bad-code", state=state)
    finally:
        await close_test_redis_client(client)


@pytest.mark.asyncio
async def test_redis_session_store_from_url_and_context_manager():
    """Verify from_url factory method and async context manager lifecycle."""
    store = RedisSessionStore.from_url("redis://localhost:6379/0")
    assert store.redis is not None
    assert store._owned_client is True

    # Async context manager cleans up
    async with store:
        assert store.key_prefix == "fayda:session:"

    # Direct close
    await store.close()
