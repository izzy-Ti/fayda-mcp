"""Unit and acceptance tests for Task S6: URL helper with strict parsing and key hashing."""

import hashlib
import pytest
from fayda_mcp.storage.redis import (
    RedisSessionStore,
    parse_redis_url,
    redact_redis_url,
)

try:
    import fakeredis.aioredis as fake_aioredis
except ImportError:
    fake_aioredis = None


def test_bare_and_quoted_urls():
    """Acceptance criterion: Bare and quoted URLs work."""
    # Bare unencrypted
    url_1 = "redis://localhost:6379/0"
    assert parse_redis_url(url_1) == "redis://localhost:6379/0"

    # Bare TLS
    url_2 = "rediss://cache.prod.internal:6380/2"
    assert parse_redis_url(url_2) == "rediss://cache.prod.internal:6380/2"

    # Double-quoted
    url_3 = '"redis://10.0.0.5:6379/1"'
    assert parse_redis_url(url_3) == "redis://10.0.0.5:6379/1"

    # Single-quoted
    url_4 = "'rediss://myuser:secret@redis-cluster.aws:6380/0'"
    assert parse_redis_url(url_4) == "rediss://myuser:secret@redis-cluster.aws:6380/0"


def test_cli_flags_forms():
    """Acceptance criterion: redis-cli -u URL and --uri forms with shell-style tokenization work."""
    # redis-cli -u bare
    res_1 = parse_redis_url("redis-cli -u redis://localhost:6379")
    assert res_1 == "redis://localhost:6379"

    # redis-cli -u quoted
    res_2 = parse_redis_url('redis-cli -u "rediss://secure-host:6380/0"')
    assert res_2 == "rediss://secure-host:6380/0"

    # redis-cli --uri
    res_3 = parse_redis_url("redis-cli --uri rediss://secure-host:6380/1")
    assert res_3 == "rediss://secure-host:6380/1"

    # -u without leading redis-cli
    res_4 = parse_redis_url("-u redis://localhost:6379/0")
    assert res_4 == "redis://localhost:6379/0"

    # --uri without leading redis-cli
    res_5 = parse_redis_url("--uri redis://localhost:6379/0")
    assert res_5 == "redis://localhost:6379/0"


def test_password_encoding_survives_parsing():
    """Acceptance criterion: Password encoding survives parsing."""
    encoded_url = "rediss://app_user:p%40ssw%3Ard%21@redis.internal:6380/0"
    assert parse_redis_url(encoded_url) == encoded_url

    quoted_encoded = f'redis-cli -u "{encoded_url}"'
    assert parse_redis_url(quoted_encoded) == encoded_url


def test_strings_containing_extra_commands_fail():
    """Acceptance criterion: Strings containing extra commands fail."""
    # Extra command after bare URL
    with pytest.raises(ValueError, match="Trailing command text"):
        parse_redis_url("redis://localhost:6379 FLUSHALL")

    # Extra command after quoted URL
    with pytest.raises(ValueError, match="Trailing command text"):
        parse_redis_url('"redis://localhost:6379" KEYS *')

    # Extra command in redis-cli form
    with pytest.raises(ValueError, match="Trailing arguments or extra commands"):
        parse_redis_url("redis-cli -u redis://localhost:6379 info")

    # Command chaining / shell injection attempt
    with pytest.raises(ValueError):
        parse_redis_url("redis://localhost:6379; rm -rf /")


def test_unsupported_flags_fail():
    """Acceptance criterion: Reject unsupported flags."""
    # Unsupported -a flag
    with pytest.raises(ValueError, match="Unsupported redis-cli flag"):
        parse_redis_url("redis-cli -a mypassword -u redis://localhost:6379")

    # Unsupported -p flag
    with pytest.raises(ValueError, match="Unsupported redis-cli flag"):
        parse_redis_url("redis-cli -p 6380 redis://localhost")

    # Unsupported --cluster flag
    with pytest.raises(ValueError, match="Unsupported redis-cli flag"):
        parse_redis_url("redis-cli --cluster -u redis://localhost:6379")


def test_invalid_schemes_and_empty_inputs_fail():
    """Verify non-redis schemes and empty inputs are rejected."""
    with pytest.raises(ValueError, match="cannot be empty"):
        parse_redis_url("")

    with pytest.raises(ValueError, match="cannot be empty"):
        parse_redis_url("   ")

    with pytest.raises(ValueError, match="Invalid scheme"):
        parse_redis_url("http://localhost:6379")

    with pytest.raises(ValueError, match="Invalid scheme"):
        parse_redis_url("postgresql://localhost:5432/db")


def test_redact_redis_url():
    """Verify passwords are redacted for safe logging and error reporting."""
    raw_url = "rediss://service_user:SuperSecretPassword123@redis.cloud:6380/1"
    redacted = redact_redis_url(raw_url)
    assert "SuperSecretPassword123" not in redacted
    assert "service_user:***@redis.cloud:6380/1" in redacted
    assert redacted.startswith("rediss://")

    # URL without password is untouched
    no_pass = "redis://localhost:6379/0"
    assert redact_redis_url(no_pass) == no_pass


@pytest.mark.asyncio
async def test_state_key_hashing_in_namespaced_keys():
    """Acceptance criterion: Use a hash of random state in namespaced keys."""
    assert fake_aioredis is not None
    client = fake_aioredis.FakeRedis(decode_responses=True)
    try:
        store = RedisSessionStore(client, key_prefix="fayda:session:")
        random_state = "nU9_x87yZZa901-very-long-random-state-token"

        expected_hash = hashlib.sha256(random_state.encode("utf-8")).hexdigest()
        expected_redis_key = f"fayda:session:{expected_hash}"

        # Verify key derivation uses SHA-256 hash
        derived_key = store._key(random_state)
        assert derived_key == expected_redis_key
        assert random_state not in derived_key

        # Save session
        session_data = {
            "request_id": "req-hash-1",
            "tenant_id": "tenant-abc",
            "principal_id": "agent-xyz",
            "application_user_ref": "user-42",
            "nonce": "nonce-hash-1",
            "code_verifier": "verifier-secret",
            "purpose": "onboarding",
            "checks": ["identity_verified"],
            "expires_at": "2026-10-07T12:00:00Z",
            "browser_binding": "bind-fingerprint-1",
        }
        await store.save_session(random_state, session_data, ttl_seconds=60)

        # Raw state is NOT stored as key in Redis
        raw_state_val = await client.get(random_state)
        assert raw_state_val is None

        # Hashed key IS present in Redis
        hashed_val = await client.get(expected_redis_key)
        assert hashed_val is not None

        # Consuming with the raw state successfully consumes the hashed key
        consumed = await store.consume_session(random_state)
        assert consumed is not None
        assert consumed["request_id"] == "req-hash-1"
        assert consumed["code_verifier"] == "verifier-secret"

        # Key is now deleted
        assert await client.get(expected_redis_key) is None
    finally:
        await client.aclose()


def test_from_url_strict_enforcement():
    """Verify RedisSessionStore.from_url rejects trailing commands and invalid flags."""
    with pytest.raises(ValueError, match="Trailing command text"):
        RedisSessionStore.from_url("redis://localhost:6379 FLUSHALL")

    with pytest.raises(ValueError, match="Unsupported redis-cli flag"):
        RedisSessionStore.from_url("redis-cli -a secret -u redis://localhost:6379")

    # Valid CLI form succeeds
    store = RedisSessionStore.from_url("redis-cli -u redis://localhost:6379")
    assert store.redis is not None
