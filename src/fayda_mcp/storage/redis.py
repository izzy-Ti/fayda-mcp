"""Redis session storage adapter for multi-process deployments (Tasks S5 & S6).

Provides:
- Strict shell-tokenized URL parsing for bare URLs, quoted URLs, and redis-cli -u / --uri forms
- Rejection of unsupported flags, extra commands, and shell execution
- Secure SHA-256 state hashing for dedicated session key namespaces
- Atomic, race-safe session state consumption using Redis GETDEL or equivalent Lua scripts
- Full SessionStore protocol implementation with idempotent deletion and connection lifecycle
"""

import asyncio
import hashlib
import json
import logging
import shlex
from typing import Any, Dict, Optional
import urllib.parse

try:
    import redis.asyncio as aioredis
    from redis.exceptions import ResponseError as _RedisResponseError

    RedisResponseError: Any = _RedisResponseError
except ImportError:
    aioredis = None  # type: ignore

    class _FallbackResponseError(Exception):
        pass

    RedisResponseError: Any = _FallbackResponseError

logger = logging.getLogger("fayda_mcp.storage.redis")

# Atomic GET and DEL Lua script for Redis versions lacking native GETDEL (< 6.2).
# Guarantees that two concurrent callbacks racing for the same state will produce
# strictly one winner, avoiding the race hazard inherent in separate GET and DEL commands.
_GETDEL_LUA = """
local val = redis.call('GET', KEYS[1])
if val then
    redis.call('DEL', KEYS[1])
end
return val
"""


def redact_redis_url(url: str) -> str:
    """Redact sensitive password credentials from a Redis connection URL for safe logging/errors."""
    try:
        parsed = urllib.parse.urlsplit(url)
        if parsed.password is not None:
            user = parsed.username or ""
            host = parsed.hostname or ""
            port_str = f":{parsed.port}" if parsed.port else ""
            netloc = f"{user}:***@{host}{port_str}"
            return urllib.parse.urlunsplit(
                (parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment)
            )
        return url
    except Exception:
        return "<redacted-redis-url>"


def parse_redis_url(raw_input: str) -> str:
    """Parse and validate a Redis connection string with strict syntax checking.

    Accepts:
    - Bare URLs: 'redis://host:port/db' or 'rediss://host:port/db'
    - Quoted URLs: '"redis://..."' or "'rediss://...'"
    - CLI forms: 'redis-cli -u URL' or 'redis-cli --uri URL' (or '-u URL', '--uri URL')

    Rejects:
    - Schemes other than 'redis://' and 'rediss://'
    - Trailing command text (e.g. 'redis://host FLUSHALL')
    - Unsupported CLI flags (e.g. '-a', '-p', '--cluster')
    - Shell injection characters or invalid syntax

    Never invokes a shell. Password encoding survives parsing.
    """
    if not raw_input or not raw_input.strip():
        raise ValueError("Redis connection string cannot be empty.")

    clean_input = raw_input.strip()

    try:
        tokens = shlex.split(clean_input, posix=True)
    except Exception as e:
        raise ValueError(f"Invalid shell-style syntax in Redis connection string: {e}")

    if not tokens:
        raise ValueError("Redis connection string contains no tokens.")

    # Remove leading 'redis-cli' command token if present
    if tokens[0] == "redis-cli":
        tokens = tokens[1:]

    if not tokens:
        raise ValueError("Missing Redis URL in redis-cli command string.")

    target_url: Optional[str] = None

    if tokens[0] in ("-u", "--uri"):
        if len(tokens) < 2:
            raise ValueError(f"Flag '{tokens[0]}' requires a URL argument.")
        target_url = tokens[1]
        if len(tokens) > 2:
            raise ValueError(
                f"Trailing arguments or extra commands detected after Redis URL: {tokens[2:]}"
            )
    else:
        first = tokens[0]
        if "://" in first:
            target_url = first
            if len(tokens) > 1:
                raise ValueError(
                    f"Trailing command text detected in Redis connection string: {tokens[1:]}"
                )
        elif first.startswith("-"):
            raise ValueError(
                f"Unsupported redis-cli flag '{first}'. Only -u and --uri are supported."
            )
        else:
            raise ValueError(
                "Invalid Redis connection string. Must start with 'redis://', 'rediss://', or 'redis-cli -u/--uri'."
            )

    try:
        parsed = urllib.parse.urlsplit(target_url)
    except Exception as e:
        raise ValueError(f"Failed to parse Redis URL: {e}")

    if parsed.scheme not in ("redis", "rediss"):
        raise ValueError(
            f"Invalid scheme '{parsed.scheme}'. Only 'redis://' and 'rediss://' URLs are supported."
        )

    if not parsed.hostname and not parsed.netloc:
        raise ValueError("Invalid Redis URL: missing host or network location.")

    return target_url


class RedisSessionStore:
    """Redis-backed session store for atomic state consumption across processes.

    Implements the SessionStore protocol:
    - save_session: creates session with strict TTL expiry and SHA-256 state key hashing.
    - consume_session: atomically reads and deletes session in one atomic operation.
    - get_session: reads session without consuming (for status inspection).
    - delete_session: explicitly and idempotently deletes session (cancellation / cleanup).
    - close: cleans up connection pool and socket handles.
    """

    def __init__(
        self,
        redis_client: Any,
        key_prefix: str = "fayda:session:",
        owned: bool = False,
    ) -> None:
        if aioredis is None:
            raise ImportError(
                "Redis extra is not installed. Install with: pip install 'fayda-mcp[redis]'"
            )
        self.redis = redis_client
        self.key_prefix = key_prefix
        self._owned_client = owned

    @classmethod
    def from_url(
        cls,
        redis_url: str,
        key_prefix: str = "fayda:session:",
        **redis_kwargs: Any,
    ) -> "RedisSessionStore":
        """Instantiate a RedisSessionStore from a connection URL with strict parsing.

        Accepts bare redis:// and rediss:// URLs, quoted URLs, or documented
        redis-cli -u / --uri connection strings. Rejects unsupported flags and trailing commands.
        """
        if aioredis is None:
            raise ImportError(
                "Redis extra is not installed. Install with: pip install 'fayda-mcp[redis]'"
            )
        parsed_url = parse_redis_url(redis_url)
        if "decode_responses" not in redis_kwargs:
            redis_kwargs["decode_responses"] = True
        client = aioredis.from_url(parsed_url, **redis_kwargs)
        store = cls(redis_client=client, key_prefix=key_prefix)
        store._owned_client = True
        return store

    def _key(self, state: str) -> str:
        """Derive namespaced Redis key using SHA-256 hash of the random state parameter."""
        state_hash = hashlib.sha256(state.encode("utf-8")).hexdigest()
        return f"{self.key_prefix}{state_hash}"

    async def save_session(
        self, state: str, data: Dict[str, Any], ttl_seconds: int = 600
    ) -> None:
        """Store OIDC session data keyed by state with a strict TTL expiry."""
        key = self._key(state)
        payload = json.dumps(data)
        if ttl_seconds <= 0:
            # Redis EX requires a positive integer. For zero/negative TTL, set with 1ms expiry.
            await self.redis.set(key, payload, px=1)
        else:
            await self.redis.set(key, payload, ex=ttl_seconds)

    async def consume_session(self, state: str) -> Optional[Dict[str, Any]]:
        """Atomically read and delete session data once.

        Uses Redis GETDEL (Redis >= 6.2) or an atomic Lua script fallback on older servers.
        Never executes separate non-atomic GET and DEL commands.
        Returns session data on first successful consumption.
        Returns None if already consumed, nonexistent, or expired.
        """
        key = self._key(state)
        val = None

        try:
            val = await self.redis.getdel(key)
        except (RedisResponseError, AttributeError):
            # Fallback for Redis servers < 6.2 lacking native GETDEL
            val = await self.redis.eval(_GETDEL_LUA, 1, key)
        except Exception as e:
            # Check for command unknown error messages
            err_str = str(e).lower()
            if "unknown command" in err_str or "getdel" in err_str:
                val = await self.redis.eval(_GETDEL_LUA, 1, key)
            else:
                redacted_k = self._key(state)
                logger.error("Error executing atomic getdel on Redis key %s: %s", redacted_k, e)
                raise

        if not val:
            return None

        if isinstance(val, (bytes, bytearray)):
            val = val.decode("utf-8")

        try:
            return json.loads(val)
        except Exception as e:
            logger.warning("Corrupt session data for state '%s': %s", state, e)
            return None

    async def get_session(self, state: str) -> Optional[Dict[str, Any]]:
        """Read session data without consuming (for status inspection)."""
        key = self._key(state)
        val = await self.redis.get(key)
        if not val:
            return None

        if isinstance(val, (bytes, bytearray)):
            val = val.decode("utf-8")

        try:
            return json.loads(val)
        except Exception:
            return None

    async def delete_session(self, state: str) -> bool:
        """Explicitly and idempotently delete a session.

        Used for explicit cancellation or session cleanup. Does not replace atomic consume.
        Returns True if a session was found and removed, False otherwise.
        """
        key = self._key(state)
        deleted_count = await self.redis.delete(key)
        return bool(deleted_count > 0)

    async def close(self) -> None:
        """Close underlying Redis connection pool and sockets if owned.

        Shutdown does not close a host-owned (borrowed) client.
        """
        if self._owned_client and self.redis is not None:
            if hasattr(self.redis, "aclose"):
                await self.redis.aclose()
            elif hasattr(self.redis, "close"):
                res = self.redis.close()
                if asyncio.iscoroutine(res):
                    await res

    async def __aenter__(self) -> "RedisSessionStore":
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.close()
