"""Redis session storage adapter for multi-process deployments (Task S5).

Provides atomic, race-safe session state consumption using Redis GETDEL
or equivalent Lua scripts across multiple worker processes.
"""

import asyncio
import json
import logging
from typing import Any, Dict, Optional

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


class RedisSessionStore:
    """Redis-backed session store for atomic state consumption across processes.

    Implements the SessionStore protocol:
    - save_session: creates session with strict TTL expiry.
    - consume_session: atomically reads and deletes session in one atomic operation.
    - get_session: reads session without consuming (for status inspection).
    - delete_session: explicitly and idempotently deletes session (cancellation / cleanup).
    - close: cleans up connection pool and socket handles.
    """

    def __init__(self, redis_client: Any, key_prefix: str = "fayda:session:") -> None:
        if aioredis is None:
            raise ImportError(
                "Redis extra is not installed. Install with: pip install 'fayda-mcp[redis]'"
            )
        self.redis = redis_client
        self.key_prefix = key_prefix
        self._owned_client = False

    @classmethod
    def from_url(
        cls,
        redis_url: str,
        key_prefix: str = "fayda:session:",
        **redis_kwargs: Any,
    ) -> "RedisSessionStore":
        """Instantiate a RedisSessionStore from a connection URL."""
        if aioredis is None:
            raise ImportError(
                "Redis extra is not installed. Install with: pip install 'fayda-mcp[redis]'"
            )
        if "decode_responses" not in redis_kwargs:
            redis_kwargs["decode_responses"] = True
        client = aioredis.from_url(redis_url, **redis_kwargs)
        store = cls(redis_client=client, key_prefix=key_prefix)
        store._owned_client = True
        return store

    def _key(self, state: str) -> str:
        return f"{self.key_prefix}{state}"

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
                logger.error("Error executing atomic getdel on Redis key %s: %s", key, e)
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
        """Close underlying Redis connection pool and sockets."""
        if self.redis is not None:
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
