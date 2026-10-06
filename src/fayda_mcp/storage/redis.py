"""Optional Redis session storage adapter for multi-process deployments."""

import json
from typing import Any, Dict, Optional

try:
    import redis.asyncio as aioredis
except ImportError:
    aioredis = None  # type: ignore


class RedisSessionStore:
    """Redis-backed session store for atomic state consumption across processes."""

    def __init__(self, redis_client: Any, key_prefix: str = "fayda:session:") -> None:
        if aioredis is None:
            raise ImportError(
                "Redis extra is not installed. Install with: pip install 'fayda-mcp[redis]'"
            )
        self.redis = redis_client
        self.key_prefix = key_prefix

    def _key(self, state: str) -> str:
        return f"{self.key_prefix}{state}"

    async def save_session(self, state: str, data: Dict[str, Any], ttl_seconds: int = 600) -> None:
        await self.redis.set(self._key(state), json.dumps(data), ex=ttl_seconds)

    async def consume_session(self, state: str) -> Optional[Dict[str, Any]]:
        """Atomically read and delete the key using a Redis pipeline or GETDEL."""
        key = self._key(state)
        # GETDEL is atomic in Redis >= 6.2
        try:
            val = await self.redis.getdel(key)
        except Exception:
            # Fallback for environments lacking GETDEL
            pipeline = self.redis.pipeline()
            pipeline.get(key)
            pipeline.delete(key)
            res = await pipeline.execute()
            val = res[0]
        if not val:
            return None
        return json.loads(val)

    async def get_session(self, state: str) -> Optional[Dict[str, Any]]:
        val = await self.redis.get(self._key(state))
        if not val:
            return None
        return json.loads(val)
