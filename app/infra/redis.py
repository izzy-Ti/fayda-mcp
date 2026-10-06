"""Redis client infrastructure for sessions, state, and rate limits."""

from typing import Optional
import redis.asyncio as aioredis
from app.core.config import Settings, get_settings
from app.core.logging import logger

_redis_client: Optional[aioredis.Redis] = None


async def init_redis(settings: Optional[Settings] = None) -> aioredis.Redis:
    """Initialize the global async Redis client."""
    global _redis_client
    if settings is None:
        settings = get_settings()

    logger.info("Initializing Redis connection to %s", settings.REDIS_URL.split("@")[-1])
    _redis_client = aioredis.from_url(
        settings.REDIS_URL,
        encoding="utf-8",
        decode_responses=True,
    )
    return _redis_client


async def close_redis() -> None:
    """Close the global Redis client connection cleanly."""
    global _redis_client
    if _redis_client is not None:
        logger.info("Closing Redis connection...")
        await _redis_client.aclose()
        _redis_client = None
        logger.info("Redis connection closed.")


def get_redis() -> Optional[aioredis.Redis]:
    """Get the initialized Redis client instance."""
    return _redis_client


async def check_redis_health() -> bool:
    """Ping Redis to confirm connectivity."""
    client = get_redis()
    if client is None:
        return False
    try:
        return bool(await client.ping())
    except Exception as exc:
        logger.warning("Redis health check failed: %s", exc)
        return False
