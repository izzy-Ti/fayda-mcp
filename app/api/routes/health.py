"""Health and readiness check endpoints."""

from fastapi import APIRouter, status
from fastapi.responses import JSONResponse
from app.infra.redis import check_redis_health
from app.db.session import check_db_health

router = APIRouter(prefix="/health", tags=["health"])


@router.get("/live")
async def liveness():
    """Liveness probe.

    Returns OK as long as the process is alive. Does not restart on upstream provider outage.
    """
    return {"status": "ok"}


@router.get("/ready")
async def readiness():
    """Readiness probe.

    Detects if required storage backends (Redis, Neon DB) are ready to accept traffic.
    """
    redis_ok = await check_redis_health()
    db_ok = await check_db_health()

    is_ready = redis_ok and db_ok
    payload = {
        "status": "ready" if is_ready else "not_ready",
        "components": {
            "redis": "healthy" if redis_ok else "unhealthy",
            "database": "healthy" if db_ok else "unhealthy",
        },
    }

    if not is_ready:
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content=payload)
    return payload
