"""Optional PostgreSQL / Neon durable result repository."""

from typing import Any, Dict, Optional
from fayda_mcp.schemas import VerificationResult

try:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
except ImportError:
    AsyncSession = None  # type: ignore
    async_sessionmaker = None  # type: ignore


class PostgresResultRepository:
    """PostgreSQL / Neon backed storage adapter.

    Table creation and migrations are never executed automatically on import.
    """

    def __init__(self, session_factory: Any, table_prefix: str = "fayda_") -> None:
        if AsyncSession is None:
            raise ImportError(
                "Postgres extra is not installed. Install with: pip install 'fayda-mcp[postgres]'"
            )
        self.session_factory = session_factory
        self.table_prefix = table_prefix

    async def save_request(self, request_id: str, data: Dict[str, Any], ttl_seconds: int = 900) -> None:
        # Full persistence query implemented in task D1
        pass

    async def get_request(self, request_id: str) -> Optional[Dict[str, Any]]:
        return None

    async def update_status(self, request_id: str, status: str) -> None:
        pass

    async def save_result(self, request_id: str, result: VerificationResult, ttl_seconds: int = 900) -> None:
        pass

    async def get_result(self, request_id: str) -> Optional[VerificationResult]:
        return None
