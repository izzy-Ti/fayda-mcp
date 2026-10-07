"""Fayda MCP storage backends and protocols."""
from fayda_mcp.storage.memory import (
    MemoryAuditLogger,
    MemoryResultRepository,
    MemorySessionStore,
)
from fayda_mcp.storage.protocols import (
    AuditLogger,
    ResultRepository,
    SessionStore,
)

from fayda_mcp.storage.retention import RetentionCleanupManager

__all__ = [
    "AuditLogger",
    "MemoryAuditLogger",
    "MemoryResultRepository",
    "MemorySessionStore",
    "ResultRepository",
    "SessionStore",
    "RetentionCleanupManager",
]

try:
    from fayda_mcp.storage.postgres import PostgresAuditLogger, PostgresResultRepository
    __all__.extend(["PostgresAuditLogger", "PostgresResultRepository"])
except ImportError:
    pass

try:
    from fayda_mcp.storage.redis import RedisSessionStore
    __all__.append("RedisSessionStore")
except ImportError:
    pass
