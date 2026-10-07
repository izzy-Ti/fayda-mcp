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

__all__ = [
    "AuditLogger",
    "MemoryAuditLogger",
    "MemoryResultRepository",
    "MemorySessionStore",
    "ResultRepository",
    "SessionStore",
]

try:
    from fayda_mcp.storage.postgres import PostgresAuditLogger, PostgresResultRepository
    __all__.extend(["PostgresAuditLogger", "PostgresResultRepository"])
except ImportError:
    pass
