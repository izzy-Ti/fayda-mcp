"""Database migration runner for Fayda MCP durable schema.

Discovers and applies versioned SQL migrations using explicit commands.
Importing this module never executes DDL or connects to any database.
"""

import importlib.resources
import os
import re
from typing import Any, Dict, List, Optional, Tuple

try:
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
except ImportError:
    create_async_engine = None  # type: ignore
    AsyncEngine = None  # type: ignore
    text = None  # type: ignore


def _sql_text(statement: str) -> Any:
    if text is None:
        raise ImportError(
            "Postgres extra is not installed. Install with: pip install 'fayda-mcp[postgres]'"
        )
    return text(statement)


def _adapt_ddl_for_dialect(sql: str, dialect_name: str) -> str:
    """Adapt PostgreSQL DDL for SQLite when running under local/test environments."""
    if dialect_name == "sqlite":
        # Replace PostgreSQL specific types and casts for SQLite compatibility
        sql = re.sub(r"::jsonb", "", sql, flags=re.IGNORECASE)
        sql = re.sub(r"\bJSONB\b", "TEXT", sql, flags=re.IGNORECASE)
        sql = re.sub(r"\bTIMESTAMPTZ\b", "TIMESTAMP", sql, flags=re.IGNORECASE)
        sql = re.sub(r"\bDOUBLE PRECISION\b", "REAL", sql, flags=re.IGNORECASE)
    return sql


class MigrationRunner:
    """Manages versioned database migrations for Fayda MCP."""

    def __init__(self, engine_or_url: Any) -> None:
        if create_async_engine is None:
            raise ImportError(
                "Postgres extra is not installed. Install with: pip install 'fayda-mcp[postgres]'"
            )

        if isinstance(engine_or_url, str):
            # Normalize driver for async execution
            url = engine_or_url
            if url.startswith("postgres://"):
                url = url.replace("postgres://", "postgresql+psycopg://", 1)
            elif url.startswith("postgresql://") and not url.startswith("postgresql+"):
                url = url.replace("postgresql://", "postgresql+psycopg://", 1)
            elif url.startswith("sqlite://") and not url.startswith("sqlite+"):
                url = url.replace("sqlite://", "sqlite+aiosqlite://", 1)
            self._engine = create_async_engine(url)
            self._owns_engine = True
        else:
            self._engine = engine_or_url
            self._owns_engine = False

    async def close(self) -> None:
        """Dispose the underlying engine if owned."""
        if self._owns_engine and self._engine:
            await self._engine.dispose()

    async def __aenter__(self) -> "MigrationRunner":
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.close()

    def discover_migrations(self) -> List[Tuple[str, str, str, str]]:
        """Discover available migration files.

        Returns list of (version, name, up_sql, down_sql).
        """
        migrations: Dict[str, Dict[str, str]] = {}

        # Look in package resources
        try:
            pkg_files = importlib.resources.files("fayda_mcp.migrations")
            for item in pkg_files.iterdir():
                filename = item.name
                match = re.match(r"^(\d+)_([a-zA-Z0-9_]+)\.(up|down)\.sql$", filename)
                if match:
                    version, name, direction = match.groups()
                    content = item.read_text(encoding="utf-8")
                    if version not in migrations:
                        migrations[version] = {"name": name, "up": "", "down": ""}
                    migrations[version][direction] = content
        except Exception:
            # Fallback to local filesystem relative to this file
            curr_dir = os.path.dirname(__file__)
            for filename in os.listdir(curr_dir):
                match = re.match(r"^(\d+)_([a-zA-Z0-9_]+)\.(up|down)\.sql$", filename)
                if match:
                    version, name, direction = match.groups()
                    filepath = os.path.join(curr_dir, filename)
                    with open(filepath, "r", encoding="utf-8") as f:
                        content = f.read()
                    if version not in migrations:
                        migrations[version] = {"name": name, "up": "", "down": ""}
                    migrations[version][direction] = content

        result: List[Tuple[str, str, str, str]] = []
        for ver in sorted(migrations.keys()):
            data = migrations[ver]
            result.append((ver, data["name"], data["up"], data["down"]))
        return result

    async def _ensure_migrations_table(self) -> None:
        """Ensure schema migrations table exists."""
        dialect = self._engine.dialect.name
        ddl = """
        CREATE TABLE IF NOT EXISTS fayda_schema_migrations (
            version VARCHAR(64) PRIMARY KEY,
            description VARCHAR(256) NOT NULL,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """
        adapted_ddl = _adapt_ddl_for_dialect(ddl, dialect)
        async with self._engine.begin() as conn:
            await conn.execute(_sql_text(adapted_ddl))

    async def get_applied_migrations(self) -> List[str]:
        """Return list of versions that have been applied."""
        await self._ensure_migrations_table()
        sql = "SELECT version FROM fayda_schema_migrations ORDER BY version ASC"
        async with self._engine.connect() as conn:
            res = await conn.execute(_sql_text(sql))
            return [str(row[0]) for row in res.fetchall()]

    async def upgrade(self, target_version: Optional[str] = None) -> List[str]:
        """Apply pending migrations up to target_version (or all if None).

        Returns list of applied migration versions.
        """
        await self._ensure_migrations_table()
        applied = set(await self.get_applied_migrations())
        available = self.discover_migrations()

        applied_now: List[str] = []
        dialect = self._engine.dialect.name

        for version, name, up_sql, _ in available:
            if version in applied:
                continue
            if target_version and version > target_version:
                break

            adapted_sql = _adapt_ddl_for_dialect(up_sql, dialect)
            statements = [s.strip() for s in adapted_sql.split(";") if s.strip()]

            async with self._engine.begin() as conn:
                for stmt in statements:
                    await conn.execute(_sql_text(stmt))

                record_sql = """
                INSERT INTO fayda_schema_migrations (version, description)
                VALUES (:version, :description)
                """
                await conn.execute(
                    _sql_text(record_sql),
                    {"version": version, "description": name},
                )

            applied_now.append(version)

        return applied_now

    async def downgrade(self, steps: int = 1) -> List[str]:
        """Roll back the last `steps` applied migrations.

        Returns list of rolled back migration versions.
        """
        await self._ensure_migrations_table()
        applied = await self.get_applied_migrations()
        if not applied:
            return []

        available_map = {v: (n, up, down) for v, n, up, down in self.discover_migrations()}
        to_rollback = list(reversed(applied))[:steps]

        rolled_back: List[str] = []
        dialect = self._engine.dialect.name

        for version in to_rollback:
            if version not in available_map:
                raise RuntimeError(f"Migration version {version} missing rollback file.")
            _, _, down_sql = available_map[version]

            adapted_sql = _adapt_ddl_for_dialect(down_sql, dialect)
            statements = [s.strip() for s in adapted_sql.split(";") if s.strip()]

            async with self._engine.begin() as conn:
                for stmt in statements:
                    await conn.execute(_sql_text(stmt))

                delete_sql = "DELETE FROM fayda_schema_migrations WHERE version = :version"
                await conn.execute(_sql_text(delete_sql), {"version": version})

            rolled_back.append(version)

        return rolled_back

    async def get_status(self) -> Dict[str, Any]:
        """Return migration status summary."""
        applied = await self.get_applied_migrations()
        available = self.discover_migrations()
        pending = [v for v, _, _, _ in available if v not in applied]
        return {
            "applied": applied,
            "pending": pending,
            "current_version": applied[-1] if applied else None,
            "total_available": len(available),
        }


async def run_migrations(
    database_url: str, target_version: Optional[str] = None
) -> List[str]:
    """Helper to instantiate runner and apply migrations."""
    async with MigrationRunner(database_url) as runner:
        return await runner.upgrade(target_version=target_version)


async def rollback_migrations(database_url: str, steps: int = 1) -> List[str]:
    """Helper to instantiate runner and rollback migrations."""
    async with MigrationRunner(database_url) as runner:
        return await runner.downgrade(steps=steps)


async def get_migration_status(database_url: str) -> Dict[str, Any]:
    """Helper to inspect migration status on a database."""
    async with MigrationRunner(database_url) as runner:
        return await runner.get_status()
