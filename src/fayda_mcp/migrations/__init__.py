"""Fayda MCP schema migration assets and runner.

Note: Importing this module never executes DDL or alters the database.
Migrations must be invoked explicitly via the CLI or MigrationRunner.
"""

from fayda_mcp.migrations.runner import MigrationRunner, run_migrations, rollback_migrations, get_migration_status

__all__ = [
    "MigrationRunner",
    "run_migrations",
    "rollback_migrations",
    "get_migration_status",
]
