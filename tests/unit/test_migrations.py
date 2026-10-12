"""Tests for versioned schema migrations, runner, and CLI tooling (Task S2)."""

import os
import tempfile
import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text

from fayda_mcp.migrations.runner import MigrationRunner, run_migrations, rollback_migrations, get_migration_status
from fayda_mcp.cli import main


@pytest.mark.asyncio
async def test_import_never_creates_tables():
    """Acceptance criterion: Importing library modules never creates tables."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    try:
        url = f"sqlite+aiosqlite:///{db_path}"
        engine = create_async_engine(url)

        # Re-import storage & migrations modules
        import fayda_mcp
        import fayda_mcp.storage.postgres
        import fayda_mcp.migrations
        import fayda_mcp.cli

        # Verify database is completely empty (no tables)
        async with engine.connect() as conn:
            res = await conn.execute(text("SELECT name FROM sqlite_master WHERE type='table';"))
            tables = [row[0] for row in res.fetchall()]
            assert tables == []

        await engine.dispose()
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


@pytest.mark.asyncio
async def test_migration_upgrade_and_idempotency():
    """Verify applying migrations creates versioned schema and second run is a no-op."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    try:
        url = f"sqlite+aiosqlite:///{db_path}"
        engine = create_async_engine(url)

        async with MigrationRunner(engine) as runner:
            # 1. Discover migrations
            available = runner.discover_migrations()
            assert len(available) >= 1
            ver, name, up_sql, down_sql = available[0]
            assert ver == "0001"
            assert "fayda_requests" in up_sql
            assert "fayda_results" in up_sql
            assert "fayda_audit_events" in up_sql

            # 2. Run initial upgrade
            applied = await runner.upgrade()
            assert "0001" in applied

            # Verify tables exist
            status = await runner.get_status()
            assert status["current_version"] == "0001"
            assert "0001" in status["applied"]
            assert status["pending"] == []

            # 3. Running upgrade again is an idempotent no-op
            applied_again = await runner.upgrade()
            assert applied_again == []

        await engine.dispose()
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


@pytest.mark.asyncio
async def test_migration_rollback_cycle():
    """Verify rollback strategy cleanly rolls back applied migrations."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    try:
        url = f"sqlite+aiosqlite:///{db_path}"
        engine = create_async_engine(url)

        async with MigrationRunner(engine) as runner:
            # 1. Upgrade
            await runner.upgrade()

            # Verify requests table exists
            async with engine.connect() as conn:
                res = await conn.execute(
                    text("SELECT name FROM sqlite_master WHERE type='table' AND name='fayda_requests';")
                )
                assert len(res.fetchall()) == 1

            # 2. Downgrade (Rollback)
            rolled = await runner.downgrade(steps=1)
            assert "0001" in rolled

            # Verify requests table was dropped
            async with engine.connect() as conn:
                res = await conn.execute(
                    text("SELECT name FROM sqlite_master WHERE type='table' AND name='fayda_requests';")
                )
                assert len(res.fetchall()) == 0

            # Verify status reports 0001 as pending
            status = await runner.get_status()
            assert "0001" in status["pending"]
            assert status["current_version"] is None

        await engine.dispose()
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


def test_cli_migrate_commands(monkeypatch):
    """Verify CLI migrate subcommand handles --database-url, --status, and --rollback."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    try:
        url = f"sqlite+aiosqlite:///{db_path}"

        # 1. Migrate upgrade
        ret = main(["migrate", "--database-url", url])
        assert ret == 0

        # 2. Check status
        ret = main(["migrate", "--database-url", url, "--status"])
        assert ret == 0

        # 3. Rollback
        ret = main(["migrate", "--database-url", url, "--rollback"])
        assert ret == 0
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


def test_cli_missing_database_url():
    """Verify CLI returns nonzero when database URL is missing."""
    ret = main(["migrate", "--database-url-env", "NONEXISTENT_DB_VAR"])
    assert ret != 0


def test_wheel_package_data_includes_migrations():
    """Verify package resources find the .sql migration files."""
    import importlib.resources
    files = [f.name for f in importlib.resources.files("fayda_mcp.migrations").iterdir()]
    assert "0001_initial_schema.up.sql" in files
    assert "0001_initial_schema.down.sql" in files
