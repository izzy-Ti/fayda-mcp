"""Unit and acceptance tests for Task S4: Connection and retention controls."""

import asyncio
import os
import tempfile
import time
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from fayda_mcp import (
    CallerContext,
    FaydaConfig,
    FaydaVerificationService,
    VerificationNotFoundError,
)
from fayda_mcp.cli import main
from fayda_mcp.migrations.runner import MigrationRunner
from fayda_mcp.schemas import VerificationResult
from fayda_mcp.storage.memory import MemorySessionStore
from fayda_mcp.storage.postgres import PostgresAuditLogger, PostgresResultRepository
from fayda_mcp.storage.retention import RetentionCleanupManager


@pytest.fixture
def temp_db_file():
    """Provide a clean temporary SQLite database file for testing persistence across restarts."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        yield db_path
    finally:
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except PermissionError:
                pass


@pytest.mark.asyncio
async def test_restart_preserves_results_and_audits(temp_db_file):
    """Acceptance criterion: A restart preserves results and audit records across lifecycles."""
    db_url = f"sqlite+aiosqlite:///{temp_db_file}"

    # 1. Run migrations to initialize schema
    async with MigrationRunner(db_url) as runner:
        await runner.upgrade()

    req_id = "req-persisted-1"
    tenant_id = "tenant-prod"
    principal_id = "agent-alpha"
    now = time.time()

    # 2. Process Lifecycle 1: Create, finalize, audit, then shutdown
    engine_1 = create_async_engine(db_url)
    factory_1 = async_sessionmaker(engine_1, expire_on_commit=False, class_=AsyncSession)
    repo_1 = PostgresResultRepository(session_factory=factory_1, engine=engine_1)
    audit_1 = PostgresAuditLogger(session_factory=factory_1)

    try:
        req_record = {
            "request_id": req_id,
            "tenant_id": tenant_id,
            "principal_id": principal_id,
            "application_user_ref": "user-42",
            "purpose": "onboarding",
            "checks": ["identity_verified"],
            "status": "pending",
            "expires_at": now + 3600,
            "idempotency_key": "idemp-persist-1",
            "request_fingerprint": "fp-123",
            "authorization_url": "https://auth.example.com",
        }
        await repo_1.save_request(req_id, req_record, ttl_seconds=3600)

        result_to_save = VerificationResult(
            request_id=req_id,
            status="verified",
            checks={"identity_verified": True},
            verified_at="2026-10-07T12:00:00Z",
            evidence_ref="audit-event-1",
            policy_version="v1",
        )
        await repo_1.finalize_result(req_id, result_to_save, ttl_seconds=3600)

        await audit_1.record_event(
            event_type="verification_finalized",
            safe_metadata={
                "request_id": req_id,
                "tenant_id": tenant_id,
                "principal_id": principal_id,
                "status": "verified",
            },
        )
    finally:
        # Simulate shutdown / process restart
        await repo_1.close()
        await engine_1.dispose()

    # 3. Process Lifecycle 2: Reopen database and verify results and audits are intact
    engine_2 = create_async_engine(db_url)
    factory_2 = async_sessionmaker(engine_2, expire_on_commit=False, class_=AsyncSession)
    repo_2 = PostgresResultRepository(session_factory=factory_2, engine=engine_2)
    audit_2 = PostgresAuditLogger(session_factory=factory_2)

    try:
        # Check request persisted
        fetched_req = await repo_2.get_request(req_id)
        assert fetched_req is not None
        assert fetched_req["request_id"] == req_id
        assert fetched_req["status"] == "verified"

        # Check result persisted
        fetched_res = await repo_2.get_result(req_id)
        assert fetched_res is not None
        assert fetched_res.request_id == req_id
        assert fetched_res.status == "verified"
        assert fetched_res.checks == {"identity_verified": True}
        assert fetched_res.evidence_ref == "audit-event-1"

        # Check audit event persisted
        events = await audit_2.get_events(request_id=req_id)
        assert len(events) >= 1
        assert events[0]["event_type"] == "verification_finalized"
        assert events[0]["request_id"] == req_id
    finally:
        await repo_2.close()
        await engine_2.dispose()


@pytest.mark.asyncio
async def test_two_processes_share_state(temp_db_file):
    """Acceptance criterion: Two independent processes share state concurrently."""
    db_url = f"sqlite+aiosqlite:///{temp_db_file}"

    async with MigrationRunner(db_url) as runner:
        await runner.upgrade()

    engine_a = create_async_engine(db_url)
    factory_a = async_sessionmaker(engine_a, expire_on_commit=False, class_=AsyncSession)
    repo_a = PostgresResultRepository(session_factory=factory_a, engine=engine_a)

    engine_b = create_async_engine(db_url)
    factory_b = async_sessionmaker(engine_b, expire_on_commit=False, class_=AsyncSession)
    repo_b = PostgresResultRepository(session_factory=factory_b, engine=engine_b)

    req_id = "req-shared-proc"
    tenant_id = "tenant-shared"
    principal_id = "agent-shared"

    try:
        # Process A starts and reserves request
        req_record = {
            "request_id": req_id,
            "tenant_id": tenant_id,
            "principal_id": principal_id,
            "application_user_ref": "user-shared",
            "purpose": "kyc",
            "checks": ["identity_verified"],
            "status": "pending",
            "idempotency_key": "idemp-shared-99",
            "request_fingerprint": "fp-shared",
        }
        reserved, record = await repo_a.reserve_request(req_id, req_record, ttl_seconds=300)
        assert reserved is True

        # Process B immediately reads state created by Process A
        seen_by_b = await repo_b.find_by_idempotency_key(tenant_id, principal_id, "idemp-shared-99")
        assert seen_by_b is not None
        assert seen_by_b["request_id"] == req_id
        assert seen_by_b["status"] == "pending"

        # Process B finalizes result
        res_b = VerificationResult(
            request_id=req_id,
            status="verified",
            checks={"identity_verified": True},
            verified_at="2026-10-07T12:05:00Z",
        )
        await repo_b.finalize_result(req_id, res_b, ttl_seconds=300)

        # Process A immediately reads result finalized by Process B
        result_seen_by_a = await repo_a.get_result(req_id)
        assert result_seen_by_a is not None
        assert result_seen_by_a.status == "verified"
        assert result_seen_by_a.checks == {"identity_verified": True}
    finally:
        await repo_a.close()
        await repo_b.close()
        await engine_a.dispose()
        await engine_b.dispose()


@pytest.mark.asyncio
async def test_expired_results_are_denied_on_read_before_cleanup(temp_db_file):
    """Acceptance criterion: Expired results are denied on read even before cleanup executes."""
    db_url = f"sqlite+aiosqlite:///{temp_db_file}"

    async with MigrationRunner(db_url) as runner:
        await runner.upgrade()

    engine = create_async_engine(db_url)
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    repo = PostgresResultRepository(session_factory=factory, engine=engine)

    config = FaydaConfig(
        client_id="test-client",
        redirect_uri="https://app.example.com/callback",
        issuer="https://esignet.example.com",
        authorization_endpoint="https://esignet.example.com/auth",
        token_endpoint="https://esignet.example.com/token",
        userinfo_endpoint="https://esignet.example.com/userinfo",
        jwks_uri="https://esignet.example.com/jwks",
    )
    sessions = MemorySessionStore()
    service = FaydaVerificationService(config=config, sessions=sessions, results=repo)

    req_id = "req-expiry-test"
    tenant_id = "tenant-exp"
    principal_id = "agent-exp"
    ctx = CallerContext(tenant_id=tenant_id, principal_id=principal_id)

    try:
        # Create request with 3600-second retention
        req_record = {
            "request_id": req_id,
            "tenant_id": tenant_id,
            "principal_id": principal_id,
            "application_user_ref": "user-exp",
            "purpose": "onboarding",
            "checks": ["identity_verified"],
            "status": "pending",
            "idempotency_key": "idemp-exp-1",
            "request_fingerprint": "fp-exp-1",
        }
        await repo.save_request(req_id, req_record, ttl_seconds=3600)

        # Finalize result with 1-second TTL
        res = VerificationResult(
            request_id=req_id,
            status="verified",
            checks={"identity_verified": True},
            verified_at="2026-10-07T12:00:00Z",
        )
        await repo.finalize_result(req_id, res, ttl_seconds=1)

        # Before expiry: read succeeds
        read_res = await service.get_verification_result(ctx, req_id)
        assert read_res.status == "verified"

        # Wait for result TTL to elapse (1.1s)
        time.sleep(1.1)

        # VERIFY DATABASE: cleanup has NOT run yet, row still physically exists in database!
        async with factory() as session:
            db_check = await session.execute(
                text("SELECT count(*) as cnt FROM fayda_results WHERE request_id = :rid"),
                {"rid": req_id},
            )
            row = db_check.mappings().first()
            assert row is not None
            assert row["cnt"] == 1, "Row must still physically exist in table before cleanup"

        # ACCEPTANCE TEST: Repo denies read on expired result before cleanup executes
        repo_get = await repo.get_result(req_id)
        assert repo_get is None, "Repo must deny read on expired result"

        # ACCEPTANCE TEST: Service raises VerificationNotFoundError on expired result
        with pytest.raises(VerificationNotFoundError, match="expired"):
            await service.get_verification_result(ctx, req_id)

        # NOW run cleanup: expired result row is purged from table
        cleanup_manager = RetentionCleanupManager(repo)
        purged = await cleanup_manager.run_once()
        assert purged >= 1

        async with factory() as session:
            db_check_after = await session.execute(
                text("SELECT count(*) as cnt FROM fayda_results WHERE request_id = :rid"),
                {"rid": req_id},
            )
            row_after = db_check_after.mappings().first()
            assert row_after is not None
            assert row_after["cnt"] == 0, "Row must be purged after cleanup pass"
    finally:
        await repo.close()
        await engine.dispose()


@pytest.mark.asyncio
async def test_retention_cleanup_manager_periodic_lifecycle():
    """Verify RetentionCleanupManager start_periodic and clean cancellation."""
    from unittest.mock import AsyncMock

    mock_repo = AsyncMock()
    mock_repo.cleanup.return_value = 0

    manager = RetentionCleanupManager(mock_repo)
    task = manager.start_periodic(interval_seconds=0.05)
    assert not task.done()

    # Allow one or two loop iterations
    await asyncio.sleep(0.12)
    assert mock_repo.cleanup.call_count >= 1

    await manager.stop()
    assert task.done()


def test_tls_enforced_for_remote_neon_connections():
    """Verify that remote Neon endpoints automatically enforce TLS (sslmode=require)."""
    # Remote neon url missing sslmode
    neon_url = "postgresql://user:pass@ep-cool-12345-pooler.us-east-2.aws.neon.tech/neondb"

    repo = PostgresResultRepository.from_url(neon_url)
    assert repo._engine is not None
    engine_url_str = str(repo._engine.url)
    assert "sslmode=require" in engine_url_str

    # Runner also enforces sslmode
    runner = MigrationRunner(neon_url)
    assert runner._engine is not None
    runner_url_str = str(runner._engine.url)
    assert "sslmode=require" in runner_url_str


def test_small_process_pool_defaults_configured():
    """Verify small process pool defaults for PostgreSQL."""
    pg_url = "postgresql://user:pass@remotehost:5432/faydadb?sslmode=require"
    repo = PostgresResultRepository.from_url(pg_url)
    assert repo._engine is not None
    pool = repo._engine.pool
    # SQLAlchemy QueuePool defaults
    assert pool.size() == 5
    assert pool._max_overflow == 10
    assert pool._recycle == 300
    assert pool._pre_ping is True


def test_cli_cleanup_command(temp_db_file, capsys):
    """Verify the CLI `fayda-mcp cleanup` command runs cleanup pass synchronously."""
    db_url = f"sqlite+aiosqlite:///{temp_db_file}"

    # First migrate tables via CLI
    ret_migrate = main(["migrate", "--database-url", db_url])
    assert ret_migrate == 0

    exit_code = main(["cleanup", "--database-url", db_url])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "Retention cleanup completed" in captured.out
