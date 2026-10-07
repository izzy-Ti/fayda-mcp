"""Storage contract test suite applying to every storage backend adapter."""

import asyncio
import pytest
from fayda_mcp.schemas import VerificationResult
from fayda_mcp.storage.memory import (
    MemoryAuditLogger,
    MemoryResultRepository,
    MemorySessionStore,
)
from fayda_mcp.storage.protocols import AuditLogger, ResultRepository, SessionStore
from fayda_mcp import (
    CallerContext,
    ConfigurationError,
    FaydaConfig,
    FaydaVerificationService,
    InvalidStateError,
)


class BaseStorageAdapterContractTests:
    """Reusable contract test suite verifying any SessionStore and ResultRepository implementation."""

    async def create_session_store(self) -> SessionStore:
        raise NotImplementedError

    async def create_result_repository(self) -> ResultRepository:
        raise NotImplementedError

    async def create_audit_logger(self) -> AuditLogger:
        raise NotImplementedError

    @pytest.mark.asyncio
    async def test_session_save_and_get(self):
        store = await self.create_session_store()
        state = "state_test_1"
        data = {"request_id": "vr_1", "nonce": "nonce_1"}

        await store.save_session(state, data, ttl_seconds=60)
        retrieved = await store.get_session(state)
        assert retrieved is not None
        assert retrieved["request_id"] == "vr_1"
        assert retrieved["nonce"] == "nonce_1"

    @pytest.mark.asyncio
    async def test_duplicate_callback_state_fails(self):
        """Acceptance requirement: Duplicate callback state fails."""
        store = await self.create_session_store()
        state = "state_dup_test"
        data = {"request_id": "vr_dup", "user": "alice"}

        await store.save_session(state, data, ttl_seconds=60)

        # First consumption must succeed
        consumed_1 = await store.consume_session(state)
        assert consumed_1 is not None
        assert consumed_1["request_id"] == "vr_dup"

        # Second consumption of the same state MUST fail (return None)
        consumed_2 = await store.consume_session(state)
        assert consumed_2 is None

    @pytest.mark.asyncio
    async def test_concurrent_consume_state_only_one_succeeds(self):
        """Concurrent calls to consume_session for the same state: exactly one wins."""
        store = await self.create_session_store()
        state = "state_concurrent"
        await store.save_session(state, {"request_id": "vr_conc"}, ttl_seconds=60)

        # 10 concurrent consumers racing to consume the same state
        results = await asyncio.gather(*[store.consume_session(state) for _ in range(10)])

        successes = [r for r in results if r is not None]
        failures = [r for r in results if r is None]

        assert len(successes) == 1
        assert len(failures) == 9

    @pytest.mark.asyncio
    async def test_session_expiry(self):
        store = await self.create_session_store()
        state = "state_expired"
        await store.save_session(state, {"request_id": "vr_exp"}, ttl_seconds=0)

        # Immediate check should see expired session as None
        await asyncio.sleep(0.01)
        assert await store.get_session(state) is None
        assert await store.consume_session(state) is None

    @pytest.mark.asyncio
    async def test_idempotency_lookup(self):
        repo = await self.create_result_repository()
        request_id = "vr_idemp_1"
        data = {
            "request_id": request_id,
            "tenant_id": "tenant-A",
            "principal_id": "principal-B",
            "idempotency_key": "key-12345",
            "status": "pending",
        }

        await repo.save_request(request_id, data, ttl_seconds=60)

        found = await repo.find_by_idempotency_key("tenant-A", "principal-B", "key-12345")
        assert found is not None
        assert found["request_id"] == request_id

        # Mismatched tenant or principal returns None
        assert await repo.find_by_idempotency_key("tenant-OTHER", "principal-B", "key-12345") is None

    @pytest.mark.asyncio
    async def test_concurrent_completion_does_not_finalize_twice(self):
        """Acceptance requirement: Concurrent completion does not finalize twice."""
        repo = await self.create_result_repository()
        request_id = "vr_finalize_conc"
        await repo.save_request(request_id, {"status": "pending"}, ttl_seconds=60)

        result = VerificationResult(
            request_id=request_id,
            status="verified",
            checks={"identity_verified": True},
        )

        # 10 concurrent tasks attempt to finalize the result
        outcomes = await asyncio.gather(
            *[repo.finalize_result(request_id, result, ttl_seconds=60) for _ in range(10)]
        )

        # Exactly ONE task must succeed (return True), the rest must fail (return False)
        assert outcomes.count(True) == 1
        assert outcomes.count(False) == 9

        # Request status is updated to verified
        req = await repo.get_request(request_id)
        assert req is not None
        assert req["status"] == "verified"

        # Stored result is accessible
        saved_res = await repo.get_result(request_id)
        assert saved_res is not None
        assert saved_res.status == "verified"

    @pytest.mark.asyncio
    async def test_audit_append_and_query(self):
        logger = await self.create_audit_logger()
        await logger.record_event("started", {"request_id": "vr_audit_1"})
        await logger.record_event("completed", {"request_id": "vr_audit_1"})
        await logger.record_event("started", {"request_id": "vr_audit_2"})

        events_1 = await logger.get_events(request_id="vr_audit_1")
        assert len(events_1) == 2
        assert events_1[0]["event_type"] == "started"
        assert events_1[1]["event_type"] == "completed"

        events_all = await logger.get_events()
        assert len(events_all) == 3

    @pytest.mark.asyncio
    async def test_genuine_not_found_returns_none(self):
        """Acceptance: No production method silently returns None except a genuine not-found lookup."""
        repo = await self.create_result_repository()
        assert await repo.get_request("non_existent_req_id") is None
        assert await repo.get_result("non_existent_req_id") is None
        assert await repo.find_by_idempotency_key("tenant_x", "principal_y", "key_z") is None

    @pytest.mark.asyncio
    async def test_cleanup_purges_expired_records(self):
        """Verify cleanup purges expired requests and results."""
        repo = await self.create_result_repository()
        req_id = "vr_cleanup_exp"
        await repo.save_request(req_id, {"status": "pending"}, ttl_seconds=0)
        res = VerificationResult(
            request_id=req_id,
            status="verified",
            checks={"identity_verified": True},
        )
        await repo.save_result(req_id, res, ttl_seconds=0)

        await asyncio.sleep(0.01)
        purged = await repo.cleanup()
        assert purged >= 2
        assert await repo.get_request(req_id) is None
        assert await repo.get_result(req_id) is None

    @pytest.mark.asyncio
    async def test_reserve_request_unique_and_idempotent(self):
        """Verify reserve_request atomically prevents duplicate reservations for same idempotency key."""
        repo = await self.create_result_repository()
        req_id_1 = "vr_res_1"
        data_1 = {
            "tenant_id": "tenant-A",
            "principal_id": "principal-A",
            "idempotency_key": "idemp-unique-1",
            "status": "initializing",
            "request_fingerprint": "fp_hash_1",
            "auth_url": "https://auth.example/1",
        }

        # 1. First reservation succeeds
        reserved_1, rec_1 = await repo.reserve_request(req_id_1, data_1, ttl_seconds=60)
        assert reserved_1 is True
        assert rec_1["status"] == "initializing"

        # 2. Second reservation with same idempotency key returns False and existing record
        req_id_2 = "vr_res_2"
        data_2 = {
            "tenant_id": "tenant-A",
            "principal_id": "principal-A",
            "idempotency_key": "idemp-unique-1",
            "status": "initializing",
            "request_fingerprint": "fp_hash_1",
            "auth_url": "https://auth.example/2",
        }
        reserved_2, rec_2 = await repo.reserve_request(req_id_2, data_2, ttl_seconds=60)
        assert reserved_2 is False
        assert rec_2["request_id"] == req_id_1

    @pytest.mark.asyncio
    async def test_cancelled_or_terminal_cannot_finalize(self):
        """Acceptance requirement: Cancelled/expired requests cannot finalize verified."""
        repo = await self.create_result_repository()
        req_id = "vr_cancel_fin"
        await repo.save_request(req_id, {"status": "pending", "auth_url": "https://secret/auth"}, ttl_seconds=60)

        # Mark request as cancelled
        await repo.update_status(req_id, "cancelled")

        # Verify auth_url was purged on cancellation
        cancelled_req = await repo.get_request(req_id)
        assert cancelled_req is not None
        assert cancelled_req["status"] == "cancelled"
        assert not cancelled_req.get("authorization_url") and not cancelled_req.get("auth_url")

        # Attempt to finalize result on cancelled request fails
        res = VerificationResult(request_id=req_id, status="verified", checks={"identity_verified": True})
        success = await repo.finalize_result(req_id, res, ttl_seconds=60)
        assert success is False
        assert await repo.get_result(req_id) is None

    @pytest.mark.asyncio
    async def test_lifecycle_close(self):
        """Verify repository close cleans up without error."""
        repo = await self.create_result_repository()
        await repo.close()


class TestMemoryStorageAdapter(BaseStorageAdapterContractTests):
    """Run the storage contract suite against Memory adapters."""

    async def create_session_store(self) -> SessionStore:
        return MemorySessionStore()

    async def create_result_repository(self) -> ResultRepository:
        return MemoryResultRepository()

    async def create_audit_logger(self) -> AuditLogger:
        return MemoryAuditLogger()


class TestPostgresStorageAdapter(BaseStorageAdapterContractTests):
    """Run the storage contract suite against PostgreSQL / SQL adapters."""

    def setup_method(self) -> None:
        from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
        from sqlalchemy.pool import StaticPool
        from fayda_mcp.storage.postgres import PostgresAuditLogger, PostgresResultRepository

        self.engine = create_async_engine(
            "sqlite+aiosqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        self.factory = async_sessionmaker(self.engine, expire_on_commit=False, class_=AsyncSession)
        self.repo = PostgresResultRepository(session_factory=self.factory, engine=self.engine)
        self.audit = PostgresAuditLogger(session_factory=self.factory)
        self._initialized = False

    async def _ensure_tables(self) -> None:
        if not self._initialized:
            await self.repo.create_tables()
            self._initialized = True

    async def create_session_store(self) -> SessionStore:
        return MemorySessionStore()

    async def create_result_repository(self) -> ResultRepository:
        await self._ensure_tables()
        return self.repo

    async def create_audit_logger(self) -> AuditLogger:
        await self._ensure_tables()
        return self.audit


@pytest.mark.asyncio
async def test_service_duplicate_callback_state_fails():
    """Verify at the service level that replaying the same callback state raises an error."""
    config = FaydaConfig(
        client_id="test",
        redirect_uri="https://test/cb",
        issuer="https://test",
        authorization_endpoint="https://test/auth",
        token_endpoint="https://test/token",
        userinfo_endpoint="https://test/userinfo",
        jwks_uri="https://test/jwks",
    )
    sessions = MemorySessionStore()
    results = MemoryResultRepository()
    service = FaydaVerificationService(config=config, sessions=sessions, results=results)

    # 1. Start verification
    ctx = CallerContext(tenant_id="tenant-1", principal_id="agent-1")
    started = await service.start_verification(
        context=ctx,
        purpose="onboarding",
        checks=["identity_verified"],
        application_user_ref="usr-1",
        idempotency_key="id-1",
    )

    # Extract state from authorization url query
    import urllib.parse
    parsed = urllib.parse.urlparse(started.authorization_url)
    qs = urllib.parse.parse_qs(parsed.query)
    state = qs["state"][0]

    # 2. First callback consumes state (requires signing key)
    with pytest.raises(ConfigurationError, match="signing key is required"):
        await service.complete_verification(code="auth_code_1", state=state)

    # 3. Second callback with the same state -> fails because state was already consumed
    with pytest.raises(InvalidStateError, match="invalid, expired, or already used"):
        await service.complete_verification(code="auth_code_1", state=state)


@pytest.mark.asyncio
async def test_service_idempotent_start_verification():
    """Verify repeating start_verification with same idempotency_key returns original request."""
    config = FaydaConfig(
        client_id="test",
        redirect_uri="https://test/cb",
        issuer="https://test",
        authorization_endpoint="https://test/auth",
        token_endpoint="https://test/token",
        userinfo_endpoint="https://test/userinfo",
        jwks_uri="https://test/jwks",
    )
    service = FaydaVerificationService(
        config=config,
        sessions=MemorySessionStore(),
        results=MemoryResultRepository(),
    )
    ctx = CallerContext(tenant_id="tenant-1", principal_id="agent-1")

    first = await service.start_verification(
        context=ctx,
        purpose="onboarding",
        checks=["identity_verified"],
        application_user_ref="usr-1",
        idempotency_key="same-key-123",
    )
    second = await service.start_verification(
        context=ctx,
        purpose="onboarding",
        checks=["identity_verified"],
        application_user_ref="usr-1",
        idempotency_key="same-key-123",
    )

    assert first.request_id == second.request_id
    assert first.authorization_url == second.authorization_url
    assert first.expires_at == second.expires_at
