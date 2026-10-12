"""Unit tests for Task 18: Scoped idempotency, atomic finalization, and host users-table success hook.

Validates:
1. Deterministic request fingerprinting (compute_qr_request_fingerprint).
2. Scoped idempotency deduplication with conflict detection (IdempotencyConflictError).
3. Atomic request reservation and finalization via ResultRepository (reserve_request, finalize_result).
4. Explicit host users-table success hook (HostUserSuccessContext, HostSuccessHookError) for both sync and async hooks.
5. Invariant that idempotent replay does NOT re-invoke the success hook.
6. Invariant that unverified / invalid signature / rejected requests NEVER trigger the success hook.
7. Audit trail records host_success_hook_failed event on hook failure.
8. End-to-end delegation through FaydaVerificationService.
"""

import os
from typing import List, Optional
import pytest
from cryptography.hazmat.primitives import serialization
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from fayda_mcp.context import CallerContext
from fayda_mcp.exceptions import HostSuccessHookError, IdempotencyConflictError
from fayda_mcp.policy import VerificationPolicy
from fayda_mcp.qr.schemas import HostUserSuccessContext, QRVerificationRequest
from fayda_mcp.qr.service import (
    FaydaQRVerificationService,
    compute_qr_request_fingerprint,
)
from fayda_mcp.qr.trust import QRTrustStore, TrustedKey, calculate_key_thumbprint
from fayda_mcp.service import FaydaVerificationService
from fayda_mcp.storage.memory import MemoryAuditLogger, MemoryResultRepository, MemorySessionStore
from fayda_mcp.storage.postgres import PostgresAuditLogger, PostgresResultRepository


def _load_fixtures():
    fixtures_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "fixtures")
    with open(os.path.join(fixtures_dir, "test_qr_rsa_public.pem"), "rb") as f:
        pub_key = serialization.load_pem_public_key(f.read())
    with open(os.path.join(fixtures_dir, "synthetic_authorized_qr_v4.txt"), "r", encoding="utf-8") as f:
        valid_qr = f.read().strip()
    return pub_key, valid_qr


def _build_test_trust_store(pub_key) -> tuple[QRTrustStore, str]:
    thumbprint = calculate_key_thumbprint(pub_key)
    store = QRTrustStore()
    store.add_key(
        TrustedKey(
            public_key=pub_key,
            thumbprint=thumbprint,
            key_id="test-key-2024",
            source="test_fixtures",
        )
    )
    return store, thumbprint


async def _get_postgres_storage():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    repo = PostgresResultRepository(session_factory=factory, engine=engine)
    audit = PostgresAuditLogger(session_factory=factory)
    await repo.create_tables()
    return repo, audit, engine


# ---------------------------------------------------------------------------
# 1. Deterministic Request Fingerprinting
# ---------------------------------------------------------------------------


def test_compute_qr_request_fingerprint_deterministic():
    """Verify that fingerprinting is deterministic and sort-invariant over checks."""
    fp1 = compute_qr_request_fingerprint(
        purpose="kyc_check",
        checks=["age_over_18", "credential_signature_valid"],
        application_user_ref="user_123",
        qr_text="test_qr_payload_data",
    )
    fp2 = compute_qr_request_fingerprint(
        purpose="kyc_check",
        checks=["credential_signature_valid", "age_over_18"],
        application_user_ref="user_123",
        qr_text="test_qr_payload_data",
    )
    assert fp1 == fp2
    assert len(fp1) == 64  # SHA-256 hex string


def test_compute_qr_request_fingerprint_detects_changes():
    """Verify that changing any parameter alters the fingerprint."""
    base_fp = compute_qr_request_fingerprint(
        purpose="kyc",
        checks=["credential_signature_valid"],
        application_user_ref="user_1",
        qr_text="data_1",
    )
    diff_user = compute_qr_request_fingerprint(
        purpose="kyc",
        checks=["credential_signature_valid"],
        application_user_ref="user_2",
        qr_text="data_1",
    )
    diff_purpose = compute_qr_request_fingerprint(
        purpose="other_purpose",
        checks=["credential_signature_valid"],
        application_user_ref="user_1",
        qr_text="data_1",
    )
    diff_qr = compute_qr_request_fingerprint(
        purpose="kyc",
        checks=["credential_signature_valid"],
        application_user_ref="user_1",
        qr_text="data_2",
    )
    assert base_fp != diff_user
    assert base_fp != diff_purpose
    assert base_fp != diff_qr


# ---------------------------------------------------------------------------
# 2. Scoped Idempotency & Conflict Handling
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_idempotent_retry_returns_cached_result_memory_and_postgres():
    """Submitting the same idempotency key twice returns the existing result without re-executing."""
    pub_key, valid_qr = _load_fixtures()
    store, _ = _build_test_trust_store(pub_key)

    for use_postgres in (False, True):
        if use_postgres:
            repo, audit, _ = await _get_postgres_storage()
        else:
            repo, audit = MemoryResultRepository(), MemoryAuditLogger()

        service = FaydaQRVerificationService(trust_store=store, results=repo, audit=audit)
        ctx = CallerContext(tenant_id="ten_1", principal_id="prin_1")

        # First submission
        res1 = await service.submit_qr_verification(
            context=ctx,
            qr_text=valid_qr,
            purpose="login",
            application_user_ref="usr_42",
            idempotency_key="idemp_repeat_1",
        )
        assert res1.status == "verified"

        # Repeated submission with identical parameters
        res2 = await service.submit_qr_verification(
            context=ctx,
            qr_text=valid_qr,
            purpose="login",
            application_user_ref="usr_42",
            idempotency_key="idemp_repeat_1",
        )
        assert res2.status == "verified"
        assert res2.request_id == res1.request_id
        assert res2.application_user_ref == res1.application_user_ref


@pytest.mark.asyncio
async def test_idempotent_retry_with_conflicting_parameters_raises():
    """Reusing an idempotency key with different user, purpose, or QR text raises IdempotencyConflictError."""
    pub_key, valid_qr = _load_fixtures()
    store, _ = _build_test_trust_store(pub_key)
    repo, audit = MemoryResultRepository(), MemoryAuditLogger()
    service = FaydaQRVerificationService(trust_store=store, results=repo, audit=audit)
    ctx = CallerContext(tenant_id="ten_1", principal_id="prin_1")

    # Initial submission
    await service.submit_qr_verification(
        context=ctx,
        qr_text=valid_qr,
        purpose="onboarding",
        application_user_ref="user_alice",
        idempotency_key="conflict_key_1",
    )

    # 1. Different user ref
    with pytest.raises(IdempotencyConflictError) as exc_info:
        await service.submit_qr_verification(
            context=ctx,
            qr_text=valid_qr,
            purpose="onboarding",
            application_user_ref="user_bob",
            idempotency_key="conflict_key_1",
        )
    assert "conflict_key_1" in str(exc_info.value)

    # 2. Different purpose
    with pytest.raises(IdempotencyConflictError):
        await service.submit_qr_verification(
            context=ctx,
            qr_text=valid_qr,
            purpose="different_purpose",
            application_user_ref="user_alice",
            idempotency_key="conflict_key_1",
        )

    # 3. Different checks / QR payload
    with pytest.raises(IdempotencyConflictError):
        await service.submit_qr_verification(
            context=ctx,
            qr_text=valid_qr + "extra_corrupted_bits",
            purpose="onboarding",
            application_user_ref="user_alice",
            idempotency_key="conflict_key_1",
        )


# ---------------------------------------------------------------------------
# 3. Explicit Host Users-Table Success Hook
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sync_host_success_hook_invoked_on_verified():
    """Synchronous host users-table hook is invoked with typed HostUserSuccessContext on verified outcome."""
    pub_key, valid_qr = _load_fixtures()
    store, thumbprint = _build_test_trust_store(pub_key)
    repo, audit = MemoryResultRepository(), MemoryAuditLogger()

    captured_contexts: List[HostUserSuccessContext] = []

    def host_users_table_hook(ctx: HostUserSuccessContext) -> None:
        # Host application updates its users table here
        captured_contexts.append(ctx)

    service = FaydaQRVerificationService(
        trust_store=store,
        results=repo,
        audit=audit,
        success_hook=host_users_table_hook,
    )

    ctx = CallerContext(tenant_id="tenant_host", principal_id="admin_1")
    res = await service.submit_qr_verification(
        context=ctx,
        qr_text=valid_qr,
        purpose="kyc_verification",
        application_user_ref="host_user_777",
        checks=["credential_signature_valid", "age_over_18"],
    )

    assert res.status == "verified"
    assert len(captured_contexts) == 1
    hook_ctx = captured_contexts[0]
    assert hook_ctx.application_user_ref == "host_user_777"
    assert hook_ctx.request_id == res.request_id
    assert hook_ctx.status == "verified"
    assert hook_ctx.method == "qr_offline"
    assert hook_ctx.profile == "v4"
    assert hook_ctx.key_reference == thumbprint
    assert hook_ctx.policy_version == "v1"
    assert hook_ctx.tenant_id == "tenant_host"
    assert hook_ctx.principal_id == "admin_1"
    assert hook_ctx.evidence_ref is not None


@pytest.mark.asyncio
async def test_async_host_success_hook_invoked_on_verified():
    """Asynchronous coroutine host hook is awaited with typed HostUserSuccessContext on verified outcome."""
    pub_key, valid_qr = _load_fixtures()
    store, _ = _build_test_trust_store(pub_key)
    repo, audit = MemoryResultRepository(), MemoryAuditLogger()

    captured_contexts: List[HostUserSuccessContext] = []

    async def async_host_hook(ctx: HostUserSuccessContext) -> None:
        captured_contexts.append(ctx)

    service = FaydaQRVerificationService(
        trust_store=store,
        results=repo,
        audit=audit,
    )
    service.set_success_hook(async_host_hook)

    ctx = CallerContext(tenant_id="t1", principal_id="p1")
    res = await service.submit_qr_verification(
        context=ctx,
        qr_text=valid_qr,
        purpose="login",
        application_user_ref="user_async_1",
    )

    assert res.status == "verified"
    assert len(captured_contexts) == 1
    assert captured_contexts[0].application_user_ref == "user_async_1"


@pytest.mark.asyncio
async def test_idempotent_replay_does_not_reinvoke_success_hook():
    """Critical invariant: replaying an idempotent request does NOT execute the success hook again."""
    pub_key, valid_qr = _load_fixtures()
    store, _ = _build_test_trust_store(pub_key)
    repo, audit = MemoryResultRepository(), MemoryAuditLogger()

    hook_invocations = 0

    def counting_hook(ctx: HostUserSuccessContext) -> None:
        nonlocal hook_invocations
        hook_invocations += 1

    service = FaydaQRVerificationService(
        trust_store=store,
        results=repo,
        audit=audit,
        success_hook=counting_hook,
    )

    ctx = CallerContext(tenant_id="t1", principal_id="p1")
    idemp_key = "idemp_no_double_hook"

    # First call -> hook executes once
    res1 = await service.submit_qr_verification(
        context=ctx,
        qr_text=valid_qr,
        purpose="login",
        application_user_ref="usr_abc",
        idempotency_key=idemp_key,
    )
    assert res1.status == "verified"
    assert hook_invocations == 1

    # Second call (idempotent retry) -> returns result, hook is NOT invoked again
    res2 = await service.submit_qr_verification(
        context=ctx,
        qr_text=valid_qr,
        purpose="login",
        application_user_ref="usr_abc",
        idempotency_key=idemp_key,
    )
    assert res2.status == "verified"
    assert res2.request_id == res1.request_id
    assert hook_invocations == 1


@pytest.mark.asyncio
async def test_success_hook_never_invoked_on_unverified_or_rejected():
    """Incomplete, untrusted, or invalid signature requests MUST NEVER trigger the host success hook."""
    pub_key, _ = _load_fixtures()
    store, _ = _build_test_trust_store(pub_key)
    repo, audit = MemoryResultRepository(), MemoryAuditLogger()

    hook_called = False

    def hook(ctx: HostUserSuccessContext) -> None:
        nonlocal hook_called
        hook_called = True

    service = FaydaQRVerificationService(
        trust_store=store,
        results=repo,
        audit=audit,
        success_hook=hook,
    )

    ctx = CallerContext(tenant_id="t1", principal_id="p1")

    # 1. Corrupted signature text
    res_corrupt = await service.submit_qr_verification(
        context=ctx,
        qr_text="INVALID_PAYLOAD:SIGN:corrupted_sig",
        purpose="login",
        application_user_ref="user_bad",
    )
    assert res_corrupt.status != "verified"
    assert hook_called is False

    # 2. Malformed input
    res_malformed = await service.submit_qr_verification(
        context=ctx,
        qr_text="completely_malformed_scanner_noise",
        purpose="login",
        application_user_ref="user_bad",
    )
    assert res_malformed.status != "verified"
    assert hook_called is False


@pytest.mark.asyncio
async def test_host_success_hook_failure_raises_and_records_audit():
    """If the host hook raises an error, wrap in HostSuccessHookError and audit host_success_hook_failed."""
    pub_key, valid_qr = _load_fixtures()
    store, _ = _build_test_trust_store(pub_key)
    repo, audit = MemoryResultRepository(), MemoryAuditLogger()

    def failing_hook(ctx: HostUserSuccessContext) -> None:
        raise RuntimeError("Database connection lost while writing to host users table")

    service = FaydaQRVerificationService(
        trust_store=store,
        results=repo,
        audit=audit,
        success_hook=failing_hook,
    )

    ctx = CallerContext(tenant_id="t1", principal_id="p1")

    with pytest.raises(HostSuccessHookError) as exc_info:
        await service.submit_qr_verification(
            context=ctx,
            qr_text=valid_qr,
            purpose="kyc",
            application_user_ref="user_db_fail",
        )

    assert "Database connection lost" in str(exc_info.value)

    # Verify audit event recorded for hook failure
    all_events = await audit.get_events()
    events = [e for e in all_events if e.get("event_type") == "host_success_hook_failed"]
    assert len(events) == 1
    meta = events[0].get("safe_metadata") or events[0].get("metadata", {})
    assert meta["application_user_ref"] == "user_db_fail"
    assert "Database connection lost" in meta["error"]


@pytest.mark.asyncio
async def test_per_request_success_hook_override():
    """Per-request success_hook overrides service-default hook."""
    pub_key, valid_qr = _load_fixtures()
    store, _ = _build_test_trust_store(pub_key)
    repo, audit = MemoryResultRepository(), MemoryAuditLogger()

    default_called = False
    override_called = False

    def default_hook(ctx: HostUserSuccessContext):
        nonlocal default_called
        default_called = True

    def override_hook(ctx: HostUserSuccessContext):
        nonlocal override_called
        override_called = True

    service = FaydaQRVerificationService(
        trust_store=store,
        results=repo,
        audit=audit,
        success_hook=default_hook,
    )

    ctx = CallerContext(tenant_id="t1", principal_id="p1")
    await service.submit_qr_verification(
        context=ctx,
        qr_text=valid_qr,
        purpose="kyc",
        application_user_ref="user_override",
        success_hook=override_hook,
    )

    assert default_called is False
    assert override_called is True


# ---------------------------------------------------------------------------
# 4. Delegation through FaydaVerificationService
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fayda_verification_service_forwards_qr_success_hook():
    """FaydaVerificationService forwards qr_success_hook into qr_service and executes on submit_qr_verification."""
    pub_key, valid_qr = _load_fixtures()
    store, _ = _build_test_trust_store(pub_key)
    repo, audit = MemoryResultRepository(), MemoryAuditLogger()
    sessions = MemorySessionStore()

    hook_calls: List[HostUserSuccessContext] = []

    def main_hook(ctx: HostUserSuccessContext):
        hook_calls.append(ctx)

    from fayda_mcp.config import FaydaConfig

    cfg = FaydaConfig(
        client_id="cid",
        redirect_uri="https://localhost/callback",
        issuer="https://esignet.fayda.et",
        authorization_endpoint="https://esignet.fayda.et/authorize",
        token_endpoint="https://esignet.fayda.et/token",
        userinfo_endpoint="https://esignet.fayda.et/userinfo",
        jwks_uri="https://esignet.fayda.et/jwks",
        qr_verification_enabled=True,
    )

    service = FaydaVerificationService(
        config=cfg,
        sessions=sessions,
        results=repo,
        audit=audit,
        qr_success_hook=main_hook,
    )
    # Inject our trusted keys into qr_service
    service.qr_service.trust_store = store

    ctx = CallerContext(tenant_id="ten_main", principal_id="prin_main")
    res = await service.submit_qr_verification(
        context=ctx,
        qr_text=valid_qr,
        purpose="onboarding",
        application_user_ref="emp_404",
    )

    assert res.status == "verified"
    assert len(hook_calls) == 1
    assert hook_calls[0].application_user_ref == "emp_404"
    assert hook_calls[0].tenant_id == "ten_main"
