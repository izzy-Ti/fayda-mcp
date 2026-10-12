"""Unit tests for Task 17: Persist minimal evidence in Neon / Postgres storage.

Validates that Neon / SQL results and audit trails store and retrieve:
- QR method ('qr_offline')
- Profile ('v4')
- Cryptographic key reference / thumbprint
- Evaluated policy version ('v1')
While strictly excluding demographic payloads, photo, and signature.
"""

import os
import time
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from fayda_mcp.context import CallerContext
from fayda_mcp.migrations.runner import MigrationRunner
from fayda_mcp.policy import VerificationPolicy
from fayda_mcp.qr.schemas import QRVerificationResult
from fayda_mcp.qr.service import FaydaQRVerificationService
from fayda_mcp.qr.trust import QRTrustStore, TrustedKey, calculate_key_thumbprint
from fayda_mcp.schemas import VerificationResult
from fayda_mcp.storage.postgres import PostgresAuditLogger, PostgresResultRepository


def _get_test_engine():
    """Create in-memory SQLite engine simulating Postgres storage schema."""
    return create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )


async def _get_migrated_storage():
    """Initialize repository and audit logger with full migrations applied."""
    engine = _get_test_engine()
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    repo = PostgresResultRepository(session_factory=factory, engine=engine)
    audit = PostgresAuditLogger(session_factory=factory)
    await repo.create_tables()
    return repo, audit, engine, factory


@pytest.mark.asyncio
async def test_migration_runner_applies_qr_minimal_evidence_schema():
    """Verify MigrationRunner applies schema migrations with QR evidence columns."""
    engine = _get_test_engine()
    async with MigrationRunner(engine) as runner:
        applied = await runner.upgrade()
        assert "0001" in applied

        # Verify columns exist via PRAGMA table_info on SQLite
        async with engine.connect() as conn:
            # Check fayda_requests
            res_req = await conn.execute(text("PRAGMA table_info(fayda_requests)"))
            req_cols = {row[1] for row in res_req.fetchall()}
            assert {"method", "profile", "key_reference", "evidence_ref", "times", "reasons", "credential_signature_valid", "verified_at"}.issubset(req_cols)

            # Check fayda_results
            res_res = await conn.execute(text("PRAGMA table_info(fayda_results)"))
            res_cols = {row[1] for row in res_res.fetchall()}
            assert {"method", "profile", "key_reference"}.issubset(res_cols)

            # Check fayda_audit_events
            res_aud = await conn.execute(text("PRAGMA table_info(fayda_audit_events)"))
            aud_cols = {row[1] for row in res_aud.fetchall()}
            assert {"method", "profile", "key_reference", "policy_version"}.issubset(aud_cols)


@pytest.mark.asyncio
async def test_postgres_result_repository_persists_and_retrieves_qr_result():
    """Verify PostgresResultRepository stores and retrieves QR method, profile, and key reference."""
    repo, audit, engine, factory = await _get_migrated_storage()

    req_id = "req_qr_test_persist"
    tenant_id = "tenant_neon"
    principal_id = "agent_neon"
    now_iso = "2026-10-10T12:00:00Z"
    thumbprint = "b9f5e143aa08d660e1"

    req_data = {
        "tenant_id": tenant_id,
        "principal_id": principal_id,
        "application_user_ref": "usr_neon_123",
        "idempotency_key": "idemp_neon_123",
        "purpose": "kyc_verification",
        "checks": ["credential_signature_valid", "age_over_18"],
        "status": "pending",
        "method": "qr_offline",
        "profile": "v4",
        "key_reference": thumbprint,
        "policy_version": "v1",
        "evidence_ref": "ev_ref_12345",
        "times": {"verified_at": now_iso},
        "reasons": {},
        "credential_signature_valid": True,
        "verified_at": now_iso,
    }

    # 1. Save and retrieve request
    await repo.save_request(req_id, req_data, ttl_seconds=300)
    fetched_req = await repo.get_request(req_id)
    assert fetched_req is not None
    assert fetched_req["method"] == "qr_offline"
    assert fetched_req["profile"] == "v4"
    assert fetched_req["key_reference"] == thumbprint
    assert fetched_req["policy_version"] == "v1"
    assert fetched_req["credential_signature_valid"] is True

    # 2. Lookup by idempotency key
    found_idemp = await repo.find_by_idempotency_key(tenant_id, principal_id, "idemp_neon_123")
    assert found_idemp is not None
    assert found_idemp["request_id"] == req_id
    assert found_idemp["method"] == "qr_offline"
    assert found_idemp["profile"] == "v4"
    assert found_idemp["key_reference"] == thumbprint

    # 3. Finalize result with QRVerificationResult
    qr_res = QRVerificationResult(
        request_id=req_id,
        status="verified",
        method="qr_offline",
        profile="v4",
        key_reference=thumbprint,
        policy_version="v1",
        checks={"credential_signature_valid": True, "age_over_18": True},
        verified_at=now_iso,
        evidence_ref="ev_ref_12345",
        credential_signature_valid=True,
        holder_authenticated=False,
    )

    audit_payload = {
        "event_type": "qr_verification_completed",
        "metadata": {
            "method": "qr_offline",
            "profile": "v4",
            "key_reference": thumbprint,
            "policy_version": "v1",
        },
    }

    finalized = await repo.finalize_result(req_id, qr_res, ttl_seconds=600, audit_event=audit_payload)
    assert finalized is True

    # 4. Read back result from repository
    retrieved_result = await repo.get_result(req_id)
    assert retrieved_result is not None
    assert isinstance(retrieved_result, QRVerificationResult)
    assert retrieved_result.method == "qr_offline"
    assert retrieved_result.profile == "v4"
    assert retrieved_result.key_reference == thumbprint
    assert retrieved_result.policy_version == "v1"
    assert retrieved_result.checks["credential_signature_valid"] is True
    assert retrieved_result.holder_authenticated is False

    # 5. Verify direct SQL rows in fayda_results and fayda_audit_events
    async with engine.connect() as conn:
        res_row = (await conn.execute(
            text(f"SELECT method, profile, key_reference, policy_version FROM {repo.results_table} WHERE request_id = :r"),
            {"r": req_id},
        )).mappings().first()
        assert res_row is not None
        assert res_row["method"] == "qr_offline"
        assert res_row["profile"] == "v4"
        assert res_row["key_reference"] == thumbprint
        assert res_row["policy_version"] == "v1"

        aud_row = (await conn.execute(
            text(f"SELECT method, profile, key_reference, policy_version, safe_metadata FROM {audit.audit_table} WHERE request_id = :r"),
            {"r": req_id},
        )).mappings().first()
        assert aud_row is not None
        assert aud_row["method"] == "qr_offline"
        assert aud_row["profile"] == "v4"
        assert aud_row["key_reference"] == thumbprint
        assert aud_row["policy_version"] == "v1"


@pytest.mark.asyncio
async def test_postgres_audit_logger_records_and_queries_minimal_evidence():
    """Verify PostgresAuditLogger records and queries method, profile, key_ref, and policy_version."""
    repo, audit, engine, factory = await _get_migrated_storage()

    req_id = "req_audit_test_1"
    safe_meta = {
        "request_id": req_id,
        "tenant_id": "tenant_1",
        "principal_id": "principal_1",
        "method": "qr_offline",
        "profile": "v4",
        "key_reference": "thumb_abc_xyz",
        "policy_version": "v1",
        "credential_signature_valid": True,
    }

    await audit.record_event(event_type="qr_verification_submitted", safe_metadata=safe_meta)

    events = await audit.get_events(request_id=req_id)
    assert len(events) == 1
    evt = events[0]
    assert evt["request_id"] == req_id
    assert evt["event_type"] == "qr_verification_submitted"
    assert evt["method"] == "qr_offline"
    assert evt["profile"] == "v4"
    assert evt["key_reference"] == "thumb_abc_xyz"
    assert evt["policy_version"] == "v1"
    assert evt["metadata"]["method"] == "qr_offline"


@pytest.mark.asyncio
async def test_qr_service_persists_minimal_evidence_in_postgres():
    """End-to-end service test: submit_qr_verification persists minimal evidence and audits in Neon."""
    repo, audit, engine, factory = await _get_migrated_storage()

    fixtures_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "fixtures")
    with open(os.path.join(fixtures_dir, "test_qr_rsa_public.pem"), "rb") as f:
        pub_key = serialization.load_pem_public_key(f.read())
    with open(os.path.join(fixtures_dir, "synthetic_authorized_qr_v4.txt"), "r", encoding="utf-8") as f:
        qr_text = f.read().strip()

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

    service = FaydaQRVerificationService(
        trust_store=store,
        results=repo,
        audit=audit,
        policy=VerificationPolicy(policy_version="v1"),
    )

    ctx = CallerContext(tenant_id="tenant_svc", principal_id="agent_svc")
    result = await service.submit_qr_verification(
        context=ctx,
        qr_text=qr_text,
        checks=["credential_signature_valid", "age_over_18"],
        purpose="onboarding",
        application_user_ref="user_emp_99",
        idempotency_key="idemp_emp_99",
    )

    assert result.status == "verified"
    assert result.method == "qr_offline"
    assert result.profile == "v4"
    assert result.key_reference == thumbprint
    assert result.policy_version == "v1"
    assert result.holder_authenticated is False

    # Check persisted record in Postgres repository
    persisted_req = await repo.get_request(result.request_id)
    assert persisted_req is not None
    assert persisted_req["method"] == "qr_offline"
    assert persisted_req["profile"] == "v4"
    assert persisted_req["key_reference"] == thumbprint
    assert persisted_req["policy_version"] == "v1"

    # Check persisted audit trail in Postgres
    audit_events = await audit.get_events(request_id=result.request_id)
    assert len(audit_events) == 1
    evt = audit_events[0]
    assert evt["method"] == "qr_offline"
    assert evt["profile"] == "v4"
    assert evt["key_reference"] == thumbprint
    assert evt["policy_version"] == "v1"

    # Verify no demographics, photo, or signature in the audit metadata
    assert "name" not in evt["metadata"]
    assert "photo" not in evt["metadata"]
    assert "signature" not in evt["metadata"]

