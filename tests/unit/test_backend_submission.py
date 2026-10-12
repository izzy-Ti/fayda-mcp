"""Unit tests for Task 14: Add backend submission (submit_qr_verification binding request, caller, purpose, and application user).

Acceptance Requirements:
1. Expose submit_qr_verification on QR service and top-level verification service.
2. Bind request_id, caller (tenant/principal), purpose, and application user.
3. Persist minimal evidence to ResultRepository without leaking raw PII.
4. Support scoped idempotency deduplication and conflict detection.
5. Record non-sensitive structured audit events.
6. Support retrieval by opaque request_id with caller ownership enforcement.
"""

import os
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from fayda_mcp.config import FaydaConfig
from fayda_mcp.context import CallerContext
from fayda_mcp.exceptions import AuthorizationError, IdempotencyConflictError
from fayda_mcp.policy import VerificationPolicy
from fayda_mcp.qr.schemas import (
    QRVerificationRequest,
    QRVerificationResult,
)
from fayda_mcp.qr.service import FaydaQRVerificationService
from fayda_mcp.qr.trust import QRTrustStore, TrustedKey, calculate_key_thumbprint
from fayda_mcp.service import FaydaVerificationService
from fayda_mcp.storage.memory import MemoryResultRepository, MemorySessionStore


@pytest.fixture
def fixtures_dir() -> str:
    return os.path.join(os.path.dirname(os.path.dirname(__file__)), "fixtures")


@pytest.fixture
def synthetic_qr_raw(fixtures_dir: str) -> str:
    with open(os.path.join(fixtures_dir, "synthetic_authorized_qr_v4.txt"), "r", encoding="utf-8") as f:
        return f.read().strip()


@pytest.fixture
def trusted_test_public_key(fixtures_dir: str) -> rsa.RSAPublicKey:
    with open(os.path.join(fixtures_dir, "test_qr_rsa_public.pem"), "rb") as f:
        return serialization.load_pem_public_key(f.read())  # type: ignore


@pytest.fixture
def trust_store(trusted_test_public_key: rsa.RSAPublicKey) -> QRTrustStore:
    store = QRTrustStore()
    tp = calculate_key_thumbprint(trusted_test_public_key)
    store.add_key(
        TrustedKey(
            public_key=trusted_test_public_key,
            thumbprint=tp,
            key_id="test-key-2024",
            source="test_fixtures",
        )
    )
    return store


class MockAuditLogger:
    def __init__(self):
        self.events = []

    async def record_event(self, event_type: str, safe_metadata: dict):
        self.events.append({"event_type": event_type, "metadata": safe_metadata})

    async def get_events(self, request_id=None):
        return self.events


@pytest.mark.asyncio
async def test_submit_qr_verification_binds_caller_purpose_and_user(
    synthetic_qr_raw: str,
    trust_store: QRTrustStore,
):
    """submit_qr_verification generates opaque request ID and binds caller, purpose, and user."""
    results_repo = MemoryResultRepository()
    audit_logger = MockAuditLogger()
    service = FaydaQRVerificationService(
        trust_store=trust_store,
        results=results_repo,
        audit=audit_logger,
    )
    context = CallerContext(tenant_id="bank-123", principal_id="cashier-agent")

    result = await service.submit_qr_verification(
        qr_text=synthetic_qr_raw,
        context=context,
        purpose="account_opening",
        application_user_ref="usr_c0ffee",
        checks=["credential_signature_valid", "age_over_18"],
        idempotency_key="idemp_qr_1",
    )

    # 1. Returned result verification
    assert isinstance(result, QRVerificationResult)
    assert result.status == "verified"
    assert result.credential_signature_valid is True
    assert result.holder_authenticated is False
    assert result.request_id.startswith("qr_")
    assert result.purpose == "account_opening"
    assert result.application_user_ref == "usr_c0ffee"
    assert result.checks["credential_signature_valid"] is True
    assert result.checks["age_over_18"] is True

    # 2. Persisted record verification
    stored = await results_repo.get_request(result.request_id)
    assert stored is not None
    assert stored["request_id"] == result.request_id
    assert stored["tenant_id"] == "bank-123"
    assert stored["principal_id"] == "cashier-agent"
    assert stored["purpose"] == "account_opening"
    assert stored["application_user_ref"] == "usr_c0ffee"
    assert stored["idempotency_key"] == "idemp_qr_1"
    assert stored["status"] == "verified"
    assert stored["method"] == "qr_offline"
    # Ensure no raw PII in storage
    assert "photo" not in stored
    assert "photo_base64url" not in stored

    # 3. Audit log verification
    events = await audit_logger.get_events()
    assert len(events) == 1
    assert events[0]["event_type"] == "qr_verification"
    assert events[0]["metadata"]["tenant_id"] == "bank-123"
    assert events[0]["metadata"]["application_user_ref"] == "usr_c0ffee"


@pytest.mark.asyncio
async def test_submit_qr_verification_idempotency_replay_and_conflict(
    synthetic_qr_raw: str,
    trust_store: QRTrustStore,
):
    """Retrying with identical key returns cached result; differing params raises IdempotencyConflictError."""
    results_repo = MemoryResultRepository()
    service = FaydaQRVerificationService(trust_store=trust_store, results=results_repo)
    context = CallerContext(tenant_id="tenant-1", principal_id="agent-1")

    # First submission
    res1 = await service.submit_qr_verification(
        qr_text=synthetic_qr_raw,
        context=context,
        purpose="kyc",
        application_user_ref="usr_1",
        idempotency_key="key_abc",
    )

    # Exact replay returns cached result
    res2 = await service.submit_qr_verification(
        qr_text=synthetic_qr_raw,
        context=context,
        purpose="kyc",
        application_user_ref="usr_1",
        idempotency_key="key_abc",
    )
    assert res2.request_id == res1.request_id
    assert res2.status == res1.status
    assert res2.application_user_ref == "usr_1"

    # Conflicting replay (different user or purpose) raises IdempotencyConflictError
    with pytest.raises(IdempotencyConflictError, match="already been used"):
        await service.submit_qr_verification(
            qr_text=synthetic_qr_raw,
            context=context,
            purpose="kyc",
            application_user_ref="usr_2_conflict",
            idempotency_key="key_abc",
        )


@pytest.mark.asyncio
async def test_get_qr_verification_result_enforces_caller_ownership(
    synthetic_qr_raw: str,
    trust_store: QRTrustStore,
):
    """get_qr_verification_result retrieves result for owner and rejects mismatched tenants."""
    results_repo = MemoryResultRepository()
    service = FaydaQRVerificationService(trust_store=trust_store, results=results_repo)
    context_owner = CallerContext(tenant_id="tenant_owner", principal_id="agent_1")
    context_intruder = CallerContext(tenant_id="tenant_intruder", principal_id="agent_2")

    result = await service.submit_qr_verification(
        qr_text=synthetic_qr_raw,
        context=context_owner,
        purpose="kyc",
        application_user_ref="usr_99",
    )

    # Owner can retrieve
    retrieved = await service.get_qr_verification_result(result.request_id, context=context_owner)
    assert retrieved is not None
    assert retrieved.request_id == result.request_id
    assert retrieved.application_user_ref == "usr_99"

    # Intruder is denied
    with pytest.raises(AuthorizationError, match="Access denied"):
        await service.get_qr_verification_result(result.request_id, context=context_intruder)

    # Nonexistent request returns None
    assert await service.get_qr_verification_result("qr_nonexistent", context=context_owner) is None


@pytest.mark.asyncio
async def test_fayda_verification_service_delegates_submit_qr_verification(
    synthetic_qr_raw: str,
    trust_store: QRTrustStore,
):
    """Top-level FaydaVerificationService exposes submit_qr_verification seamlessly."""
    config = FaydaConfig(
        client_id="test_client",
        redirect_uri="https://localhost/callback",
        issuer="https://esignet.sandbox.fayda.et",
        authorization_endpoint="https://esignet.sandbox.fayda.et/authorize",
        token_endpoint="https://esignet.sandbox.fayda.et/token",
        userinfo_endpoint="https://esignet.sandbox.fayda.et/userinfo",
        jwks_uri="https://esignet.sandbox.fayda.et/jwks",
        qr_verification_enabled=True,
    )
    sessions = MemorySessionStore()
    results = MemoryResultRepository()
    audit = MockAuditLogger()

    service = FaydaVerificationService(
        config=config,
        sessions=sessions,
        results=results,
        audit=audit,
    )
    # Inject trust store into internal qr_service
    service.qr_service.trust_store = trust_store

    ctx = CallerContext(tenant_id="fintech_app", principal_id="api_server")
    res = await service.submit_qr_verification(
        qr_text=synthetic_qr_raw,
        context=ctx,
        purpose="kyc",
        application_user_ref="user_xyz",
        checks=["credential_signature_valid", "age_over_18"],
    )

    assert res.status == "verified"
    assert res.application_user_ref == "user_xyz"
    assert res.purpose == "kyc"
    assert res.credential_signature_valid is True

    # Check retrieval via top-level service
    fetched = await service.get_qr_verification_result(res.request_id, context=ctx)
    assert fetched is not None
    assert fetched.request_id == res.request_id
