"""Unit tests for Task 11: FaydaQRVerificationService orchestration (qr/service.py)."""

import os
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from fayda_mcp.context import CallerContext
from fayda_mcp.exceptions import PolicyViolationError
from fayda_mcp.policy import VerificationPolicy
from fayda_mcp.qr.schemas import (
    QRVerificationRequest,
    QRVerificationResult,
)
from fayda_mcp.qr.service import FaydaQRVerificationService
from fayda_mcp.qr.trust import QRTrustStore, TrustedKey, calculate_key_thumbprint


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
def trust_store_with_valid_key(trusted_test_public_key: rsa.RSAPublicKey) -> QRTrustStore:
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


def test_service_orchestrates_valid_qr_verification_sync(
    synthetic_qr_raw: str,
    trust_store_with_valid_key: QRTrustStore,
):
    """Verify synchronous QR verification and policy predicate evaluation."""
    service = FaydaQRVerificationService(trust_store=trust_store_with_valid_key)

    request = QRVerificationRequest(
        qr_text=synthetic_qr_raw,
        checks=["credential_signature_valid", "age_over_18"],
        purpose="age_verification",
    )
    result = service.verify_qr_sync(request)

    assert isinstance(result, QRVerificationResult)
    assert result.status == "verified"
    assert result.credential_signature_valid is True
    assert result.holder_authenticated is False
    assert result.checks["credential_signature_valid"] is True
    assert result.checks["age_over_18"] is True

    # Demographics are privacy-filtered (None by default)
    assert result.demographics is None


def test_service_demographics_opt_in(
    synthetic_qr_raw: str,
    trust_store_with_valid_key: QRTrustStore,
):
    """Verify demographics are exposed only when explicitly requested."""
    service = FaydaQRVerificationService(trust_store=trust_store_with_valid_key)

    request = QRVerificationRequest(
        qr_text=synthetic_qr_raw,
        checks=["credential_signature_valid"],
        include_demographics=True,
    )
    result = service.verify_qr_sync(request)

    assert result.demographics is not None
    assert result.demographics.name == "Abebe Bikila"
    assert result.demographics.fan == "1234  5678  9012  3456"


@pytest.mark.asyncio
async def test_service_async_verification_with_audit_logging(
    synthetic_qr_raw: str,
    trust_store_with_valid_key: QRTrustStore,
):
    """Verify async verification workflow with audit logging and caller context."""
    audit = MockAuditLogger()
    service = FaydaQRVerificationService(trust_store=trust_store_with_valid_key, audit=audit)

    context = CallerContext(tenant_id="tenant-xyz", principal_id="agent-007")
    request = QRVerificationRequest(
        qr_text=synthetic_qr_raw,
        checks=["credential_signature_valid", "age_over_21"],
    )
    result = await service.verify_qr(request, context=context)

    assert result.status == "verified"
    assert len(audit.events) == 1
    event = audit.events[0]
    assert event["event_type"] == "qr_verification"
    assert event["metadata"]["tenant_id"] == "tenant-xyz"
    assert event["metadata"]["principal_id"] == "agent-007"
    assert event["metadata"]["credential_signature_valid"] is True


def test_service_enforces_tenant_policy(
    synthetic_qr_raw: str,
    trust_store_with_valid_key: QRTrustStore,
):
    """Verify that tenant policy rejects forbidden purposes or checks."""
    policy = VerificationPolicy(
        allowed_purposes=["restricted_purpose"],
        allowed_checks=["credential_signature_valid"],
    )
    service = FaydaQRVerificationService(trust_store=trust_store_with_valid_key, policy=policy)

    # 1. Disallowed purpose raises PolicyViolationError
    bad_purpose_req = QRVerificationRequest(
        qr_text=synthetic_qr_raw,
        purpose="unauthorized_purpose",
    )
    with pytest.raises(PolicyViolationError):
        service.verify_qr_sync(bad_purpose_req)

    # 2. Disallowed check raises PolicyViolationError
    bad_check_req = QRVerificationRequest(
        qr_text=synthetic_qr_raw,
        purpose="restricted_purpose",
        checks=["age_over_18"],  # Not in allowed_checks
    )
    with pytest.raises(PolicyViolationError):
        service.verify_qr_sync(bad_check_req)


def test_service_tampered_qr_fails_closed(
    synthetic_qr_raw: str,
    trust_store_with_valid_key: QRTrustStore,
):
    """Verify that tampered QR code fails closed with unverified predicates."""
    service = FaydaQRVerificationService(trust_store=trust_store_with_valid_key)

    tampered_raw = synthetic_qr_raw.replace("Abebe Bikila", "Tampered Name")
    request = QRVerificationRequest(
        qr_text=tampered_raw,
        checks=["credential_signature_valid", "age_over_18"],
    )
    result = service.verify_qr_sync(request)

    assert result.status == "invalid_signature"
    assert result.credential_signature_valid is False
    assert result.checks["credential_signature_valid"] is False
    assert result.checks["age_over_18"] == "unavailable"
    assert result.reasons["age_over_18"] == "credential_signature_unverified"


def test_service_missing_keys_returns_unverified(
    synthetic_qr_raw: str,
):
    """Verify that empty trust store returns status='unverified' without trusting results."""
    empty_store = QRTrustStore()
    service = FaydaQRVerificationService(trust_store=empty_store)

    request = QRVerificationRequest(
        qr_text=synthetic_qr_raw,
        checks=["credential_signature_valid", "age_over_18"],
    )
    result = service.verify_qr_sync(request)

    assert result.status == "unverified"
    assert result.credential_signature_valid is False
    assert result.checks["credential_signature_valid"] is False
    assert result.checks["age_over_18"] == "unavailable"
