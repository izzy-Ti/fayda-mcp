"""Unit tests for Task 13: Separate holder authentication (keep holder_authenticated=False and never set identity_verified from QR alone).

Security & Acceptance Requirements:
1. QR-only verification establishes credential integrity, NOT live holder presence.
2. holder_authenticated is ALWAYS False on QRVerificationResult and QREvidence.
3. identity_verified is ALWAYS False for standalone QR verification.
4. Schema-level type constraints (Literal[False]) forbid setting holder_authenticated=True or identity_verified=True.
5. If caller requests checks=['holder_authenticated', 'identity_verified'], outcomes evaluate strictly to False with explicit explanation reasons.
"""

import os
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import ValidationError

from fayda_mcp.qr.schemas import (
    QREvidence,
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


# ---------------------------------------------------------------------------
# 1. Schema Invariants (Literal[False] enforcement)
# ---------------------------------------------------------------------------


def test_schema_forbids_setting_holder_authenticated_true():
    """Attempting to construct QRVerificationResult or QREvidence with holder_authenticated=True fails validation."""
    with pytest.raises(ValidationError):
        QRVerificationResult(
            status="verified",
            credential_signature_valid=True,
            holder_authenticated=True,  # Schema requires Literal[False]
        )

    with pytest.raises(ValidationError):
        QREvidence(
            credential_signature_valid=True,
            holder_authenticated=True,  # Schema requires Literal[False]
        )


def test_schema_forbids_setting_identity_verified_true():
    """Attempting to construct QREvidence with identity_verified=True fails validation."""
    with pytest.raises(ValidationError):
        QREvidence(
            credential_signature_valid=True,
            identity_verified=True,  # Schema requires Literal[False]
        )


# ---------------------------------------------------------------------------
# 2. Service-Level Separation Tests
# ---------------------------------------------------------------------------


def test_qr_verification_result_keeps_holder_authenticated_false(
    synthetic_qr_raw: str,
    trust_store: QRTrustStore,
):
    """Even on an authorized, cryptographically valid QR card scan, holder_authenticated is strictly False."""
    service = FaydaQRVerificationService(trust_store=trust_store)
    req = QRVerificationRequest(
        qr_text=synthetic_qr_raw,
        checks=["credential_signature_valid"],
    )
    result = service.verify_qr_sync(req)

    assert result.status == "verified"
    assert result.credential_signature_valid is True
    # Invariant: holder_authenticated must remain False
    assert result.holder_authenticated is False
    if result.evidence:
        assert result.evidence.holder_authenticated is False
        assert result.evidence.identity_verified is False


def test_requested_holder_authenticated_evaluates_false_with_safe_reason(
    synthetic_qr_raw: str,
    trust_store: QRTrustStore,
):
    """When a caller requests holder_authenticated check, it evaluates to False with clear reason."""
    service = FaydaQRVerificationService(trust_store=trust_store)
    req = QRVerificationRequest(
        qr_text=synthetic_qr_raw,
        checks=["credential_signature_valid", "holder_authenticated"],
    )
    result = service.verify_qr_sync(req)

    assert result.credential_signature_valid is True
    assert result.checks["credential_signature_valid"] is True
    assert result.checks["holder_authenticated"] is False
    assert result.reasons["holder_authenticated"] == "qr_scan_does_not_authenticate_holder"
    assert result.holder_authenticated is False


def test_requested_identity_verified_evaluates_false_with_safe_reason(
    synthetic_qr_raw: str,
    trust_store: QRTrustStore,
):
    """When a caller requests identity_verified check, it evaluates to False with clear reason."""
    service = FaydaQRVerificationService(trust_store=trust_store)
    req = QRVerificationRequest(
        qr_text=synthetic_qr_raw,
        checks=["credential_signature_valid", "identity_verified"],
    )
    result = service.verify_qr_sync(req)

    assert result.credential_signature_valid is True
    assert result.checks["credential_signature_valid"] is True
    assert result.checks["identity_verified"] is False
    assert result.reasons["identity_verified"] == "offline_qr_alone_cannot_assert_identity"
    if result.evidence:
        assert result.evidence.identity_verified is False


def test_failure_cases_also_preserve_holder_authenticated_false(
    synthetic_qr_raw: str,
):
    """On signature failure, missing key bundle, or tampering, holder_authenticated is False."""
    empty_store = QRTrustStore()
    service = FaydaQRVerificationService(trust_store=empty_store)
    req = QRVerificationRequest(
        qr_text=synthetic_qr_raw,
        checks=["credential_signature_valid", "holder_authenticated", "identity_verified"],
    )
    result = service.verify_qr_sync(req)

    assert result.status == "unverified"
    assert result.credential_signature_valid is False
    assert result.holder_authenticated is False
    assert result.checks["holder_authenticated"] is False
    assert result.checks["identity_verified"] is False
