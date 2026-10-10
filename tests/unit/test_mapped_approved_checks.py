"""Unit tests for Task 12: Map approved checks (credential_signature_valid, signed DOB age evaluation, confirmed calendar).

Acceptance Requirements:
1. Add credential_signature_valid as an approved check.
2. Evaluate age only from signed DOB with a confirmed calendar.
3. If signature verification fails, age checks fail closed as unavailable (unauthenticated DOB).
4. If calendar is unconfirmed, age checks fail closed as unavailable ('unconfirmed_calendar').
5. holder_authenticated is always False for offline QR scans.
6. identity_verified is never asserted for standalone offline QR scans.
7. Phone and email flags fail closed as unavailable ('claim_not_present_in_qr').
"""

import os
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from fayda_mcp.config import FaydaConfig
from fayda_mcp.qr.schemas import (
    QRVerificationRequest,
    QRVerificationResult,
)
from fayda_mcp.qr.service import FaydaQRVerificationService
from fayda_mcp.qr.signed_content import CONFIRMED_CALENDARS
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
# 1. credential_signature_valid Tests
# ---------------------------------------------------------------------------


def test_credential_signature_valid_evaluated_and_approved(
    synthetic_qr_raw: str,
    trust_store: QRTrustStore,
):
    """credential_signature_valid evaluates to True when signature matches trusted key."""
    service = FaydaQRVerificationService(trust_store=trust_store)
    req = QRVerificationRequest(
        qr_text=synthetic_qr_raw,
        checks=["credential_signature_valid"],
    )
    result = service.verify_qr_sync(req)

    assert result.status == "verified"
    assert result.credential_signature_valid is True
    assert result.checks["credential_signature_valid"] is True
    assert "credential_signature_valid" not in result.reasons


def test_credential_signature_valid_fails_on_tampering(
    synthetic_qr_raw: str,
    trust_store: QRTrustStore,
):
    """Tampering with signed envelope causes credential_signature_valid to be False."""
    service = FaydaQRVerificationService(trust_store=trust_store)

    # Tamper with the birthdate in the signed payload
    tampered_raw = synthetic_qr_raw.replace(":D:1990/01/01:", ":D:2004/12/28:")

    req = QRVerificationRequest(
        qr_text=tampered_raw,
        checks=["credential_signature_valid"],
    )
    result = service.verify_qr_sync(req)

    assert result.status == "invalid_signature"
    assert result.credential_signature_valid is False
    assert result.checks["credential_signature_valid"] is False
    assert result.reasons["credential_signature_valid"] == "qr_invalid_signature"


def test_credential_signature_valid_fails_on_missing_trust_store(
    synthetic_qr_raw: str,
):
    """Missing trusted key bundle returns unverified with credential_signature_valid = False."""
    empty_store = QRTrustStore()
    service = FaydaQRVerificationService(trust_store=empty_store)

    req = QRVerificationRequest(
        qr_text=synthetic_qr_raw,
        checks=["credential_signature_valid"],
    )
    result = service.verify_qr_sync(req)

    assert result.status == "unverified"
    assert result.credential_signature_valid is False
    assert result.checks["credential_signature_valid"] is False
    assert result.reasons["credential_signature_valid"] == "qr_key_bundle_missing"


# ---------------------------------------------------------------------------
# 2. Evaluate Age ONLY from Signed DOB with a Confirmed Calendar
# ---------------------------------------------------------------------------


def test_age_evaluation_with_confirmed_gregorian_calendar(
    synthetic_qr_raw: str,
    trust_store: QRTrustStore,
):
    """Age is evaluated accurately when signature is valid and Gregorian calendar is confirmed."""
    service = FaydaQRVerificationService(trust_store=trust_store)
    # The fixture DOB is 1990/01/01
    req = QRVerificationRequest(
        qr_text=synthetic_qr_raw,
        checks=["credential_signature_valid", "age_over_18"],
        dob_calendar="gregorian",
    )
    result = service.verify_qr_sync(req)

    assert result.status == "verified"
    assert result.credential_signature_valid is True
    assert result.checks["credential_signature_valid"] is True
    assert result.checks["age_over_18"] is True


def test_age_evaluation_with_confirmed_ethiopic_calendar(
    synthetic_qr_raw: str,
    trust_store: QRTrustStore,
):
    """Age is evaluated using Ethiopian calendar conversion when Ethiopic is confirmed."""
    service = FaydaQRVerificationService(trust_store=trust_store)
    req = QRVerificationRequest(
        qr_text=synthetic_qr_raw,
        checks=["credential_signature_valid", "age_over_18"],
        dob_calendar="ethiopic",
    )
    result = service.verify_qr_sync(req)

    assert result.status == "verified"
    assert result.credential_signature_valid is True
    assert result.checks["credential_signature_valid"] is True
    assert isinstance(result.checks["age_over_18"], bool)


def test_age_evaluation_fails_when_calendar_is_unconfirmed(
    synthetic_qr_raw: str,
    trust_store: QRTrustStore,
):
    """Age check returns unavailable when calendar is explicitly unconfirmed."""
    service = FaydaQRVerificationService(trust_store=trust_store)

    req = QRVerificationRequest(
        qr_text=synthetic_qr_raw,
        checks=["credential_signature_valid", "age_over_18"],
        dob_calendar="unconfirmed",
    )
    result = service.verify_qr_sync(req)

    # Signature is valid, but age cannot be evaluated without confirmed calendar
    assert result.credential_signature_valid is True
    assert result.checks["credential_signature_valid"] is True
    assert result.checks["age_over_18"] == "unavailable"
    assert result.reasons["age_over_18"] == "unconfirmed_calendar"
    assert result.status == "incomplete"


def test_age_evaluation_fails_when_signature_is_unverified(
    synthetic_qr_raw: str,
    trust_store: QRTrustStore,
):
    """Age checks MUST NOT evaluate from unauthenticated/tampered DOB."""
    service = FaydaQRVerificationService(trust_store=trust_store)

    # Tamper with the raw payload
    tampered_raw = synthetic_qr_raw.replace(":G:M:", ":G:F:")

    req = QRVerificationRequest(
        qr_text=tampered_raw,
        checks=["credential_signature_valid", "age_over_18"],
        dob_calendar="gregorian",
    )
    result = service.verify_qr_sync(req)

    # Signature fails, so age check fails closed as unavailable
    assert result.credential_signature_valid is False
    assert result.checks["credential_signature_valid"] is False
    assert result.checks["age_over_18"] == "unavailable"
    assert result.reasons["age_over_18"] == "credential_signature_unverified"
    assert result.status == "invalid_signature"


# ---------------------------------------------------------------------------
# 3. QR-Specific Check Invariants (holder_authenticated, identity_verified, contact)
# ---------------------------------------------------------------------------


def test_qr_only_checks_enforce_holder_and_identity_invariants(
    synthetic_qr_raw: str,
    trust_store: QRTrustStore,
):
    """QR verification never asserts holder_authenticated or identity_verified."""
    service = FaydaQRVerificationService(trust_store=trust_store)
    req = QRVerificationRequest(
        qr_text=synthetic_qr_raw,
        checks=[
            "credential_signature_valid",
            "holder_authenticated",
            "identity_verified",
            "phone_verified",
            "email_verified",
        ],
        dob_calendar="gregorian",
    )
    result = service.verify_qr_sync(req)

    # Credential integrity is verified
    assert result.credential_signature_valid is True
    assert result.checks["credential_signature_valid"] is True

    # Holder presence is strictly False
    assert result.holder_authenticated is False
    assert result.checks["holder_authenticated"] is False
    assert result.reasons["holder_authenticated"] == "qr_scan_does_not_authenticate_holder"

    # Identity verified is strictly False
    assert result.checks["identity_verified"] is False
    assert result.reasons["identity_verified"] == "offline_qr_alone_cannot_assert_identity"

    # Contact checks fail closed as claim not present in QR
    assert result.checks["phone_verified"] == "unavailable"
    assert result.reasons["phone_verified"] == "claim_not_present_in_qr"

    assert result.checks["email_verified"] == "unavailable"
    assert result.reasons["email_verified"] == "claim_not_present_in_qr"
