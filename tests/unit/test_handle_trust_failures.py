"""Unit tests for Task 10: Handle trust failures, reject bad signatures/unsupported headers, and acceptance tests."""

import os
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from fayda_mcp.qr.decoder import decode_and_verify_qr
from fayda_mcp.qr.schemas import QRVerificationResult
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
            key_id="official-valid-key",
            source="test_fixtures",
        )
    )
    return store


# ---------------------------------------------------------------------------
# Acceptance Criterion 1: Decoder returns every observed field
# Acceptance Criterion 2: Official valid fixture passes signature verification
# ---------------------------------------------------------------------------


def test_decoder_returns_every_observed_field_and_passes_verification(
    synthetic_qr_raw: str,
    trust_store_with_valid_key: QRTrustStore,
):
    """Acceptance: Decoder returns every observed field and official valid fixture passes signature verification."""
    result = decode_and_verify_qr(synthetic_qr_raw, trust_store=trust_store_with_valid_key)

    assert isinstance(result, QRVerificationResult)
    assert result.status == "verified"
    assert result.credential_signature_valid is True
    # Invariant: holder_authenticated must remain False
    assert result.holder_authenticated is False
    assert result.error is None

    # Every observed demographic field must be present
    demo = result.demographics
    assert demo is not None
    assert demo.photo_base64url is not None and demo.photo_base64url.startswith("UklGR")
    assert demo.name == "Abebe Bikila"
    assert demo.name_normalized == "Abebe Bikila"
    assert demo.version == 4
    assert demo.gender == "M"
    assert demo.fan == "1234  5678  9012  3456"
    assert demo.fan_normalized == "1234567890123456"
    assert demo.date_of_birth == "1990/01/01"
    assert demo.dob_normalized == "1990-01-01"

    # Evidence record
    assert result.evidence is not None
    assert result.evidence.credential_signature_valid is True
    assert result.evidence.holder_authenticated is False
    assert result.evidence.identity_verified is False
    assert result.evidence.evidence_ref is not None
    assert result.evidence.key_thumbprint == trust_store_with_valid_key.get_keys()[0].thumbprint


# ---------------------------------------------------------------------------
# Acceptance Criterion 3: Missing keys / profile returns unverified
# Acceptance Criterion 4: No unsigned result becomes trusted
# ---------------------------------------------------------------------------


def test_missing_keys_or_profile_returns_unverified(synthetic_qr_raw: str):
    """Acceptance: Missing keys returns unverified with credential_signature_valid=False.

    No unsigned or unverified result becomes trusted.
    """
    # 1. With None trust store
    result_none = decode_and_verify_qr(synthetic_qr_raw, trust_store=None)
    assert result_none.status == "unverified"
    assert result_none.credential_signature_valid is False
    assert result_none.holder_authenticated is False
    assert result_none.error_code == "qr_key_bundle_missing"
    assert result_none.checks["credential_signature_valid"] is False

    # Observed fields are still returned for transparency if requested
    assert result_none.demographics is not None
    assert result_none.demographics.name == "Abebe Bikila"

    # 2. With empty trust store
    empty_store = QRTrustStore()
    result_empty = decode_and_verify_qr(synthetic_qr_raw, trust_store=empty_store)
    assert result_empty.status == "unverified"
    assert result_empty.credential_signature_valid is False
    assert result_empty.holder_authenticated is False
    assert result_empty.checks["credential_signature_valid"] is False


# ---------------------------------------------------------------------------
# Acceptance Criterion 5: Tampering fails signature verification
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "tampered_snippet",
    [
        ("Abebe Bikila", "Chala Kebede"),  # Tamper name
        ("1234  5678  9012  3456", "9999  5678  9012  3456"),  # Tamper FAN
        ("1990/01/01", "1990/01/02"),  # Tamper DOB
        (":G:M:", ":G:F:"),  # Tamper gender
    ],
)
def test_tampering_fails_verification(
    synthetic_qr_raw: str,
    trust_store_with_valid_key: QRTrustStore,
    tampered_snippet: tuple[str, str],
):
    """Acceptance: Tampering with any field fails signature verification."""
    original, replacement = tampered_snippet
    tampered_raw = synthetic_qr_raw.replace(original, replacement, 1)

    result = decode_and_verify_qr(tampered_raw, trust_store=trust_store_with_valid_key)

    assert result.status == "invalid_signature"
    assert result.credential_signature_valid is False
    assert result.holder_authenticated is False
    assert result.checks["credential_signature_valid"] is False
    assert result.evidence is not None
    assert result.evidence.credential_signature_valid is False


# ---------------------------------------------------------------------------
# Acceptance Criterion 6: Wrong keys fail
# ---------------------------------------------------------------------------


def test_wrong_keys_fail_verification(synthetic_qr_raw: str):
    """Acceptance: Wrong / unauthorized keys fail verification."""
    foreign_key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    wrong_store = QRTrustStore()
    wrong_store.add_key(
        TrustedKey(
            public_key=foreign_key,
            thumbprint=calculate_key_thumbprint(foreign_key),
            key_id="unauthorized-key",
            source="foreign",
        )
    )

    result = decode_and_verify_qr(synthetic_qr_raw, trust_store=wrong_store)

    assert result.status == "invalid_signature"
    assert result.credential_signature_valid is False
    assert result.holder_authenticated is False
    assert result.checks["credential_signature_valid"] is False


# ---------------------------------------------------------------------------
# Acceptance Criterion 7: Bad signatures & unsupported headers rejected
# ---------------------------------------------------------------------------


def test_bad_signature_bytes_fail(
    synthetic_qr_raw: str,
    trust_store_with_valid_key: QRTrustStore,
):
    """Verify that flipping bytes in signature fails verification."""
    payload, detached_jws = synthetic_qr_raw.split(":SIGN:")
    header, sig = detached_jws.split("..")
    # Flip the first character of the signature
    flipped_char = "Z" if sig[0] != "Z" else "A"
    tampered_sig = flipped_char + sig[1:]
    corrupted_raw = f"{payload}:SIGN:{header}..{tampered_sig}"

    result = decode_and_verify_qr(corrupted_raw, trust_store=trust_store_with_valid_key)
    assert result.status == "invalid_signature"
    assert result.credential_signature_valid is False


def test_unsupported_header_algorithm_rejected(
    synthetic_qr_raw: str,
    trust_store_with_valid_key: QRTrustStore,
):
    """Verify that unsupported JWS algorithm (e.g. 'none' or 'HS256') is rejected."""
    payload, detached_jws = synthetic_qr_raw.split(":SIGN:")
    _, sig = detached_jws.split("..")
    # '{"alg":"none"}' in base64url is 'eyJhbGciOiJub25lIn0'
    fake_header = "eyJhbGciOiJub25lIn0"
    corrupted_raw = f"{payload}:SIGN:{fake_header}..{sig}"

    result = decode_and_verify_qr(corrupted_raw, trust_store=trust_store_with_valid_key)
    assert result.status == "malformed_input"
    assert result.credential_signature_valid is False
    assert "Unsupported signature algorithm" in (result.error or "")
