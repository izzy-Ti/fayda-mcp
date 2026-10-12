"""Unit tests for Task 09: Verify detached RS256 signatures in qr/signatures.py."""

import os
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from fayda_mcp.qr.parser import parse_qr_code
from fayda_mcp.qr.schemas import (
    QRInvalidSignatureError,
    QRKeyBundleMissingError,
)
from fayda_mcp.qr.signatures import (
    SignatureVerificationOutcome,
    verify_detached_qr_signature,
)
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


def test_verify_valid_detached_signature_succeeds(
    synthetic_qr_raw: str,
    trust_store_with_valid_key: QRTrustStore,
):
    """Verify that an authorized synthetic fixture passes detached RS256 signature verification."""
    parsed = parse_qr_code(synthetic_qr_raw)
    outcome = verify_detached_qr_signature(parsed, trust_store_with_valid_key)

    assert isinstance(outcome, SignatureVerificationOutcome)
    assert outcome.valid is True
    assert outcome.verifying_key is not None
    assert outcome.verifying_key.key_id == "test-key-2024"
    assert outcome.verified_at is not None
    assert outcome.evidence_ref is not None
    assert outcome.evidence_ref.startswith("sha256:")
    assert outcome.signature_metadata is not None
    assert outcome.signature_metadata.algorithm == "RS256"
    assert outcome.signature_metadata.key_thumbprint == outcome.verifying_key.thumbprint


def test_verify_signature_from_raw_string(
    synthetic_qr_raw: str,
    trust_store_with_valid_key: QRTrustStore,
):
    """Verify that verify_detached_qr_signature accepts raw scanner text directly."""
    outcome = verify_detached_qr_signature(synthetic_qr_raw, trust_store_with_valid_key)
    assert outcome.valid is True


def test_wrong_key_fails_verification(synthetic_qr_raw: str):
    """Verify that a trust store with a different RSA key fails verification."""
    different_pub = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    store = QRTrustStore()
    store.add_key(
        TrustedKey(
            public_key=different_pub,
            thumbprint=calculate_key_thumbprint(different_pub),
            key_id="wrong-key",
            source="wrong_test_key",
        )
    )

    # Without raise_on_error
    outcome = verify_detached_qr_signature(synthetic_qr_raw, store, raise_on_error=False)
    assert outcome.valid is False
    assert outcome.verifying_key is None
    assert outcome.error is not None

    # With raise_on_error
    with pytest.raises(QRInvalidSignatureError):
        verify_detached_qr_signature(synthetic_qr_raw, store, raise_on_error=True)


def test_empty_trust_store_fails_closed(synthetic_qr_raw: str):
    """Verify that an empty trust store fails closed with QRKeyBundleMissingError."""
    empty_store = QRTrustStore()
    with pytest.raises(QRKeyBundleMissingError):
        verify_detached_qr_signature(synthetic_qr_raw, empty_store)


def test_multi_key_trust_store_finds_matching_candidate(
    synthetic_qr_raw: str,
    trusted_test_public_key: rsa.RSAPublicKey,
):
    """Verify candidate evaluation succeeds when multiple keys are present (no kid in header)."""
    decoy_pub1 = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    decoy_pub2 = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()

    multi_store = QRTrustStore()
    multi_store.add_key(TrustedKey(public_key=decoy_pub1, thumbprint=calculate_key_thumbprint(decoy_pub1), key_id="decoy-1"))
    multi_store.add_key(TrustedKey(public_key=trusted_test_public_key, thumbprint=calculate_key_thumbprint(trusted_test_public_key), key_id="valid-key"))
    multi_store.add_key(TrustedKey(public_key=decoy_pub2, thumbprint=calculate_key_thumbprint(decoy_pub2), key_id="decoy-2"))

    assert len(multi_store) == 3
    outcome = verify_detached_qr_signature(synthetic_qr_raw, multi_store)
    assert outcome.valid is True
    assert outcome.verifying_key is not None
    assert outcome.verifying_key.key_id == "valid-key"


def test_tampered_payload_text_fails_verification(
    synthetic_qr_raw: str,
    trust_store_with_valid_key: QRTrustStore,
):
    """Verify that any modification to the signed payload fails verification."""
    parsed = parse_qr_code(synthetic_qr_raw)

    # Tamper with the internal payload text
    tampered_payload = parsed.signed_payload_text.replace("Abebe Bikila", "Chala Kebede")
    tampered_parsed = parsed.model_copy(update={"signed_payload_text": tampered_payload})

    outcome = verify_detached_qr_signature(tampered_parsed, trust_store_with_valid_key)
    assert outcome.valid is False

    with pytest.raises(QRInvalidSignatureError):
        verify_detached_qr_signature(tampered_parsed, trust_store_with_valid_key, raise_on_error=True)
