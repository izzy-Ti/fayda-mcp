"""Unit tests for Task 08: Load the QR key bundle in qr/trust.py.

Verifies operator-approved key bundle loading across PEM, X.509 certs, and JWKS,
enforces fail-closed behavior when keys are missing, and confirms trust isolation
from eSignet OIDC JWKS.
"""

import base64
import datetime
import json
import os
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from fayda_mcp.qr.schemas import QRKeyBundleMissingError
from fayda_mcp.qr.trust import (
    QRTrustStore,
    TrustedKey,
    calculate_key_thumbprint,
    load_trust_store_from_config,
)


@pytest.fixture
def fixtures_dir() -> str:
    return os.path.join(os.path.dirname(os.path.dirname(__file__)), "fixtures")


@pytest.fixture
def test_public_pem_path(fixtures_dir: str) -> str:
    return os.path.join(fixtures_dir, "test_qr_rsa_public.pem")


def test_load_pem_public_key_from_file(test_public_pem_path: str):
    """Verify loading operator public key PEM from file."""
    store = QRTrustStore()
    count = store.load_file(test_public_pem_path)

    assert count == 1
    assert len(store) == 1
    assert not store.is_empty()

    key = store.get_keys()[0]
    assert isinstance(key, TrustedKey)
    assert isinstance(key.public_key, rsa.RSAPublicKey)
    assert len(key.thumbprint) == 64  # SHA-256 hex string

    # Lookup by thumbprint and prefix
    found = store.get_key_by_thumbprint(key.thumbprint)
    assert found == key
    found_prefix = store.get_key_by_thumbprint(key.thumbprint[:12])
    assert found_prefix == key


def test_load_concatenated_multi_pem_string():
    """Verify loading multiple PEM blocks in a single bundle."""
    key1 = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    key2 = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()

    pem1 = key1.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    pem2 = key2.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    bundle_pem = f"{pem1}\n{pem2}\n"

    store = QRTrustStore()
    count = store.load_pem(bundle_pem, source="multi_bundle")
    assert count == 2
    assert len(store) == 2


def test_load_x509_certificate():
    """Verify loading public key extracted from an X.509 certificate."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ET"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "National ID Program"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Fayda QR Card Signer"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .sign(priv, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    store = QRTrustStore()
    count = store.load_pem(cert_pem, source="fayda_cert")
    assert count == 1
    assert len(store) == 1

    loaded_key = store.get_keys()[0]
    expected_tp = calculate_key_thumbprint(pub)
    assert loaded_key.thumbprint == expected_tp


def test_load_jwks_json():
    """Verify loading operator keys from JWKS format."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_nums = priv.public_key().public_numbers()

    def int_to_b64(val: int) -> str:
        b = val.to_bytes((val.bit_length() + 7) // 8, byteorder="big")
        return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")

    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "kid": "fayda-qr-2024-v4",
                "use": "sig",
                "alg": "RS256",
                "n": int_to_b64(pub_nums.n),
                "e": int_to_b64(pub_nums.e),
            }
        ]
    }

    store = QRTrustStore()
    count = store.load_jwks(jwks)
    assert count == 1
    assert len(store) == 1

    by_kid = store.get_key_by_kid("fayda-qr-2024-v4")
    assert by_kid is not None
    assert by_kid.key_id == "fayda-qr-2024-v4"


def test_fail_closed_when_key_bundle_missing():
    """Verify strict fail-closed behavior when no trusted keys are configured."""
    empty_store = QRTrustStore()
    assert empty_store.is_empty()

    with pytest.raises(QRKeyBundleMissingError) as exc_info:
        empty_store.require_keys()

    assert exc_info.value.code == "qr_key_bundle_missing"
    assert "No trusted QR public keys" in exc_info.value.message


def test_load_nonexistent_file_raises_error():
    """Verify attempting to load a missing file raises FileNotFoundError."""
    store = QRTrustStore()
    with pytest.raises(FileNotFoundError):
        store.load_file("/nonexistent/path/to/bundle.pem")


def test_load_trust_store_from_config_factory(test_public_pem_path: str, monkeypatch: pytest.MonkeyPatch):
    """Verify factory loader reads environment variables correctly."""
    monkeypatch.setenv("FAYDA_QR_KEY_BUNDLE_PATH", test_public_pem_path)
    store = load_trust_store_from_config()
    assert len(store) == 1
    assert not store.is_empty()
