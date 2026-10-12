"""Unit tests for Task 03: Confirm trusted key source, lifecycle, and authorized valid fixture."""

import os
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import pytest

from fayda_mcp.qr.signed_content import (
    build_jws_signing_input,
    decode_detached_jws,
    extract_signed_payload,
)


@pytest.fixture
def fixtures_dir() -> str:
    return os.path.join(os.path.dirname(os.path.dirname(__file__)), "fixtures")


@pytest.fixture
def authorized_qr_fixture(fixtures_dir: str) -> str:
    path = os.path.join(fixtures_dir, "synthetic_authorized_qr_v4.txt")
    with open(path, "r", encoding="utf-8") as f:
        return f.read().strip()


@pytest.fixture
def trusted_public_key(fixtures_dir: str):
    path = os.path.join(fixtures_dir, "test_qr_rsa_public.pem")
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def test_authorized_valid_fixture_passes_verification(authorized_qr_fixture: str, trusted_public_key):
    """Verify that the authorized valid fixture passes detached RS256 signature verification."""
    payload_text, detached_jws = extract_signed_payload(authorized_qr_fixture)
    header, sig_bytes = decode_detached_jws(detached_jws)

    header_b64 = detached_jws.split("..")[0]
    signing_input = build_jws_signing_input(header_b64, payload_text.encode("utf-8"))

    # Cryptographic RS256 verification must succeed without raising InvalidSignature
    trusted_public_key.verify(sig_bytes, signing_input, padding.PKCS1v15(), hashes.SHA256())


def test_tampered_payload_fails_signature_verification(authorized_qr_fixture: str, trusted_public_key):
    """Verify that tampering with any byte of the signed payload causes verification failure."""
    payload_text, detached_jws = extract_signed_payload(authorized_qr_fixture)
    header, sig_bytes = decode_detached_jws(detached_jws)
    header_b64 = detached_jws.split("..")[0]

    # Tamper with the FAN number
    tampered_payload = payload_text.replace("1234", "9999")
    tampered_input = build_jws_signing_input(header_b64, tampered_payload.encode("utf-8"))

    with pytest.raises(InvalidSignature):
        trusted_public_key.verify(sig_bytes, tampered_input, padding.PKCS1v15(), hashes.SHA256())


def test_wrong_key_fails_signature_verification(authorized_qr_fixture: str):
    """Verify that an unauthorized / foreign public key fails signature verification."""
    payload_text, detached_jws = extract_signed_payload(authorized_qr_fixture)
    header, sig_bytes = decode_detached_jws(detached_jws)
    header_b64 = detached_jws.split("..")[0]
    signing_input = build_jws_signing_input(header_b64, payload_text.encode("utf-8"))

    # Generate a different, unauthorized 2048-bit RSA key
    unauthorized_key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()

    with pytest.raises(InvalidSignature):
        unauthorized_key.verify(sig_bytes, signing_input, padding.PKCS1v15(), hashes.SHA256())
