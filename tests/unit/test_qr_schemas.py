"""Unit tests for Task 04: QR schemas, models, and safe error types."""

import pytest
from pydantic import ValidationError

from fayda_mcp.exceptions import FaydaMCPError
from fayda_mcp.qr.schemas import (
    MAX_QR_TEXT_BYTES,
    ParsedQRCode,
    QRDelimiterError,
    QRDemographics,
    QRErrorCode,
    QREvidence,
    QRInvalidDateError,
    QRInvalidSignatureError,
    QRKeyBundleMissingError,
    QRMalformedError,
    QRPayloadSizeExceededError,
    QRSignatureMetadata,
    QRUnsupportedVersionError,
    QRUntrustedKeyError,
    QRVerificationError,
    QRVerificationResult,
)


def test_qr_demographics_valid():
    """Verify valid instantiation and normalization fields in QRDemographics."""
    demo = QRDemographics(
        photo_base64url="UklGRtYBAABXRUJQVlA4IMoBAACwEQCdASpLAGQ...",
        name="Israel Ashenafi Bekele",
        version=4,
        gender="M",
        fan="6042  3061  7816  8402",
        fan_normalized="6042306178168402",
        date_of_birth="2004/12/28",
        dob_normalized="2004-12-28",
        dob_calendar="gregorian",
    )
    assert demo.name == "Israel Ashenafi Bekele"
    assert demo.version == 4
    assert demo.gender == "M"
    assert demo.fan_normalized == "6042306178168402"
    assert demo.dob_normalized == "2004-12-28"
    assert demo.dob_calendar == "gregorian"


def test_qr_demographics_extra_fields_forbidden():
    """Verify that unexpected extra fields are rejected."""
    with pytest.raises(ValidationError):
        QRDemographics(
            photo_base64url="xyz",
            name="Test User",
            version=4,
            gender="F",
            fan="1234",
            fan_normalized="1234",
            date_of_birth="2000/01/01",
            unexpected_field="disallowed",
        )


def test_qr_signature_metadata_defaults():
    """Verify signature metadata defaults and immutability."""
    sig = QRSignatureMetadata()
    assert sig.algorithm == "RS256"
    assert sig.key_id is None
    assert sig.signature_bytes_len == 256
    assert sig.header_raw == "eyJhbGciOiJSUzI1NiJ9"


def test_qr_evidence_security_invariants():
    """Verify critical security invariants on QREvidence.

    QR offline evidence must never assert holder_authenticated=True or
    identity_verified=True on its own.
    """
    evidence = QREvidence(
        credential_signature_valid=True,
        qr_version=4,
        key_thumbprint="abcdef123456",
        evidence_ref="sha256:0123456789abcdef",
    )
    assert evidence.evidence_type == "qr_offline"
    assert evidence.credential_signature_valid is True
    # Invariant: holder_authenticated must be False
    assert evidence.holder_authenticated is False
    # Invariant: identity_verified must be False for standalone QR
    assert evidence.identity_verified is False


def test_qr_verification_result_privacy():
    """Verify QRVerificationResult defaults to privacy-filtered presentation."""
    result = QRVerificationResult(
        status="verified",
        credential_signature_valid=True,
        checks={"credential_signature_valid": True, "age_over_18": True},
    )
    assert result.status == "verified"
    assert result.credential_signature_valid is True
    assert result.holder_authenticated is False
    assert result.demographics is None  # Not leaked by default
    assert result.checks["age_over_18"] is True


def test_parsed_qr_code_container():
    """Verify ParsedQRCode holds raw text, demographics, and signature."""
    demo = QRDemographics(
        photo_base64url="webp_data",
        name="Abebe Kebede",
        version=4,
        gender="M",
        fan="1111 2222 3333 4444",
        fan_normalized="1111222233334444",
        date_of_birth="1995/05/10",
        dob_normalized="1995-05-10",
    )
    sig = QRSignatureMetadata()
    parsed = ParsedQRCode(
        raw_text="raw_qr_content",
        demographics=demo,
        signature=sig,
        signed_payload_text="raw_qr_payload_before_sign",
    )
    assert parsed.raw_text == "raw_qr_content"
    assert parsed.demographics.name == "Abebe Kebede"
    assert parsed.signed_payload_text == "raw_qr_payload_before_sign"


def test_qr_exception_hierarchy_and_safe_serialization():
    """Verify typed domain exceptions inherit from FaydaMCPError and serialize safely."""
    # Base
    base_err = QRVerificationError("Test error", code=QRErrorCode.INTERNAL_ERROR)
    assert isinstance(base_err, FaydaMCPError)
    assert base_err.to_dict()["error"] == "qr_internal_error"

    # Malformed
    malformed_err = QRMalformedError("Bad syntax")
    assert malformed_err.code == "qr_malformed_input"

    # Delimiter
    delim_err = QRDelimiterError("Missing :SIGN:")
    assert delim_err.code == "qr_delimiter_error"

    # Unsupported version
    version_err = QRUnsupportedVersionError(version=2)
    assert version_err.code == "qr_unsupported_version"
    assert "2" in version_err.message
    assert version_err.details["unsupported_version"] == "2"

    # Payload size exceeded
    size_err = QRPayloadSizeExceededError(size_bytes=20000, max_bytes=MAX_QR_TEXT_BYTES)
    assert size_err.code == "qr_payload_size_exceeded"
    assert size_err.details["size_bytes"] == 20000

    # Invalid signature
    sig_err = QRInvalidSignatureError()
    assert sig_err.code == "qr_invalid_signature"

    # Untrusted key
    untrusted_err = QRUntrustedKeyError()
    assert untrusted_err.code == "qr_untrusted_key"

    # Key bundle missing
    bundle_err = QRKeyBundleMissingError()
    assert bundle_err.code == "qr_key_bundle_missing"

    # Invalid date
    date_err = QRInvalidDateError("9999/99/99")
    assert date_err.code == "qr_invalid_date"
    assert date_err.details["dob"] == "9999/99/99"
