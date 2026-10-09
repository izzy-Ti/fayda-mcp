"""Fayda National ID QR code credential verification package.

Implements offline/edge parsing, signature verification, and privacy-filtered
result evaluation for printed Fayda National ID QR credentials.
"""

# Supported QR specification versions
SUPPORTED_QR_VERSIONS = (4,)
DEFAULT_QR_VERSION = 4

# Delimiter tags in Version-4 QR layout
TAG_NAME_INTRO = "DLT"
TAG_VERSION = "V"
TAG_GENDER = "G"
TAG_FAN = "A"
TAG_DOB = "D"
TAG_SIGNATURE = "SIGN"

QR_DELIMITERS = (
    TAG_NAME_INTRO,
    TAG_VERSION,
    TAG_GENDER,
    TAG_FAN,
    TAG_DOB,
    TAG_SIGNATURE,
)

from fayda_mcp.qr.signed_content import (
    DELIMITER_SIGN,
    build_jws_signing_input,
    decode_detached_jws,
    extract_signed_payload,
    normalize_qr_dob,
)
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

__all__ = [
    "SUPPORTED_QR_VERSIONS",
    "DEFAULT_QR_VERSION",
    "TAG_NAME_INTRO",
    "TAG_VERSION",
    "TAG_GENDER",
    "TAG_FAN",
    "TAG_DOB",
    "TAG_SIGNATURE",
    "QR_DELIMITERS",
    "DELIMITER_SIGN",
    "extract_signed_payload",
    "decode_detached_jws",
    "build_jws_signing_input",
    "normalize_qr_dob",
    "MAX_QR_TEXT_BYTES",
    "QRErrorCode",
    "QRVerificationError",
    "QRMalformedError",
    "QRDelimiterError",
    "QRUnsupportedVersionError",
    "QRPayloadSizeExceededError",
    "QRInvalidSignatureError",
    "QRUntrustedKeyError",
    "QRKeyBundleMissingError",
    "QRInvalidDateError",
    "QRDemographics",
    "QRSignatureMetadata",
    "QREvidence",
    "ParsedQRCode",
    "QRVerificationResult",
]

