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
    QRInvalidBase64Error,
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

from fayda_mcp.qr.parser import (
    ScannerInput,
    format_fan_display,
    ingest_scanner_text,
    normalize_dob_for_display,
    normalize_fan_digits,
    normalize_gender_for_display,
    normalize_name_for_display,
    parse_qr_code,
    validate_scanner_text,
)
from fayda_mcp.qr.trust import (
    QRTrustStore,
    TrustedKey,
    calculate_key_thumbprint,
    load_trust_store_from_config,
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
    "QRInvalidBase64Error",
    "QRDemographics",
    "QRSignatureMetadata",
    "QREvidence",
    "ParsedQRCode",
    "QRVerificationResult",
    "ScannerInput",
    "validate_scanner_text",
    "ingest_scanner_text",
    "normalize_fan_digits",
    "format_fan_display",
    "normalize_name_for_display",
    "normalize_gender_for_display",
    "normalize_dob_for_display",
    "parse_qr_code",
    "TrustedKey",
    "QRTrustStore",
    "calculate_key_thumbprint",
    "load_trust_store_from_config",
]

