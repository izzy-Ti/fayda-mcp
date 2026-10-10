"""Typed schemas, models, and safe domain error types for Fayda QR verification.

Defines parsed demographic fields, detached signature metadata, cryptographic
evidence records, verification results, and structured safe exception types.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Union
from pydantic import BaseModel, ConfigDict, Field

from fayda_mcp.exceptions import FaydaMCPError
from fayda_mcp.schemas import CheckOutcomeType

# Maximum allowed size for raw scanner input (bounded memory protection)
MAX_QR_TEXT_BYTES: int = 16384  # 16 KB
SUPPORTED_QR_VERSIONS = (4,)


class QRErrorCode(str, Enum):
    """Machine-readable safe error codes for QR processing."""

    MALFORMED_INPUT = "qr_malformed_input"
    DELIMITER_ERROR = "qr_delimiter_error"
    UNSUPPORTED_VERSION = "qr_unsupported_version"
    PAYLOAD_SIZE_EXCEEDED = "qr_payload_size_exceeded"
    INVALID_BASE64 = "qr_invalid_base64"
    INVALID_SIGNATURE = "qr_invalid_signature"
    UNTRUSTED_KEY = "qr_untrusted_key"
    KEY_BUNDLE_MISSING = "qr_key_bundle_missing"
    INVALID_DATE = "qr_invalid_date"
    INTERNAL_ERROR = "qr_internal_error"


# ---------------------------------------------------------------------------
# Exceptions Hierarchy
# ---------------------------------------------------------------------------


class QRVerificationError(FaydaMCPError):
    """Base exception for all Fayda QR verification errors."""

    def __init__(
        self,
        message: str,
        code: Union[str, QRErrorCode] = QRErrorCode.INTERNAL_ERROR,
        details: Optional[Dict[str, Any]] = None,
    ):
        code_str = code.value if isinstance(code, QRErrorCode) else str(code)
        super().__init__(message=message, code=code_str, details=details)


class QRMalformedError(QRVerificationError):
    """Raised when the QR raw text does not adhere to the Version-4 delimiter format."""

    def __init__(self, message: str = "Malformed QR code format", details: Optional[Dict[str, Any]] = None):
        super().__init__(message=message, code=QRErrorCode.MALFORMED_INPUT, details=details)


class QRDelimiterError(QRMalformedError):
    """Raised when expected delimiters (:DLT:, :V:, :G:, :A:, :D:, :SIGN:) are missing or repeated."""

    def __init__(self, message: str = "Missing or invalid QR delimiter tag", details: Optional[Dict[str, Any]] = None):
        super().__init__(message=message, details=details)
        self.code = QRErrorCode.DELIMITER_ERROR.value


class QRUnsupportedVersionError(QRVerificationError):
    """Raised when the QR specification version is not supported (only V4 currently supported)."""

    def __init__(self, version: Any, details: Optional[Dict[str, Any]] = None):
        msg = f"Unsupported QR version '{version}'. Only Version 4 is supported."
        details = details or {}
        details["unsupported_version"] = str(version)
        super().__init__(message=msg, code=QRErrorCode.UNSUPPORTED_VERSION, details=details)


class QRPayloadSizeExceededError(QRVerificationError):
    """Raised when raw scanner text exceeds maximum bounded size limit."""

    def __init__(self, size_bytes: int, max_bytes: int = MAX_QR_TEXT_BYTES, details: Optional[Dict[str, Any]] = None):
        msg = f"QR scanner payload size ({size_bytes} bytes) exceeds maximum limit of {max_bytes} bytes."
        details = details or {}
        details.update({"size_bytes": size_bytes, "max_bytes": max_bytes})
        super().__init__(message=msg, code=QRErrorCode.PAYLOAD_SIZE_EXCEEDED, details=details)


class QRInvalidBase64Error(QRMalformedError):
    """Raised when base64url decoding fails for photo or detached signature."""

    def __init__(self, message: str = "Invalid base64url encoding", details: Optional[Dict[str, Any]] = None):
        super().__init__(message=message, details=details)
        self.code = QRErrorCode.INVALID_BASE64.value


class QRInvalidSignatureError(QRVerificationError):
    """Raised when cryptographic detached RS256 signature verification fails."""

    def __init__(self, message: str = "QR digital signature verification failed", details: Optional[Dict[str, Any]] = None):
        super().__init__(message=message, code=QRErrorCode.INVALID_SIGNATURE, details=details)


class QRUntrustedKeyError(QRVerificationError):
    """Raised when the signature does not match any key in the configured trusted QR key bundle."""

    def __init__(self, message: str = "QR signature was not signed by a trusted issuer key", details: Optional[Dict[str, Any]] = None):
        super().__init__(message=message, code=QRErrorCode.UNTRUSTED_KEY, details=details)


class QRKeyBundleMissingError(QRVerificationError):
    """Raised when no trusted QR key bundle or certificates are configured."""

    def __init__(self, message: str = "No trusted QR public keys or bundle configured", details: Optional[Dict[str, Any]] = None):
        super().__init__(message=message, code=QRErrorCode.KEY_BUNDLE_MISSING, details=details)


class QRInvalidDateError(QRVerificationError):
    """Raised when the date of birth field cannot be parsed or validated."""

    def __init__(self, dob_str: str, details: Optional[Dict[str, Any]] = None):
        msg = f"Invalid date of birth format '{dob_str}' in QR credential."
        details = details or {}
        details["dob"] = dob_str
        super().__init__(message=msg, code=QRErrorCode.INVALID_DATE, details=details)


# ---------------------------------------------------------------------------
# Data Models & Schemas
# ---------------------------------------------------------------------------


class QRDemographics(BaseModel):
    """Demographic and credential attributes extracted from a parsed Fayda QR code."""

    model_config = ConfigDict(extra="forbid")

    photo_base64url: str = Field(..., description="Base64url-encoded WebP photo from the signed card payload")
    name: str = Field(..., description="Full legal name of the credential holder (preserved raw)")
    name_normalized: Optional[str] = Field(
        default=None,
        description="Whitespace-normalized full name for display",
    )
    version: int = Field(default=4, description="QR profile version number (e.g., 4)")
    gender: str = Field(..., description="Holder gender code as encoded on the card ('M', 'F', etc.)")
    gender_normalized: Optional[str] = Field(
        default=None,
        description="Standardized uppercase gender code for display ('M', 'F', 'O')",
    )
    fan: str = Field(..., description="Fayda Identification Number (FAN / FIN) raw display string with spacing")
    fan_normalized: str = Field(..., description="Normalized 16-digit FAN with all whitespace removed")
    date_of_birth: str = Field(..., description="Raw date of birth as printed in the QR code (YYYY/MM/DD)")
    dob_normalized: Optional[str] = Field(
        default=None,
        description="ISO 8601 normalized date of birth (YYYY-MM-DD)",
    )
    dob_calendar: str = Field(
        default="gregorian",
        description="Calendar convention applied to the birthdate ('gregorian' or 'ethiopic')",
    )


class QRSignatureMetadata(BaseModel):
    """Metadata describing the detached JWS digital signature."""

    model_config = ConfigDict(extra="forbid")

    algorithm: str = Field(default="RS256", description="Signature algorithm specified in the protected JWS header")
    key_id: Optional[str] = Field(
        default=None,
        description="Key identifier (kid). Omitted in Version 4 QR headers.",
    )
    header_raw: str = Field(
        default="eyJhbGciOiJSUzI1NiJ9",
        description="Base64url-encoded protected header string preceding the detached payload dots",
    )
    signature_bytes_len: int = Field(
        default=256,
        description="Length of decoded signature in bytes (256 bytes for 2048-bit RSA)",
    )
    verified_at: Optional[str] = Field(
        default=None,
        description="ISO 8601 UTC timestamp when signature verification succeeded",
    )
    key_thumbprint: Optional[str] = Field(
        default=None,
        description="SHA-256 thumbprint (hex) of the trusted public key that verified the signature",
    )
    key_source: Optional[str] = Field(
        default=None,
        description="Source of the matching trusted key (e.g. 'bundle', 'pem_file')",
    )


class QREvidence(BaseModel):
    """Cryptographic audit evidence generated during offline QR verification.

    Critical security invariants:
    - QR verification establishes CREDENTIAL INTEGRITY and ISSUER PROVENANCE only.
    - holder_authenticated is ALWAYS False because scanning a card does not prove live human presence.
    - identity_verified remains False unless combined with holder presence / biometric authentication.
    """

    model_config = ConfigDict(extra="forbid")

    evidence_type: Literal["qr_offline"] = Field(
        default="qr_offline",
        description="Evidence type identifier for offline QR scans",
    )
    credential_signature_valid: bool = Field(
        ...,
        description="True if the issuer's RS256 digital signature verified against a trusted key",
    )
    holder_authenticated: bool = Field(
        default=False,
        description="Always False for QR scans. Physical card scan does not prove live holder presence.",
    )
    identity_verified: bool = Field(
        default=False,
        description="Always False for standalone QR scans without authenticated holder presence.",
    )
    qr_version: int = Field(default=4, description="Fayda QR specification version")
    verified_at: Optional[str] = Field(
        default=None,
        description="ISO 8601 UTC timestamp of signature evaluation",
    )
    key_thumbprint: Optional[str] = Field(
        default=None,
        description="SHA-256 fingerprint of the verifying trusted public key",
    )
    evidence_ref: Optional[str] = Field(
        default=None,
        description="Deterministic opaque SHA-256 digest of the signed payload bytes",
    )
    checks_evaluated: Dict[str, CheckOutcomeType] = Field(
        default_factory=dict,
        description="Evaluated predicates (e.g., credential_signature_valid, age_over_18)",
    )
    reasons: Dict[str, str] = Field(
        default_factory=dict,
        description="Explanatory reason codes for unavailable checks",
    )


class ParsedQRCode(BaseModel):
    """Internal parsed representation containing preserved raw text, demographics, and signature."""

    model_config = ConfigDict(extra="forbid")

    raw_text: str = Field(..., description="Preserved, unmodified raw scanner text")
    demographics: QRDemographics = Field(..., description="Extracted demographic fields")
    signature: QRSignatureMetadata = Field(..., description="Extracted signature metadata")
    signed_payload_text: str = Field(..., description="Exact string portion preceding ':SIGN:'")
    detached_jws: str = Field(default="", description="Detached JWS signature string following ':SIGN:'")


class QRVerificationResult(BaseModel):
    """Top-level verification outcome returned by the QR verification engine.

    Follows privacy-preserving principles: by default, demographic details (photo, FAN, DOB)
    are NOT leaked unless explicitly authorized by caller policy.
    """

    model_config = ConfigDict(extra="forbid")

    status: Literal["verified", "unverified", "invalid_signature", "malformed_input", "untrusted_key", "error"] = Field(
        ...,
        description="High-level verification status outcome",
    )
    credential_signature_valid: bool = Field(
        ...,
        description="Cryptographic signature verification status",
    )
    holder_authenticated: bool = Field(
        default=False,
        description="Strictly False for QR scans without biometric or live authentication",
    )
    evidence: Optional[QREvidence] = Field(
        default=None,
        description="Structured audit evidence record",
    )
    demographics: Optional[QRDemographics] = Field(
        default=None,
        description="Demographics payload, present only when policy permits full claim extraction",
    )
    checks: Dict[str, CheckOutcomeType] = Field(
        default_factory=dict,
        description="Evaluated privacy-preserving boolean checks (e.g. credential_signature_valid)",
    )
    reasons: Dict[str, str] = Field(
        default_factory=dict,
        description="Safe reason codes for unavailable or failed checks",
    )
    error: Optional[str] = Field(
        default=None,
        description="Safe, non-sensitive error message if verification failed",
    )
    error_code: Optional[str] = Field(
        default=None,
        description="Machine-readable safe error code",
    )


class QRVerificationRequest(BaseModel):
    """Input payload to verify a Fayda QR code credential."""

    model_config = ConfigDict(extra="forbid")

    qr_text: str = Field(..., description="Raw text scanned from Fayda National ID QR code")
    checks: List[str] = Field(
        default_factory=lambda: ["credential_signature_valid"],
        description="Requested checks (e.g. ['credential_signature_valid', 'age_over_18'])",
    )
    optional_checks: Optional[List[str]] = Field(
        default=None,
        description="Optional checks that do not block policy completion if unavailable",
    )
    purpose: Optional[str] = Field(
        default="offline_verification",
        description="Business purpose for verification (e.g. 'age_verification', 'entry_check')",
    )
    application_user_ref: Optional[str] = Field(
        default=None,
        description="Opaque application user reference",
    )
    dob_calendar: Optional[str] = Field(
        default=None,
        description="Calendar convention for birthdate normalization ('gregorian' or 'ethiopic')",
    )
    include_demographics: bool = Field(
        default=False,
        description="Whether to include full demographic attributes in the result (requires permission)",
    )
