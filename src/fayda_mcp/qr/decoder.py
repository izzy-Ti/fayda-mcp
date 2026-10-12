"""End-to-end QR credential decoding and cryptographic verification engine.

Extracts all observed demographic fields and signature metadata while strictly enforcing
that no unsigned or unverified payload becomes trusted.
"""

import hashlib
from typing import Optional

from fayda_mcp.qr.parser import parse_qr_code
from fayda_mcp.qr.schemas import (
    QRErrorCode,
    QREvidence,
    QRVerificationError,
    QRVerificationResult,
)
from fayda_mcp.qr.signatures import verify_detached_qr_signature
from fayda_mcp.qr.trust import QRTrustStore


def decode_and_verify_qr(
    raw_text: str,
    trust_store: Optional[QRTrustStore] = None,
    dob_calendar: str = "gregorian",
    include_demographics: bool = True,
    max_bytes: Optional[int] = None,
    allowed_profiles: Optional[Sequence[str]] = None,
) -> QRVerificationResult:
    """Decode all observed fields from a Fayda QR code and perform cryptographic validation.

    Acceptance & Security Guarantees:
    1. Returns every observed field when syntax is valid (photo, name, version, gender, FAN, DOB, SIGN).
    2. Missing keys or missing profile returns status='unverified' with credential_signature_valid=False.
    3. Bad signatures, tampering, and wrong keys return status='invalid_signature' with credential_signature_valid=False.
    4. holder_authenticated is strictly False (QR verification proves credential integrity, not live presence).
    5. No unsigned or unverified result ever becomes trusted.
    """
    # 1. Parse raw scanner text and extract all observed fields
    try:
        parse_kwargs: Dict[str, Any] = {"dob_calendar": dob_calendar}
        if max_bytes is not None:
            parse_kwargs["max_bytes"] = max_bytes
        parsed = parse_qr_code(raw_text, **parse_kwargs)
    except QRVerificationError as err:
        return QRVerificationResult(
            status="malformed_input",
            credential_signature_valid=False,
            holder_authenticated=False,
            evidence=None,
            demographics=None,
            checks={"credential_signature_valid": False},
            reasons={"credential_signature_valid": err.code},
            error=err.message,
            error_code=err.code,
        )

    # 1.1 Check allowed profiles / versions
    if allowed_profiles is not None:
        v_str = f"v{parsed.demographics.version}".lower()
        allowed = [p.lower() for p in allowed_profiles]
        if v_str not in allowed and str(parsed.demographics.version) not in allowed:
            return QRVerificationResult(
                status="rejected",
                credential_signature_valid=False,
                holder_authenticated=False,
                evidence=None,
                demographics=parsed.demographics if include_demographics else None,
                checks={"credential_signature_valid": False},
                reasons={"credential_signature_valid": QRErrorCode.UNSUPPORTED_VERSION.value},
                error=f"QR profile '{v_str}' is not in allowed profiles: {list(allowed_profiles)}",
                error_code=QRErrorCode.UNSUPPORTED_VERSION.value,
            )

    # 2. Check trust store availability (missing keys/profile returns 'unverified')
    if trust_store is None or trust_store.is_empty():
        return QRVerificationResult(
            status="unverified",
            credential_signature_valid=False,
            holder_authenticated=False,
            evidence=QREvidence(
                evidence_type="qr_offline",
                credential_signature_valid=False,
                holder_authenticated=False,
                identity_verified=False,
                qr_version=parsed.demographics.version,
                evidence_ref=f"sha256:{hashlib.sha256(parsed.signed_payload_text.encode('utf-8')).hexdigest()}",
                checks_evaluated={"credential_signature_valid": False},
                reasons={"credential_signature_valid": QRErrorCode.KEY_BUNDLE_MISSING.value},
            ),
            demographics=parsed.demographics if include_demographics else None,
            checks={"credential_signature_valid": False},
            reasons={"credential_signature_valid": QRErrorCode.KEY_BUNDLE_MISSING.value},
            error="No trusted QR public key bundle configured. Credential remains unverified.",
            error_code=QRErrorCode.KEY_BUNDLE_MISSING.value,
        )

    # 3. Cryptographic signature verification against operator trust bundle
    try:
        outcome = verify_detached_qr_signature(parsed, trust_store, raise_on_error=False)
    except QRVerificationError as err:
        return QRVerificationResult(
            status="malformed_input",
            credential_signature_valid=False,
            holder_authenticated=False,
            evidence=None,
            demographics=parsed.demographics if include_demographics else None,
            checks={"credential_signature_valid": False},
            reasons={"credential_signature_valid": err.code},
            error=err.message,
            error_code=err.code,
        )

    if outcome.valid and outcome.verifying_key is not None:
        evidence = QREvidence(
            evidence_type="qr_offline",
            credential_signature_valid=True,
            holder_authenticated=False,
            identity_verified=False,
            qr_version=parsed.demographics.version,
            verified_at=outcome.verified_at,
            key_thumbprint=outcome.verifying_key.thumbprint,
            evidence_ref=outcome.evidence_ref,
            checks_evaluated={"credential_signature_valid": True},
            reasons={},
        )
        return QRVerificationResult(
            status="verified",
            credential_signature_valid=True,
            holder_authenticated=False,
            evidence=evidence,
            demographics=parsed.demographics if include_demographics else None,
            checks={"credential_signature_valid": True},
            reasons={},
            error=None,
            error_code=None,
        )

    # 4. Signature validation failure (tampering, wrong key, corrupt signature)
    evidence = QREvidence(
        evidence_type="qr_offline",
        credential_signature_valid=False,
        holder_authenticated=False,
        identity_verified=False,
        qr_version=parsed.demographics.version,
        evidence_ref=f"sha256:{hashlib.sha256(parsed.signed_payload_text.encode('utf-8')).hexdigest()}",
        checks_evaluated={"credential_signature_valid": False},
        reasons={"credential_signature_valid": QRErrorCode.INVALID_SIGNATURE.value},
    )
    return QRVerificationResult(
        status="invalid_signature",
        credential_signature_valid=False,
        holder_authenticated=False,
        evidence=evidence,
        demographics=parsed.demographics if include_demographics else None,
        checks={"credential_signature_valid": False},
        reasons={"credential_signature_valid": QRErrorCode.INVALID_SIGNATURE.value},
        error="Digital signature verification failed. Credential may be tampered or signed by an untrusted key.",
        error_code=QRErrorCode.INVALID_SIGNATURE.value,
    )
