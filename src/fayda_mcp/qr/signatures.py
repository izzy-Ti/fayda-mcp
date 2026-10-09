"""Cryptographic detached RS256 signature verification for Fayda National ID QR codes.

Reconstructs RFC 7515 Appendix F detached JWS signing inputs over the exact byte payload
and verifies against operator-approved RSA public keys.
"""

from dataclasses import dataclass
import hashlib
from datetime import datetime, timezone
from typing import Optional, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from fayda_mcp.qr.parser import parse_qr_code
from fayda_mcp.qr.schemas import (
    ParsedQRCode,
    QRInvalidSignatureError,
    QRMalformedError,
    QRSignatureMetadata,
)
from fayda_mcp.qr.signed_content import (
    build_jws_signing_input,
    decode_detached_jws,
)
from fayda_mcp.qr.trust import QRTrustStore, TrustedKey


@dataclass(frozen=True)
class SignatureVerificationOutcome:
    """Detailed outcome of a cryptographic detached signature verification check."""

    valid: bool
    verifying_key: Optional[TrustedKey]
    verified_at: Optional[str]
    evidence_ref: Optional[str]
    signature_metadata: Optional[QRSignatureMetadata]
    error: Optional[str] = None


def verify_detached_qr_signature(
    qr_input: Union[ParsedQRCode, str],
    trust_store: QRTrustStore,
    raise_on_error: bool = False,
) -> SignatureVerificationOutcome:
    """Verify the detached RS256 digital signature of a Version-4 Fayda QR code.

    Rules:
    1. Reconstructs RFC 7515 Appendix F detached signing input:
       ASCII(header_b64) + '.' + ASCII(base64url(signed_payload_bytes))
    2. Signed payload bytes are exact UTF-8 bytes of string preceding ':SIGN:'.
    3. Evaluates against all candidate keys in the operator's QRTrustStore (no kid in header).
    4. Fails closed (raises QRKeyBundleMissingError) if trust store is empty.
    5. Returns SignatureVerificationOutcome or raises QRInvalidSignatureError if raise_on_error=True.
    """
    # 1. Enforce fail-closed key store policy
    trust_store.require_keys()

    # 2. Parse if raw string is provided
    if isinstance(qr_input, str):
        parsed = parse_qr_code(qr_input)
    elif isinstance(qr_input, ParsedQRCode):
        parsed = qr_input
    else:
        raise TypeError(f"Expected ParsedQRCode or str, got {type(qr_input).__name__}")

    # 3. Decode detached JWS token
    header, sig_bytes = decode_detached_jws(parsed.detached_jws)

    alg = header.get("alg")
    if alg != "RS256":
        raise QRMalformedError(
            message=f"Unsupported signature algorithm '{alg}'. Only 'RS256' is supported.",
            details={"algorithm": alg},
        )

    header_b64 = parsed.detached_jws.split("..")[0]

    # 4. Construct RFC 7515 detached JWS signing input
    payload_bytes = parsed.signed_payload_text.encode("utf-8")
    signing_input = build_jws_signing_input(header_b64, payload_bytes)

    # 5. Evaluate candidate keys from the trust store
    verifying_key: Optional[TrustedKey] = None
    for key in trust_store.get_keys():
        try:
            key.public_key.verify(
                sig_bytes,
                signing_input,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            verifying_key = key
            break
        except InvalidSignature:
            continue

    if verifying_key is not None:
        verified_at = datetime.now(timezone.utc).isoformat()
        evidence_digest = hashlib.sha256(payload_bytes).hexdigest()
        evidence_ref = f"sha256:{evidence_digest}"

        sig_meta = QRSignatureMetadata(
            algorithm="RS256",
            key_id=verifying_key.key_id,
            header_raw=header_b64,
            signature_bytes_len=len(sig_bytes),
            verified_at=verified_at,
            key_thumbprint=verifying_key.thumbprint,
            key_source=verifying_key.source,
        )

        return SignatureVerificationOutcome(
            valid=True,
            verifying_key=verifying_key,
            verified_at=verified_at,
            evidence_ref=evidence_ref,
            signature_metadata=sig_meta,
            error=None,
        )

    # Signature verification failed against all candidate keys
    error_msg = "QR detached signature verification failed: signature does not match any trusted key."
    if raise_on_error:
        raise QRInvalidSignatureError(
            message=error_msg,
            details={"keys_evaluated": len(trust_store)},
        )

    return SignatureVerificationOutcome(
        valid=False,
        verifying_key=None,
        verified_at=None,
        evidence_ref=None,
        signature_metadata=None,
        error=error_msg,
    )
