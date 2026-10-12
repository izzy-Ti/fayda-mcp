"""Signing key parsers and converters for PEM and JWK formats."""

import base64
import json
import os
from typing import Any, Optional, Tuple, Union
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateNumbers, RSAPublicNumbers
from jwt.utils import base64url_decode
from fayda_mcp.exceptions import ConfigurationError


def _try_decode_base64_string(raw: str) -> Optional[str]:
    """Try to decode standard or urlsafe base64 string, adding padding if needed."""
    cleaned = raw.strip()
    pad = len(cleaned) % 4
    padded = cleaned + ("=" * (4 - pad)) if pad else cleaned

    for decode_fn in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            candidate = decode_fn(padded).decode("utf-8").strip()
            if candidate.startswith("{") or "BEGIN" in candidate:
                return candidate
        except Exception:
            continue
    return None


def parse_private_key(key_material: Union[str, bytes, dict[str, Any]]) -> Tuple[str, Optional[str]]:
    """Parse private key from raw PEM, JSON JWK, base64-encoded JWK, or file path.

    Returns:
        Tuple of (pem_string, kid_or_none)

    Raises:
        ConfigurationError if key cannot be parsed, without logging raw secret material.
    """
    kid: Optional[str] = None

    if isinstance(key_material, bytes):
        text = key_material.decode("utf-8").strip()
    elif isinstance(key_material, dict):
        text = json.dumps(key_material)
    else:
        text = str(key_material).strip()

    # If key_material looks like a filepath and exists on disk, read from it
    if len(text) < 1024 and "\n" not in text and not text.startswith("{"):
        try:
            if os.path.isfile(text):
                with open(text, "r", encoding="utf-8") as f:
                    text = f.read().strip()
        except Exception:
            pass

    # 1. Check if already standard PEM format
    if "BEGIN RSA PRIVATE KEY" in text or "BEGIN PRIVATE KEY" in text:
        return text, None

    # 2. Check if base64-encoded JSON JWK or base64 PEM
    if not text.startswith("{"):
        decoded = _try_decode_base64_string(text)
        if decoded:
            text = decoded
            if "BEGIN RSA PRIVATE KEY" in text or "BEGIN PRIVATE KEY" in text:
                return text, None

    # 3. Parse JWK JSON structure
    if text.startswith("{"):
        try:
            jwk = json.loads(text)
        except Exception as exc:
            raise ConfigurationError("Failed to parse private key: invalid JSON structure in JWK") from exc

        kid = jwk.get("kid")
        kty = jwk.get("kty")

        if kty == "RSA":
            try:
                n = int.from_bytes(base64url_decode(jwk["n"]), "big")
                e = int.from_bytes(base64url_decode(jwk["e"]), "big")
                d = int.from_bytes(base64url_decode(jwk["d"]), "big")
                p = int.from_bytes(base64url_decode(jwk["p"]), "big")
                q = int.from_bytes(base64url_decode(jwk["q"]), "big")

                # Recompute CRT coefficients for canonical RSA representation
                dmp1 = d % (p - 1)
                dmq1 = d % (q - 1)
                iqmp = pow(q, -1, p)

                numbers = RSAPrivateNumbers(
                    p=p,
                    q=q,
                    d=d,
                    dmp1=dmp1,
                    dmq1=dmq1,
                    iqmp=iqmp,
                    public_numbers=RSAPublicNumbers(e, n),
                )
                rsa_key = numbers.private_key()
                pem = rsa_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                ).decode("utf-8")
                return pem, kid
            except Exception as exc:
                raise ConfigurationError(
                    "Failed to convert RSA JWK to PEM: invalid or missing RSA components"
                ) from exc
        else:
            raise ConfigurationError(f"Unsupported key type in JWK: {kty}")

    # If it is neither valid PEM nor valid JWK
    raise ConfigurationError("Unrecognized private key format: expected PEM or RSA JWK")
