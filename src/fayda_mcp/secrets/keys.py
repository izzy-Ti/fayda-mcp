"""Signing key parsers and converters for PEM and JWK formats."""

import base64
import json
from typing import Any, Optional, Tuple, Union
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateNumbers, RSAPublicNumbers
from jwt.utils import base64url_decode
from fayda_mcp.exceptions import ConfigurationError


def parse_private_key(key_material: Union[str, bytes, dict[str, Any]]) -> Tuple[str, Optional[str]]:
    """Parse private key from raw PEM, JSON JWK, or base64-encoded JWK.

    Returns:
        Tuple of (pem_string, kid_or_none)
    """
    kid: Optional[str] = None

    if isinstance(key_material, bytes):
        text = key_material.decode("utf-8").strip()
    elif isinstance(key_material, dict):
        text = json.dumps(key_material)
    else:
        text = key_material.strip()

    # 1. Check if already standard PEM format
    if "BEGIN RSA PRIVATE KEY" in text or "BEGIN PRIVATE KEY" in text:
        return text, None

    # 2. Check if base64-encoded JSON JWK
    if not text.startswith("{"):
        try:
            decoded = base64.b64decode(text).decode("utf-8").strip()
            if decoded.startswith("{"):
                text = decoded
        except Exception:
            pass

    # 3. Parse JWK JSON structure
    if text.startswith("{"):
        try:
            jwk = json.loads(text)
        except Exception as e:
            raise ConfigurationError(f"Failed to parse private key JSON JWK: {e}") from e

        kid = jwk.get("kid")
        kty = jwk.get("kty")

        if kty == "RSA":
            try:
                n = int.from_bytes(base64url_decode(jwk["n"]), "big")
                e = int.from_bytes(base64url_decode(jwk["e"]), "big")
                d = int.from_bytes(base64url_decode(jwk["d"]), "big")
                p = int.from_bytes(base64url_decode(jwk["p"]), "big")
                q = int.from_bytes(base64url_decode(jwk["q"]), "big")

                # Correct Chinese Remainder Theorem coefficients if necessary
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
                raise ConfigurationError(f"Failed to convert RSA JWK to PEM: {exc}") from exc
        else:
            raise ConfigurationError(f"Unsupported key type in JWK: {kty}")

    # Fallback to returning text as-is
    return text, kid
