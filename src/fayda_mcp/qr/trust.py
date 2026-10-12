"""Trusted key store and bundle management for Fayda QR verification.

Maintains operator-approved public keys and X.509 certificates isolated from
online eSignet OIDC JWKS endpoints. Enforces strict fail-closed policies when
no trusted keys are configured.
"""

import base64
import glob
import hashlib
import json
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Union

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from fayda_mcp.qr.schemas import QRKeyBundleMissingError, QRUntrustedKeyError


def calculate_key_thumbprint(public_key: rsa.RSAPublicKey) -> str:
    """Calculate deterministic SHA-256 fingerprint (hex) over SubjectPublicKeyInfo DER bytes."""
    der_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der_bytes).hexdigest()


@dataclass(frozen=True)
class TrustedKey:
    """An operator-approved public key for offline QR signature validation."""

    public_key: rsa.RSAPublicKey
    thumbprint: str
    key_id: Optional[str] = None
    source: str = "operator_bundle"

    def __repr__(self) -> str:
        return f"TrustedKey(thumbprint={self.thumbprint[:8]}..., key_id={self.key_id}, source={self.source})"


def _decode_jwk_int(b64url_val: str) -> int:
    """Decode base64url big-endian integer parameter (RFC 7517/7518)."""
    padding = "=" * ((4 - len(b64url_val) % 4) % 4)
    raw = base64.urlsafe_b64decode(b64url_val + padding)
    return int.from_bytes(raw, byteorder="big")


def _rsa_from_jwk(jwk: Dict[str, Any]) -> rsa.RSAPublicKey:
    """Convert an RSA JWK into a cryptography RSAPublicKey."""
    if jwk.get("kty") != "RSA":
        raise ValueError(f"Expected JWK kty 'RSA', got '{jwk.get('kty')}'")
    n = _decode_jwk_int(jwk["n"])
    e = _decode_jwk_int(jwk["e"])
    return rsa.RSAPublicNumbers(e, n).public_key()


class QRTrustStore:
    """Operator-managed store of trusted QR card verification public keys.

    Security Boundaries:
    1. QR keys are strictly isolated from eSignet OIDC JWKS keys.
    2. Zero implicit network calls; all keys must be operator-provisioned.
    3. Fails closed (raises QRKeyBundleMissingError) if no keys are present.
    """

    def __init__(self, keys: Optional[List[TrustedKey]] = None):
        self._keys_by_thumbprint: Dict[str, TrustedKey] = {}
        self._keys_by_kid: Dict[str, TrustedKey] = {}
        if keys:
            for k in keys:
                self.add_key(k)

    def __len__(self) -> int:
        return len(self._keys_by_thumbprint)

    def is_empty(self) -> bool:
        return len(self._keys_by_thumbprint) == 0

    def require_keys(self) -> None:
        """Enforce fail-closed policy if no trusted keys are available."""
        if self.is_empty():
            raise QRKeyBundleMissingError(
                message="No trusted QR public keys or bundle configured. Offline verification cannot proceed.",
            )

    def add_key(self, key: TrustedKey) -> None:
        """Add an already constructed TrustedKey."""
        self._keys_by_thumbprint[key.thumbprint] = key
        if key.key_id:
            self._keys_by_kid[key.key_id] = key

    def get_keys(self) -> List[TrustedKey]:
        """Return all active trusted keys."""
        return list(self._keys_by_thumbprint.values())

    get_all_keys = get_keys

    def __len__(self) -> int:
        return len(self._keys_by_thumbprint)

    def get_key_by_thumbprint(self, thumbprint: str) -> Optional[TrustedKey]:
        """Lookup key by full SHA-256 thumbprint or leading hex prefix."""
        if thumbprint in self._keys_by_thumbprint:
            return self._keys_by_thumbprint[thumbprint]
        # Match by prefix if provided
        for tp, key in self._keys_by_thumbprint.items():
            if tp.startswith(thumbprint.lower()):
                return key
        return None

    def get_key_by_kid(self, kid: str) -> Optional[TrustedKey]:
        """Lookup key by explicit Key ID (kid) if present."""
        return self._keys_by_kid.get(kid)

    def load_pem(self, pem_data: Union[str, bytes], source: str = "pem") -> int:
        """Load one or more PEM public keys or X.509 certificates from text or bytes.

        Accepts multiple concatenated PEM blocks.
        """
        if isinstance(pem_data, bytes):
            pem_text = pem_data.decode("utf-8", errors="replace")
        else:
            pem_text = pem_data

        count = 0

        # Pattern for standard PUBLIC KEY blocks
        pub_blocks = re.findall(
            r"-----BEGIN (?:RSA )?PUBLIC KEY-----[\s\S]+?-----END (?:RSA )?PUBLIC KEY-----",
            pem_text,
        )
        for block in pub_blocks:
            try:
                pub = serialization.load_pem_public_key(block.encode("utf-8"))
                if isinstance(pub, rsa.RSAPublicKey):
                    tp = calculate_key_thumbprint(pub)
                    self.add_key(TrustedKey(public_key=pub, thumbprint=tp, source=source))
                    count += 1
            except Exception:
                continue

        # Pattern for CERTIFICATE blocks
        cert_blocks = re.findall(
            r"-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----",
            pem_text,
        )
        for block in cert_blocks:
            try:
                cert = x509.load_pem_x509_certificate(block.encode("utf-8"))
                pub = cert.public_key()
                if isinstance(pub, rsa.RSAPublicKey):
                    tp = calculate_key_thumbprint(pub)
                    self.add_key(TrustedKey(public_key=pub, thumbprint=tp, source=f"{source}:x509"))
                    count += 1
            except Exception:
                continue

        return count

    def load_jwks(self, jwks_data: Union[str, bytes, Dict[str, Any]], source: str = "jwks") -> int:
        """Load RSA public keys from a JWKS JSON structure or string."""
        if isinstance(jwks_data, (str, bytes)):
            parsed = json.loads(jwks_data)
        else:
            parsed = jwks_data

        keys_list = parsed.get("keys", []) if isinstance(parsed, dict) else parsed
        count = 0
        for jwk in keys_list:
            if not isinstance(jwk, dict) or jwk.get("kty") != "RSA":
                continue
            try:
                pub = _rsa_from_jwk(jwk)
                tp = calculate_key_thumbprint(pub)
                kid = jwk.get("kid")
                self.add_key(TrustedKey(public_key=pub, thumbprint=tp, key_id=kid, source=source))
                count += 1
            except Exception:
                continue

        return count

    def load_file(self, file_path: str) -> int:
        """Inspect and load keys from a local PEM, X.509 certificate, or JWKS JSON file."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"QR key bundle file not found at '{file_path}'")

        with open(file_path, "rb") as f:
            raw = f.read()

        text = raw.decode("utf-8", errors="replace").strip()
        count = 0

        # Try JSON / JWKS first if begins with { or [
        if text.startswith("{") or text.startswith("["):
            try:
                count = self.load_jwks(text, source=file_path)
            except Exception:
                count = 0

        if count == 0:
            count = self.load_pem(raw, source=file_path)

        return count

    def load_directory(self, dir_path: str) -> int:
        """Load all PEM, CRT, and JWKS files found within a directory."""
        if not os.path.isdir(dir_path):
            raise NotADirectoryError(f"QR key directory not found: '{dir_path}'")

        count = 0
        patterns = ("*.pem", "*.crt", "*.cer", "*.jwks", "*.json")
        for pat in patterns:
            for filepath in glob.glob(os.path.join(dir_path, pat)):
                try:
                    count += self.load_file(filepath)
                except Exception:
                    continue
        return count


def load_trust_store_from_config(
    bundle_path: Optional[str] = None,
    inline_pem: Optional[str] = None,
) -> QRTrustStore:
    """Factory creating a QRTrustStore from paths or environment variables.

    Reads FAYDA_QR_KEY_BUNDLE_PATH or FAYDA_QR_PUBLIC_KEY_PEM if arguments are None.
    """
    store = QRTrustStore()

    effective_path = bundle_path or os.environ.get("FAYDA_QR_KEY_BUNDLE_PATH")
    effective_pem = inline_pem or os.environ.get("FAYDA_QR_PUBLIC_KEY_PEM")

    if effective_pem:
        store.load_pem(effective_pem, source="inline_config")

    if effective_path:
        if os.path.isdir(effective_path):
            store.load_directory(effective_path)
        elif os.path.isfile(effective_path):
            store.load_file(effective_path)

    return store
