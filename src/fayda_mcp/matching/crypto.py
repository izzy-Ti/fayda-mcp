"""Cryptographic primitives for encrypting retained expected details at rest.

Uses AES-256-GCM (Authenticated Encryption with Associated Data) to encrypt
personal identity claims (names, dates of birth) before storage, preventing
unauthorized inspection of memory or storage dumps.
"""

import base64
import json
import os
import secrets
from typing import Any, Dict, Optional, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from fayda_mcp.matching.schemas import (
    DetailsMatchingError,
    DetailsMatchingErrorCode,
    ExpectedDetails,
)

ENCRYPTION_PREFIX = "enc:v1:"
HKDF_SALT = b"fayda-expected-details-salt"
HKDF_INFO = b"fayda-details-encryption-v1"


def derive_encryption_key(key_material: Union[str, bytes]) -> bytes:
    """Derive a 256-bit (32-byte) AES key from input key material.

    Supports:
    - Raw 32 bytes
    - Hex-encoded 64 characters
    - Base64-encoded 32 bytes
    - Passphrase/secret string derived via HKDF-SHA256
    """
    if isinstance(key_material, str):
        key_str = key_material.strip()
        # Check 64-char hex
        if len(key_str) == 64:
            try:
                return bytes.fromhex(key_str)
            except ValueError:
                pass
        # Check base64
        try:
            decoded = base64.b64decode(key_str)
            if len(decoded) == 32:
                return decoded
        except Exception:
            pass
        raw_bytes = key_str.encode("utf-8")
    else:
        raw_bytes = bytes(key_material)

    if len(raw_bytes) == 32:
        return raw_bytes

    # Derive 32 bytes using HKDF
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=HKDF_SALT,
        info=HKDF_INFO,
    )
    return hkdf.derive(raw_bytes)


class DetailsEncryptor:
    """Authenticated symmetric encryptor for expected identity details using AES-256-GCM."""

    def __init__(self, key: Optional[Union[str, bytes]] = None) -> None:
        """Initialize encryptor with an explicit or derived encryption key.

        If no key is provided, checks environment variable FAYDA_DETAILS_ENCRYPTION_KEY,
        FAYDA_ENCRYPTION_KEY, or generates a secure random 256-bit ephemeral key.
        """
        if key is not None:
            self._key = derive_encryption_key(key)
        else:
            env_key = os.environ.get("FAYDA_DETAILS_ENCRYPTION_KEY") or os.environ.get("FAYDA_ENCRYPTION_KEY")
            if env_key:
                self._key = derive_encryption_key(env_key)
            else:
                self._key = AESGCM.generate_key(bit_length=256)

        self._aesgcm = AESGCM(self._key)

    @property
    def key_bytes(self) -> bytes:
        """Return the underlying 32-byte key."""
        return self._key

    def encrypt_details(self, details: Union[ExpectedDetails, Dict[str, Any]]) -> str:
        """Encrypt expected identity details into an authenticated ciphertext string.

        Args:
            details: ExpectedDetails model instance or dictionary.

        Returns:
            URL-safe base64 string prefixed with 'enc:v1:'.
        """
        if isinstance(details, ExpectedDetails):
            payload_dict = details.model_dump()
        elif isinstance(details, dict):
            payload_dict = details
        else:
            raise DetailsMatchingError(
                "Invalid details payload for encryption",
                DetailsMatchingErrorCode.INVALID_EXPECTATIONS,
            )

        plaintext = json.dumps(payload_dict, sort_keys=True).encode("utf-8")
        nonce = os.urandom(12)  # 96-bit nonce for AES-GCM
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, associated_data=None)

        combined = nonce + ciphertext
        encoded = base64.urlsafe_b64encode(combined).decode("ascii")
        return f"{ENCRYPTION_PREFIX}{encoded}"

    def decrypt_details(self, encrypted_str: str) -> ExpectedDetails:
        """Decrypt ciphertext string back to an ExpectedDetails instance.

        Args:
            encrypted_str: String output from encrypt_details.

        Returns:
            Validated ExpectedDetails instance.

        Raises:
            DetailsMatchingError: If ciphertext is corrupt, tampered, or malformed.
        """
        if not encrypted_str or not isinstance(encrypted_str, str):
            raise DetailsMatchingError(
                "Encrypted details string must be non-empty",
                DetailsMatchingErrorCode.INVALID_EXPECTATIONS,
            )

        raw_str = encrypted_str.strip()
        if raw_str.startswith(ENCRYPTION_PREFIX):
            token = raw_str[len(ENCRYPTION_PREFIX):]
        else:
            token = raw_str

        try:
            combined = base64.urlsafe_b64decode(token.encode("ascii"))
            if len(combined) < 12 + 16:  # 12-byte nonce + 16-byte GCM auth tag minimum
                raise ValueError("Ciphertext too short")

            nonce = combined[:12]
            ciphertext = combined[12:]
            plaintext = self._aesgcm.decrypt(nonce, ciphertext, associated_data=None)
            payload_dict = json.loads(plaintext.decode("utf-8"))
            return ExpectedDetails(**payload_dict)
        except Exception as e:
            raise DetailsMatchingError(
                f"Failed to decrypt expected details: {str(e)}",
                DetailsMatchingErrorCode.INVALID_EXPECTATIONS,
            ) from e
