"""Unit tests for Fayda developer portal .env loader, OIDC discovery, and key decoding."""

import base64
import json
import os
from typing import Any, Dict
from unittest.mock import patch
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.utils import base64url_encode

from fayda_mcp.config import FaydaConfig, parse_expiration_time
from fayda_mcp.exceptions import ConfigurationError, TokenValidationError
from fayda_mcp.oidc.discovery import discover_oidc_configuration
from fayda_mcp.oidc.tokens import validate_id_token
from fayda_mcp.secrets.keys import parse_private_key


@pytest.fixture(scope="module")
def synthetic_rsa_jwk() -> Dict[str, Any]:
    """Generate a synthetic RSA key and JWK for reproducible tests."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_nums = private_key.private_numbers()
    pub_nums = priv_nums.public_numbers

    def int_to_b64u(val: int) -> str:
        byte_len = (val.bit_length() + 7) // 8
        return base64url_encode(val.to_bytes(byte_len, "big")).decode("utf-8")

    return {
        "kty": "RSA",
        "kid": "test-synthetic-portal-kid-999",
        "n": int_to_b64u(pub_nums.n),
        "e": int_to_b64u(pub_nums.e),
        "d": int_to_b64u(priv_nums.d),
        "p": int_to_b64u(priv_nums.p),
        "q": int_to_b64u(priv_nums.q),
    }


@pytest.fixture(scope="module")
def synthetic_base64_jwk(synthetic_rsa_jwk: Dict[str, Any]) -> str:
    """Base64 encoded RSA JWK string matching Fayda portal export."""
    raw_json = json.dumps(synthetic_rsa_jwk).encode("utf-8")
    return base64.b64encode(raw_json).decode("utf-8")


@pytest.fixture(autouse=True)
def clean_fayda_env(monkeypatch: pytest.MonkeyPatch):
    """Ensure clean isolated environment without lingering variables."""
    for k in list(os.environ.keys()):
        if k.startswith("FAYDA_") or k in (
            "CLIENT_ID", "REDIRECT_URI", "AUTHORIZATION_ENDPOINT", "AUTHORIZATION_URL",
            "TOKEN_ENDPOINT", "TOKEN_URL", "USERINFO_ENDPOINT", "USERINFO_URL",
            "PRIVATE_KEY", "SIGNING_KEY", "SIGNING_KEY_PATH", "KEY_ID",
            "EXPIRATION_TIME", "EXPIRATION_UNIT", "EXPIRATION_TIME_UNIT",
            "ALGORITHM", "CLIENT_ASSERTION_TYPE", "ISSUER", "ISSUER_URL",
            "JWKS_URI", "JWKS_URL",
        ):
            monkeypatch.delenv(k, raising=False)


class TestPortalEnvMapping:
    """Requirement 1 & 3: Map Fayda portal .env variables directly."""

    def test_direct_portal_env_mapping(self, synthetic_base64_jwk: str, monkeypatch: pytest.MonkeyPatch):
        """Map standard unprefixed portal variables directly to FaydaConfig."""
        # Clear existing environment to ensure clean isolation
        for k in list(os.environ.keys()):
            if k.startswith("FAYDA_") or k in (
                "CLIENT_ID", "REDIRECT_URI", "AUTHORIZATION_ENDPOINT",
                "TOKEN_ENDPOINT", "USERINFO_ENDPOINT", "PRIVATE_KEY",
                "EXPIRATION_TIME", "ALGORITHM", "CLIENT_ASSERTION_TYPE"
            ):
                monkeypatch.delenv(k, raising=False)

        monkeypatch.setenv("CLIENT_ID", "portal-app-client-123")
        monkeypatch.setenv("REDIRECT_URI", "http://localhost:3000/callback")
        monkeypatch.setenv("AUTHORIZATION_ENDPOINT", "https://esignet.ida.fayda.et/authorize")
        monkeypatch.setenv("TOKEN_ENDPOINT", "https://esignet.ida.fayda.et/v1/esignet/oauth/v2/token")
        monkeypatch.setenv("USERINFO_ENDPOINT", "https://esignet.ida.fayda.et/v1/esignet/oidc/userinfo")
        monkeypatch.setenv("PRIVATE_KEY", synthetic_base64_jwk)
        monkeypatch.setenv("EXPIRATION_TIME", "15")
        monkeypatch.setenv("ALGORITHM", "RS256")
        monkeypatch.setenv("CLIENT_ASSERTION_TYPE", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")

        # Mock discovery so network call is avoided in unit test
        with patch("fayda_mcp.oidc.discovery.discover_oidc_configuration") as mock_disc:
            mock_disc.return_value = {
                "issuer": "https://esignet.ida.fayda.et",
                "jwks_uri": "https://esignet.ida.fayda.et/.well-known/jwks.json",
            }
            config = FaydaConfig.from_env()

        assert config.client_id == "portal-app-client-123"
        assert config.redirect_uri == "http://localhost:3000/callback"
        assert config.authorization_endpoint == "https://esignet.ida.fayda.et/authorize"
        assert config.token_endpoint == "https://esignet.ida.fayda.et/v1/esignet/oauth/v2/token"
        assert config.userinfo_endpoint == "https://esignet.ida.fayda.et/v1/esignet/oidc/userinfo"
        assert config.issuer == "https://esignet.ida.fayda.et"
        assert config.jwks_uri == "https://esignet.ida.fayda.et/.well-known/jwks.json"

        # Requirement 3: Expiration unit confirmation (15 minutes -> 900s)
        assert config.client_assertion_ttl_seconds == 900
        assert config.algorithm == "RS256"
        assert config.client_assertion_type == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

        # Requirement 2: Key ID derived from decoded JWK
        assert config.key_id == "test-synthetic-portal-kid-999"
        assert config.signing_key is not None
        assert "BEGIN PRIVATE KEY" in config.signing_key

    def test_fayda_prefix_takes_priority(self, synthetic_base64_jwk: str, monkeypatch: pytest.MonkeyPatch):
        """Requirement 1: Give FAYDA_ variables priority over portal variables."""
        monkeypatch.setenv("CLIENT_ID", "portal-low-priority")
        monkeypatch.setenv("FAYDA_CLIENT_ID", "prefixed-high-priority")

        monkeypatch.setenv("REDIRECT_URI", "http://localhost:3000/portal")
        monkeypatch.setenv("FAYDA_REDIRECT_URI", "http://localhost:3000/prefixed")

        monkeypatch.setenv("AUTHORIZATION_ENDPOINT", "https://portal.endpoint/auth")
        monkeypatch.setenv("FAYDA_AUTHORIZATION_ENDPOINT", "https://prefixed.endpoint/auth")

        monkeypatch.setenv("TOKEN_ENDPOINT", "https://portal.endpoint/token")
        monkeypatch.setenv("FAYDA_TOKEN_ENDPOINT", "https://prefixed.endpoint/token")

        monkeypatch.setenv("USERINFO_ENDPOINT", "https://portal.endpoint/userinfo")
        monkeypatch.setenv("FAYDA_USERINFO_ENDPOINT", "https://prefixed.endpoint/userinfo")

        monkeypatch.setenv("FAYDA_ISSUER", "https://prefixed.endpoint/issuer")
        monkeypatch.setenv("FAYDA_JWKS_URL", "https://prefixed.endpoint/jwks")
        monkeypatch.setenv("PRIVATE_KEY", synthetic_base64_jwk)

        config = FaydaConfig.from_env()

        assert config.client_id == "prefixed-high-priority"
        assert config.redirect_uri == "http://localhost:3000/prefixed"
        assert config.authorization_endpoint == "https://prefixed.endpoint/auth"
        assert config.token_endpoint == "https://prefixed.endpoint/token"
        assert config.userinfo_endpoint == "https://prefixed.endpoint/userinfo"
        assert config.issuer == "https://prefixed.endpoint/issuer"
        assert config.jwks_uri == "https://prefixed.endpoint/jwks"


class TestPrivateKeyDecoding:
    """Requirement 2: Decode PRIVATE_KEY from base64 RSA JWK and support files."""

    def test_decode_base64_rsa_jwk(self, synthetic_base64_jwk: str):
        """Decode base64 RSA JWK into PKCS8 PEM and extract kid."""
        pem, kid = parse_private_key(synthetic_base64_jwk)
        assert kid == "test-synthetic-portal-kid-999"
        assert "BEGIN PRIVATE KEY" in pem

    def test_decode_raw_json_jwk(self, synthetic_rsa_jwk: Dict[str, Any]):
        """Support raw JSON string or dictionary representation."""
        raw_json_str = json.dumps(synthetic_rsa_jwk)
        pem, kid = parse_private_key(raw_json_str)
        assert kid == "test-synthetic-portal-kid-999"
        assert "BEGIN PRIVATE KEY" in pem

    def test_signing_key_file_support(self, tmp_path, synthetic_base64_jwk: str, monkeypatch: pytest.MonkeyPatch):
        """Support loading signing key from file path."""
        key_file = tmp_path / "portal_key.txt"
        key_file.write_text(synthetic_base64_jwk, encoding="utf-8")

        monkeypatch.delenv("PRIVATE_KEY", raising=False)
        monkeypatch.delenv("FAYDA_PRIVATE_KEY", raising=False)
        monkeypatch.delenv("KEY_ID", raising=False)
        monkeypatch.delenv("FAYDA_KEY_ID", raising=False)
        monkeypatch.setenv("CLIENT_ID", "cid")
        monkeypatch.setenv("REDIRECT_URI", "http://localhost:3000/callback")
        monkeypatch.setenv("AUTHORIZATION_ENDPOINT", "https://auth.example/auth")
        monkeypatch.setenv("TOKEN_ENDPOINT", "https://auth.example/token")
        monkeypatch.setenv("USERINFO_ENDPOINT", "https://auth.example/userinfo")
        monkeypatch.setenv("SIGNING_KEY_PATH", str(key_file))

        config = FaydaConfig.from_env()
        assert config.signing_key_path == str(key_file)
        assert config.signing_key is not None
        assert "BEGIN PRIVATE KEY" in config.signing_key
        assert config.key_id == "test-synthetic-portal-kid-999"

    def test_private_key_never_logged_or_exposed(self, synthetic_base64_jwk: str):
        """Requirement 5: Never log or expose private key material."""
        config = FaydaConfig(
            client_id="cid",
            redirect_uri="http://localhost/cb",
            issuer="https://issuer",
            authorization_endpoint="https://auth",
            token_endpoint="https://token",
            userinfo_endpoint="https://userinfo",
            jwks_uri="https://jwks",
            signing_key="sensitive-test-signing-key",
        )

        # repr(config) must not expose signing key
        repr_str = repr(config)
        assert "sensitive-test-signing-key" not in repr_str

        # to_redacted_dict() must redact signing key
        redacted = config.to_redacted_dict()
        assert redacted["signing_key"] == "[REDACTED]"

        # ConfigurationError on invalid key must not reflect raw payload
        with pytest.raises(ConfigurationError) as exc_info:
            parse_private_key("invalid-raw-key-input")
        assert "invalid-raw-key-input" not in str(exc_info.value)


class TestExpirationTimeUnits:
    """Requirement 3: Confirm expiry unit before mapping."""

    @pytest.mark.parametrize(
        "raw_val,unit_hint,expected_seconds",
        [
            ("15", None, 900),           # Portal default: 15 <= 60 confirmed as 15 minutes = 900s
            ("15m", None, 900),          # Explicit minute suffix
            ("15min", None, 900),        # Explicit min suffix
            ("900s", None, 900),         # Explicit second suffix
            ("900", None, 900),          # > 60 treated as seconds
            ("1h", None, 3600),          # Hour suffix
            ("30", "seconds", 30),       # Explicit unit hint seconds overrides portal default
            ("2", "minutes", 120),       # Explicit unit hint minutes
            (None, None, 120),           # Default fallback
            ("", None, 120),             # Empty string fallback
        ],
    )
    def test_parse_expiration_time(self, raw_val, unit_hint, expected_seconds):
        assert parse_expiration_time(raw_val, unit_hint=unit_hint) == expected_seconds


class TestOidcDiscoveryAndOverrides:
    """Requirement 4: Resolve issuer and JWKS URL via trusted OIDC discovery with overrides."""

    def test_oidc_discovery_resolution(self, monkeypatch: pytest.MonkeyPatch):
        """Resolve issuer and jwks_uri via mocked OIDC discovery."""
        monkeypatch.setenv("CLIENT_ID", "cid")
        monkeypatch.setenv("REDIRECT_URI", "http://localhost:3000/cb")
        monkeypatch.setenv("AUTHORIZATION_ENDPOINT", "https://esignet.ida.fayda.et/authorize")
        monkeypatch.setenv("TOKEN_ENDPOINT", "https://esignet.ida.fayda.et/v1/esignet/oauth/v2/token")
        monkeypatch.setenv("USERINFO_ENDPOINT", "https://esignet.ida.fayda.et/v1/esignet/oidc/userinfo")

        with patch("fayda_mcp.oidc.discovery.discover_oidc_configuration") as mock_disc:
            mock_disc.return_value = {
                "issuer": "https://esignet.ida.fayda.et",
                "jwks_uri": "https://esignet.ida.fayda.et/.well-known/jwks.json",
                "authorization_endpoint": "https://esignet.ida.fayda.et/authorize",
            }
            config = FaydaConfig.from_env()

        assert config.issuer == "https://esignet.ida.fayda.et"
        assert config.jwks_uri == "https://esignet.ida.fayda.et/.well-known/jwks.json"

    def test_explicit_overrides_take_precedence(self, monkeypatch: pytest.MonkeyPatch):
        """Explicit overrides take precedence over discovered endpoints."""
        monkeypatch.setenv("CLIENT_ID", "cid")
        monkeypatch.setenv("REDIRECT_URI", "http://localhost:3000/cb")
        monkeypatch.setenv("AUTHORIZATION_ENDPOINT", "https://esignet.ida.fayda.et/authorize")
        monkeypatch.setenv("TOKEN_ENDPOINT", "https://esignet.ida.fayda.et/v1/esignet/oauth/v2/token")
        monkeypatch.setenv("USERINFO_ENDPOINT", "https://esignet.ida.fayda.et/v1/esignet/oidc/userinfo")
        # Explicit overrides
        monkeypatch.setenv("FAYDA_ISSUER", "https://custom-mock.local/issuer")
        monkeypatch.setenv("FAYDA_JWKS_URL", "https://custom-mock.local/jwks")

        config = FaydaConfig.from_env()
        assert config.issuer == "https://custom-mock.local/issuer"
        assert config.jwks_uri == "https://custom-mock.local/jwks"

    def test_token_validation_never_skipped(self):
        """Never skip cryptographic token validation."""
        config = FaydaConfig(
            client_id="cid",
            redirect_uri="http://localhost/cb",
            issuer="https://issuer",
            authorization_endpoint="https://auth",
            token_endpoint="https://token",
            userinfo_endpoint="https://userinfo",
            jwks_uri="https://jwks",
        )

        # 1. Reject unsigned tokens (alg=none)
        unsigned_token = (
            base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode("utf-8").rstrip("=")
            + "."
            + base64.urlsafe_b64encode(b'{"sub":"123"}').decode("utf-8").rstrip("=")
            + "."
        )
        with pytest.raises(TokenValidationError, match="strictly prohibited"):
            validate_id_token(unsigned_token, config, "dummy_key")

        # 2. Reject empty token
        with pytest.raises(TokenValidationError, match="non-empty string"):
            validate_id_token("", config, "dummy_key")
