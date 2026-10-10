"""Unit tests for Task 19: QR configuration settings.

Validates:
1. QR enable setting: defaults verification to disabled (False).
2. Fail-closed rejection: disabled verification raises QRVerificationDisabledError / ConfigurationError.
3. Enabling via FaydaConfig parameter and environment variables (FAYDA_QR_VERIFICATION_ENABLED / QR_ENABLED).
4. Profile settings: qr_profile ('v4') and qr_allowed_profiles (['v4']), rejecting unpermitted profiles.
5. Key-bundle settings: qr_key_bundle_path, qr_public_key_pem, and config.load_qr_trust_store().
6. Size settings: qr_max_text_size_bytes (default 16384), enforcing maximum scanner text limits.
7. Calendar settings: qr_dob_calendar and qr_confirmed_calendars, controlling confirmed calendar predicates.
"""

import os
import pytest
from cryptography.hazmat.primitives import serialization

from fayda_mcp.config import FaydaConfig
from fayda_mcp.context import CallerContext
from fayda_mcp.exceptions import ConfigurationError, QRVerificationDisabledError
from fayda_mcp.qr.schemas import QRErrorCode, QRVerificationRequest
from fayda_mcp.qr.service import FaydaQRVerificationService
from fayda_mcp.qr.trust import QRTrustStore, TrustedKey, calculate_key_thumbprint
from fayda_mcp.service import FaydaVerificationService
from fayda_mcp.storage.memory import MemoryResultRepository, MemorySessionStore


def _load_fixtures():
    fixtures_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "fixtures")
    with open(os.path.join(fixtures_dir, "test_qr_rsa_public.pem"), "rb") as f:
        pub_pem = f.read().decode("utf-8")
        pub_key = serialization.load_pem_public_key(pub_pem.encode("utf-8"))
    with open(os.path.join(fixtures_dir, "synthetic_authorized_qr_v4.txt"), "r", encoding="utf-8") as f:
        valid_qr = f.read().strip()
    return pub_pem, pub_key, valid_qr


def _build_test_trust_store(pub_key) -> QRTrustStore:
    thumbprint = calculate_key_thumbprint(pub_key)
    store = QRTrustStore()
    store.add_key(
        TrustedKey(
            public_key=pub_key,
            thumbprint=thumbprint,
            key_id="test-key-2024",
            source="test_fixtures",
        )
    )
    return store


# ---------------------------------------------------------------------------
# 1. QR Enable Setting & Default Disabled
# ---------------------------------------------------------------------------


def test_qr_verification_default_disabled():
    """Verify that FaydaConfig defaults QR verification to disabled for fail-closed security."""
    cfg = FaydaConfig(
        client_id="cid",
        redirect_uri="https://localhost/callback",
        issuer="https://esignet.fayda.et",
        authorization_endpoint="https://esignet.fayda.et/authorize",
        token_endpoint="https://esignet.fayda.et/token",
        userinfo_endpoint="https://esignet.fayda.et/userinfo",
        jwks_uri="https://esignet.fayda.et/jwks",
    )
    assert cfg.qr_verification_enabled is False


def test_qr_verification_from_env_default_disabled(monkeypatch):
    """Verify that from_env() defaults qr_verification_enabled to False when no env var is set."""
    monkeypatch.delenv("FAYDA_QR_VERIFICATION_ENABLED", raising=False)
    monkeypatch.delenv("FAYDA_QR_ENABLED", raising=False)
    monkeypatch.delenv("QR_VERIFICATION_ENABLED", raising=False)
    monkeypatch.delenv("QR_ENABLED", raising=False)

    monkeypatch.setenv("FAYDA_CLIENT_ID", "test_id")
    monkeypatch.setenv("FAYDA_REDIRECT_URI", "https://localhost/cb")
    monkeypatch.setenv("FAYDA_ISSUER", "https://issuer.com")
    monkeypatch.setenv("FAYDA_AUTHORIZATION_ENDPOINT", "https://issuer.com/auth")
    monkeypatch.setenv("FAYDA_TOKEN_ENDPOINT", "https://issuer.com/token")
    monkeypatch.setenv("FAYDA_USERINFO_ENDPOINT", "https://issuer.com/userinfo")
    monkeypatch.setenv("FAYDA_JWKS_URI", "https://issuer.com/jwks")

    cfg = FaydaConfig.from_env()
    assert cfg.qr_verification_enabled is False


@pytest.mark.parametrize("env_var,val,expected", [
    ("FAYDA_QR_VERIFICATION_ENABLED", "true", True),
    ("FAYDA_QR_VERIFICATION_ENABLED", "1", True),
    ("FAYDA_QR_VERIFICATION_ENABLED", "yes", True),
    ("FAYDA_QR_ENABLED", "enabled", True),
    ("QR_VERIFICATION_ENABLED", "True", True),
    ("QR_ENABLED", "1", True),
    ("FAYDA_QR_VERIFICATION_ENABLED", "false", False),
    ("FAYDA_QR_VERIFICATION_ENABLED", "0", False),
    ("FAYDA_QR_VERIFICATION_ENABLED", "no", False),
])
def test_qr_verification_enable_from_env_values(monkeypatch, env_var, val, expected):
    """Verify boolean truthy and falsy parsing for QR verification enable env vars."""
    monkeypatch.delenv("FAYDA_QR_VERIFICATION_ENABLED", raising=False)
    monkeypatch.delenv("FAYDA_QR_ENABLED", raising=False)
    monkeypatch.delenv("QR_VERIFICATION_ENABLED", raising=False)
    monkeypatch.delenv("QR_ENABLED", raising=False)

    monkeypatch.setenv(env_var, val)
    monkeypatch.setenv("FAYDA_CLIENT_ID", "test_id")
    monkeypatch.setenv("FAYDA_REDIRECT_URI", "https://localhost/cb")
    monkeypatch.setenv("FAYDA_ISSUER", "https://issuer.com")
    monkeypatch.setenv("FAYDA_AUTHORIZATION_ENDPOINT", "https://issuer.com/auth")
    monkeypatch.setenv("FAYDA_TOKEN_ENDPOINT", "https://issuer.com/token")
    monkeypatch.setenv("FAYDA_USERINFO_ENDPOINT", "https://issuer.com/userinfo")
    monkeypatch.setenv("FAYDA_JWKS_URI", "https://issuer.com/jwks")

    cfg = FaydaConfig.from_env()
    assert cfg.qr_verification_enabled is expected


@pytest.mark.asyncio
async def test_disabled_verification_blocks_submit_and_verify_sync():
    """Attempting verification when disabled raises QRVerificationDisabledError (subclass of ConfigurationError)."""
    _, pub_key, valid_qr = _load_fixtures()
    store = _build_test_trust_store(pub_key)

    cfg = FaydaConfig(
        client_id="cid",
        redirect_uri="https://localhost/callback",
        issuer="https://esignet.fayda.et",
        authorization_endpoint="https://esignet.fayda.et/authorize",
        token_endpoint="https://esignet.fayda.et/token",
        userinfo_endpoint="https://esignet.fayda.et/userinfo",
        jwks_uri="https://esignet.fayda.et/jwks",
        qr_verification_enabled=False,
    )
    svc = FaydaQRVerificationService(config=cfg, trust_store=store)

    # 1. verify_qr_sync raises
    req = QRVerificationRequest(qr_text=valid_qr)
    with pytest.raises(QRVerificationDisabledError) as exc_info:
        svc.verify_qr_sync(req)
    assert isinstance(exc_info.value, ConfigurationError)
    assert exc_info.value.code == "qr_verification_disabled"

    # 2. submit_qr_verification raises
    with pytest.raises(QRVerificationDisabledError):
        await svc.submit_qr_verification(qr_text=valid_qr)

    # 3. Top-level FaydaVerificationService raises when disabled
    top_svc = FaydaVerificationService(
        config=cfg,
        sessions=MemorySessionStore(),
        results=MemoryResultRepository(),
    )
    top_svc.qr_service.trust_store = store
    with pytest.raises(QRVerificationDisabledError):
        await top_svc.submit_qr_verification(qr_text=valid_qr)


# ---------------------------------------------------------------------------
# 2. QR Profile Settings
# ---------------------------------------------------------------------------


def test_qr_profile_settings_defaults_and_env(monkeypatch):
    """Verify default profile ('v4') and parsing from env vars."""
    cfg = FaydaConfig(
        client_id="cid",
        redirect_uri="https://localhost/callback",
        issuer="https://esignet.fayda.et",
        authorization_endpoint="https://esignet.fayda.et/authorize",
        token_endpoint="https://esignet.fayda.et/token",
        userinfo_endpoint="https://esignet.fayda.et/userinfo",
        jwks_uri="https://esignet.fayda.et/jwks",
    )
    assert cfg.qr_profile == "v4"
    assert cfg.qr_allowed_profiles == ["v4"]

    monkeypatch.setenv("FAYDA_QR_PROFILE", "v4")
    monkeypatch.setenv("FAYDA_QR_ALLOWED_PROFILES", "v4, v5, v6")
    monkeypatch.setenv("FAYDA_CLIENT_ID", "test_id")
    monkeypatch.setenv("FAYDA_REDIRECT_URI", "https://localhost/cb")
    monkeypatch.setenv("FAYDA_ISSUER", "https://issuer.com")
    monkeypatch.setenv("FAYDA_AUTHORIZATION_ENDPOINT", "https://issuer.com/auth")
    monkeypatch.setenv("FAYDA_TOKEN_ENDPOINT", "https://issuer.com/token")
    monkeypatch.setenv("FAYDA_USERINFO_ENDPOINT", "https://issuer.com/userinfo")
    monkeypatch.setenv("FAYDA_JWKS_URI", "https://issuer.com/jwks")

    env_cfg = FaydaConfig.from_env()
    assert env_cfg.qr_profile == "v4"
    assert env_cfg.qr_allowed_profiles == ["v4", "v5", "v6"]


@pytest.mark.asyncio
async def test_qr_profile_rejection_when_unpermitted():
    """When a QR code profile is not in qr_allowed_profiles, the verification fails closed."""
    _, pub_key, valid_qr = _load_fixtures()
    store = _build_test_trust_store(pub_key)

    # Allow only 'v5' (whereas valid_qr has version 4)
    cfg = FaydaConfig(
        client_id="cid",
        redirect_uri="https://localhost/callback",
        issuer="https://esignet.fayda.et",
        authorization_endpoint="https://esignet.fayda.et/authorize",
        token_endpoint="https://esignet.fayda.et/token",
        userinfo_endpoint="https://esignet.fayda.et/userinfo",
        jwks_uri="https://esignet.fayda.et/jwks",
        qr_verification_enabled=True,
        qr_allowed_profiles=["v5"],
    )
    svc = FaydaQRVerificationService(config=cfg, trust_store=store)

    res = await svc.submit_qr_verification(qr_text=valid_qr)
    assert res.status == "rejected"
    assert res.credential_signature_valid is False
    assert res.error_code == QRErrorCode.UNSUPPORTED_VERSION.value


# ---------------------------------------------------------------------------
# 3. Key-Bundle Settings
# ---------------------------------------------------------------------------


def test_qr_key_bundle_settings_and_trust_loader(monkeypatch):
    """Verify key-bundle path and inline PEM configuration and load_qr_trust_store helper."""
    pub_pem, pub_key, _ = _load_fixtures()

    cfg = FaydaConfig(
        client_id="cid",
        redirect_uri="https://localhost/callback",
        issuer="https://esignet.fayda.et",
        authorization_endpoint="https://esignet.fayda.et/authorize",
        token_endpoint="https://esignet.fayda.et/token",
        userinfo_endpoint="https://esignet.fayda.et/userinfo",
        jwks_uri="https://esignet.fayda.et/jwks",
        qr_public_key_pem=pub_pem,
    )
    store = cfg.load_qr_trust_store()
    assert not store.is_empty()
    assert len(store.get_all_keys()) == 1

    # Env loading
    monkeypatch.setenv("FAYDA_QR_PUBLIC_KEY_PEM", pub_pem)
    monkeypatch.setenv("FAYDA_QR_KEY_BUNDLE_PATH", "/var/certs/fayda_qr_bundle.pem")
    monkeypatch.setenv("FAYDA_CLIENT_ID", "test_id")
    monkeypatch.setenv("FAYDA_REDIRECT_URI", "https://localhost/cb")
    monkeypatch.setenv("FAYDA_ISSUER", "https://issuer.com")
    monkeypatch.setenv("FAYDA_AUTHORIZATION_ENDPOINT", "https://issuer.com/auth")
    monkeypatch.setenv("FAYDA_TOKEN_ENDPOINT", "https://issuer.com/token")
    monkeypatch.setenv("FAYDA_USERINFO_ENDPOINT", "https://issuer.com/userinfo")
    monkeypatch.setenv("FAYDA_JWKS_URI", "https://issuer.com/jwks")

    env_cfg = FaydaConfig.from_env()
    assert env_cfg.qr_public_key_pem == pub_pem
    assert env_cfg.qr_key_bundle_path == "/var/certs/fayda_qr_bundle.pem"


# ---------------------------------------------------------------------------
# 4. QR Scanner Size Settings
# ---------------------------------------------------------------------------


def test_qr_size_setting_defaults_and_env(monkeypatch):
    """Verify default max size (16384 bytes) and parsing from environment variables."""
    cfg = FaydaConfig(
        client_id="cid",
        redirect_uri="https://localhost/callback",
        issuer="https://esignet.fayda.et",
        authorization_endpoint="https://esignet.fayda.et/authorize",
        token_endpoint="https://esignet.fayda.et/token",
        userinfo_endpoint="https://esignet.fayda.et/userinfo",
        jwks_uri="https://esignet.fayda.et/jwks",
    )
    assert cfg.qr_max_text_size_bytes == 16384

    monkeypatch.setenv("FAYDA_QR_MAX_TEXT_SIZE_BYTES", "8192")
    monkeypatch.setenv("FAYDA_CLIENT_ID", "test_id")
    monkeypatch.setenv("FAYDA_REDIRECT_URI", "https://localhost/cb")
    monkeypatch.setenv("FAYDA_ISSUER", "https://issuer.com")
    monkeypatch.setenv("FAYDA_AUTHORIZATION_ENDPOINT", "https://issuer.com/auth")
    monkeypatch.setenv("FAYDA_TOKEN_ENDPOINT", "https://issuer.com/token")
    monkeypatch.setenv("FAYDA_USERINFO_ENDPOINT", "https://issuer.com/userinfo")
    monkeypatch.setenv("FAYDA_JWKS_URI", "https://issuer.com/jwks")

    env_cfg = FaydaConfig.from_env()
    assert env_cfg.qr_max_text_size_bytes == 8192


@pytest.mark.asyncio
async def test_qr_size_limit_rejection():
    """Verify that scanner text exceeding configured qr_max_text_size_bytes is safely rejected."""
    _, pub_key, valid_qr = _load_fixtures()
    store = _build_test_trust_store(pub_key)

    # Set artificially small max size (e.g. 50 bytes)
    cfg = FaydaConfig(
        client_id="cid",
        redirect_uri="https://localhost/callback",
        issuer="https://esignet.fayda.et",
        authorization_endpoint="https://esignet.fayda.et/authorize",
        token_endpoint="https://esignet.fayda.et/token",
        userinfo_endpoint="https://esignet.fayda.et/userinfo",
        jwks_uri="https://esignet.fayda.et/jwks",
        qr_verification_enabled=True,
        qr_max_text_size_bytes=50,
    )
    svc = FaydaQRVerificationService(config=cfg, trust_store=store)

    res = await svc.submit_qr_verification(qr_text=valid_qr)
    assert res.status == "malformed_input"
    assert res.credential_signature_valid is False
    assert res.error_code == QRErrorCode.PAYLOAD_SIZE_EXCEEDED.value
    assert "exceeds maximum configured limit" in str(res.error)


# ---------------------------------------------------------------------------
# 5. Calendar Settings
# ---------------------------------------------------------------------------


def test_qr_calendar_settings_defaults_and_env(monkeypatch):
    """Verify calendar settings defaults ('gregorian', ['gregorian', 'ethiopic']) and env parsing."""
    cfg = FaydaConfig(
        client_id="cid",
        redirect_uri="https://localhost/callback",
        issuer="https://esignet.fayda.et",
        authorization_endpoint="https://esignet.fayda.et/authorize",
        token_endpoint="https://esignet.fayda.et/token",
        userinfo_endpoint="https://esignet.fayda.et/userinfo",
        jwks_uri="https://esignet.fayda.et/jwks",
    )
    assert cfg.qr_dob_calendar == "gregorian"
    assert cfg.qr_confirmed_calendars == ["gregorian", "ethiopic"]

    monkeypatch.setenv("FAYDA_QR_DOB_CALENDAR", "ethiopic")
    monkeypatch.setenv("FAYDA_QR_CONFIRMED_CALENDARS", "ethiopic, ec")
    monkeypatch.setenv("FAYDA_CLIENT_ID", "test_id")
    monkeypatch.setenv("FAYDA_REDIRECT_URI", "https://localhost/cb")
    monkeypatch.setenv("FAYDA_ISSUER", "https://issuer.com")
    monkeypatch.setenv("FAYDA_AUTHORIZATION_ENDPOINT", "https://issuer.com/auth")
    monkeypatch.setenv("FAYDA_TOKEN_ENDPOINT", "https://issuer.com/token")
    monkeypatch.setenv("FAYDA_USERINFO_ENDPOINT", "https://issuer.com/userinfo")
    monkeypatch.setenv("FAYDA_JWKS_URI", "https://issuer.com/jwks")

    env_cfg = FaydaConfig.from_env()
    assert env_cfg.qr_dob_calendar == "ethiopic"
    assert env_cfg.qr_confirmed_calendars == ["ethiopic", "ec"]


@pytest.mark.asyncio
async def test_qr_calendar_setting_restricts_age_evaluation():
    """When a calendar is not in qr_confirmed_calendars, age checks become 'unavailable'."""
    _, pub_key, valid_qr = _load_fixtures()
    store = _build_test_trust_store(pub_key)

    # Restrict confirmed calendars strictly to 'ethiopic'
    cfg = FaydaConfig(
        client_id="cid",
        redirect_uri="https://localhost/callback",
        issuer="https://esignet.fayda.et",
        authorization_endpoint="https://esignet.fayda.et/authorize",
        token_endpoint="https://esignet.fayda.et/token",
        userinfo_endpoint="https://esignet.fayda.et/userinfo",
        jwks_uri="https://esignet.fayda.et/jwks",
        qr_verification_enabled=True,
        qr_dob_calendar="gregorian",
        qr_confirmed_calendars=["ethiopic"],  # Gregorian is NOT confirmed here
    )
    svc = FaydaQRVerificationService(config=cfg, trust_store=store)

    res = await svc.submit_qr_verification(
        qr_text=valid_qr,
        dob_calendar="gregorian",
        checks=["credential_signature_valid", "age_over_18"],
    )
    assert res.checks["age_over_18"] == "unavailable"
    assert res.reasons["age_over_18"] == "unconfirmed_calendar"
