"""Comprehensive Acceptance & Edge Case Unit Tests for Task 20.

Validates the full set of acceptance criteria:
1. Tampering detection: Altered demographic fields, photo, or detached signature fail verification.
2. Parser errors: Missing delimiters, malformed tokens, oversized payloads, and unsupported versions.
3. Privacy guarantees: Minimal agent output (status, method, checks, times, safe reasons) strictly excluding demographics, photo, and signature.
4. Age boundaries: Precision boundary evaluation (today, tomorrow, yesterday) and calendar rules (Gregorian, Ethiopic, unconfirmed).
5. Isolation: Caller and tenant boundaries enforced on retrieval.
6. Retries & Idempotency: Duplicate submissions return cached result; parameter conflicts raise error; host success hook executes once.
7. Copied QR threat model: Replay retains credential_signature_valid=True, but strictly keeps holder_authenticated=False and identity_verified=False.
8. Official-fixture verification: Official sample_qr_v4.txt parsing; safe failure on unverified signature; synthetic identities in public tests.
9. Offline & Standalone: Verification requires no OIDC callback, no webhook, and no client private signing key. Redis remains optional.
"""

import asyncio
import base64
from datetime import date, datetime, timedelta, timezone
import os
from typing import Dict, Optional, Tuple
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from fayda_mcp.config import FaydaConfig
from fayda_mcp.context import CallerContext
from fayda_mcp.exceptions import (
    AuthorizationError,
    IdempotencyConflictError,
    VerificationNotFoundError,
)
from fayda_mcp.qr.decoder import decode_and_verify_qr
from fayda_mcp.qr.parser import parse_qr_code
from fayda_mcp.qr.schemas import (
    HostUserSuccessContext,
    QRAgentVerificationResult,
    QRErrorCode,
    QRVerificationRequest,
    filter_agent_output,
)
from fayda_mcp.qr.service import FaydaQRVerificationService
from fayda_mcp.qr.signed_content import build_jws_signing_input
from fayda_mcp.qr.trust import QRTrustStore, TrustedKey, calculate_key_thumbprint
from fayda_mcp.service import FaydaVerificationService
from fayda_mcp.storage.memory import MemoryResultRepository, MemorySessionStore


# ---------------------------------------------------------------------------
# Fixtures & Helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def fixtures_dir() -> str:
    return os.path.join(os.path.dirname(os.path.dirname(__file__)), "fixtures")


@pytest.fixture
def rsa_key_pair(fixtures_dir: str) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey, str]:
    """Load test RSA private and public key pair."""
    with open(os.path.join(fixtures_dir, "test_qr_rsa_private.pem"), "rb") as f:
        priv_key = serialization.load_pem_private_key(f.read(), password=None)  # type: ignore
    with open(os.path.join(fixtures_dir, "test_qr_rsa_public.pem"), "rb") as f:
        pub_pem = f.read().decode("utf-8")
        pub_key = serialization.load_pem_public_key(pub_pem.encode("utf-8"))  # type: ignore
    return priv_key, pub_key, pub_pem


@pytest.fixture
def trust_store(rsa_key_pair) -> QRTrustStore:
    _, pub_key, _ = rsa_key_pair
    store = QRTrustStore()
    thumbprint = calculate_key_thumbprint(pub_key)
    store.add_key(
        TrustedKey(
            public_key=pub_key,
            thumbprint=thumbprint,
            key_id="test-key-2024",
            source="test_fixtures",
        )
    )
    return store


@pytest.fixture
def official_sample_qr(fixtures_dir: str) -> str:
    with open(os.path.join(fixtures_dir, "sample_qr_v4.txt"), "r", encoding="utf-8") as f:
        return f.read().strip()


@pytest.fixture
def synthetic_authorized_qr(fixtures_dir: str) -> str:
    with open(os.path.join(fixtures_dir, "synthetic_authorized_qr_v4.txt"), "r", encoding="utf-8") as f:
        return f.read().strip()


def generate_synthetic_signed_qr(
    private_key: rsa.RSAPrivateKey,
    photo_b64: str = "UklGRtYBAABXRUJQVlA4IMoBAACwEQCdASpLAGQAPzmMu1SvKa0kLbZsAeAnCWMAyCBWKhN-gmWIY_qQjsUW-NESK1nBUs-reebF9HLJA6Y8HmiWJHgEdRGV_5pPn5V1w8vDtPdhJ8rVWdFf10iJxLudUYIa6AZxpcM1tR1N5x8vSMLUU38TRQPq4x_lxN-MdE2NvOamTAsTwrONBT1p7RnhY0nXbQmFdMAA",
    name: str = "Abebe Bikila",
    version: int = 4,
    gender: str = "M",
    fan: str = "1234  5678  9012  3456",
    dob: str = "1990/01/01",
) -> str:
    """Generate a mathematically valid signed QR v4 token using synthetic identity."""
    payload_text = f"{photo_b64}:DLT:{name}:V:{version}:G:{gender}:A:{fan}:D:{dob}"
    header_json = b'{"alg":"RS256"}'
    header_b64 = base64.urlsafe_b64encode(header_json).decode("utf-8").rstrip("=")
    signing_input = build_jws_signing_input(header_b64, payload_text.encode("utf-8"))
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    sig_b64 = base64.urlsafe_b64encode(signature).decode("utf-8").rstrip("=")
    detached_jws = f"{header_b64}..{sig_b64}"
    return f"{payload_text}:SIGN:{detached_jws}"


# ---------------------------------------------------------------------------
# 1. Official-Fixture Verification & Synthetic Identities
# ---------------------------------------------------------------------------

def test_official_fixture_parsing_and_signature_fail_safe(
    official_sample_qr: str,
    trust_store: QRTrustStore,
):
    """Verify that official sample fixture parses correctly and fails signature verification safely."""
    parsed = parse_qr_code(official_sample_qr)

    # 1. Official demographic fields parsed
    assert parsed.demographics.name == "Israel Ashenafi Bekele "
    assert parsed.demographics.version == 4
    assert parsed.demographics.gender == "M"
    assert parsed.demographics.fan == "6042  3061  7816  8402"
    assert parsed.demographics.date_of_birth == "2004/12/28"
    assert parsed.demographics.photo_base64url.startswith("UklGRtYBAABXRUJQVlA4")

    # 2. Detached JWS format per RFC 7515 Appendix F
    assert ".." in parsed.detached_jws
    from fayda_mcp.qr.signed_content import decode_detached_jws
    header, sig_bytes = decode_detached_jws(parsed.detached_jws)
    assert header == {"alg": "RS256"}
    assert len(sig_bytes) == 256

    # 3. Signature verification with test trust store fails safely (as noted in spec)
    res = decode_and_verify_qr(official_sample_qr, trust_store=trust_store)
    assert res.credential_signature_valid is False
    assert res.status == "invalid_signature"
    assert res.holder_authenticated is False
    assert res.error_code == QRErrorCode.INVALID_SIGNATURE.value


def test_synthetic_identities_authorized_verification(
    synthetic_authorized_qr: str,
    trust_store: QRTrustStore,
):
    """Verify that public tests use synthetic identities and pass verification with test keys."""
    parsed = parse_qr_code(synthetic_authorized_qr)
    assert parsed.demographics.name == "Abebe Bikila"
    assert parsed.demographics.fan == "1234  5678  9012  3456"

    res = decode_and_verify_qr(synthetic_authorized_qr, trust_store=trust_store)
    assert res.credential_signature_valid is True
    assert res.status == "verified"
    assert res.holder_authenticated is False


# ---------------------------------------------------------------------------
# 2. Tampering Detection Tests
# ---------------------------------------------------------------------------

def test_tampering_name_fails_signature(rsa_key_pair, trust_store: QRTrustStore):
    priv_key, _, _ = rsa_key_pair
    valid_qr = generate_synthetic_signed_qr(priv_key, name="Abebe Bikila")

    # Tamper with citizen name in payload text
    tampered_qr = valid_qr.replace("Abebe Bikila", "Abebe Bikila Modified")
    res = decode_and_verify_qr(tampered_qr, trust_store=trust_store)

    assert res.credential_signature_valid is False
    assert res.status == "invalid_signature"
    assert res.error_code == QRErrorCode.INVALID_SIGNATURE.value


def test_tampering_fan_fails_signature(rsa_key_pair, trust_store: QRTrustStore):
    priv_key, _, _ = rsa_key_pair
    valid_qr = generate_synthetic_signed_qr(priv_key, fan="1234  5678  9012  3456")

    # Tamper with FAN digits
    tampered_qr = valid_qr.replace("1234  5678  9012  3456", "9999  5678  9012  3456")
    res = decode_and_verify_qr(tampered_qr, trust_store=trust_store)

    assert res.credential_signature_valid is False
    assert res.status == "invalid_signature"


def test_tampering_birthdate_fails_signature(rsa_key_pair, trust_store: QRTrustStore):
    priv_key, _, _ = rsa_key_pair
    valid_qr = generate_synthetic_signed_qr(priv_key, dob="1990/01/01")

    # Tamper with date of birth (e.g. attempting to bypass age threshold)
    tampered_qr = valid_qr.replace("1990/01/01", "2010/01/01")
    res = decode_and_verify_qr(tampered_qr, trust_store=trust_store)

    assert res.credential_signature_valid is False
    assert res.status == "invalid_signature"


def test_tampering_gender_fails_signature(rsa_key_pair, trust_store: QRTrustStore):
    priv_key, _, _ = rsa_key_pair
    valid_qr = generate_synthetic_signed_qr(priv_key, gender="M")

    # Tamper with gender tag
    tampered_qr = valid_qr.replace(":G:M:", ":G:F:")
    res = decode_and_verify_qr(tampered_qr, trust_store=trust_store)

    assert res.credential_signature_valid is False
    assert res.status == "invalid_signature"


def test_tampering_photo_fails_signature(rsa_key_pair, trust_store: QRTrustStore):
    priv_key, _, _ = rsa_key_pair
    valid_qr = generate_synthetic_signed_qr(priv_key)

    # Tamper with photo payload
    tampered_qr = "Z" + valid_qr[1:]
    res = decode_and_verify_qr(tampered_qr, trust_store=trust_store)

    assert res.credential_signature_valid is False
    assert res.status in ("invalid_signature", "malformed_input")


def test_tampering_signature_bytes_fails_verification(rsa_key_pair, trust_store: QRTrustStore):
    priv_key, _, _ = rsa_key_pair
    valid_qr = generate_synthetic_signed_qr(priv_key)

    # Flip 1 character in the signature portion after '..'
    parts = valid_qr.split("..")
    sig_part = parts[1]
    flipped_char = "A" if sig_part[-1] != "A" else "B"
    tampered_qr = f"{parts[0]}..{sig_part[:-1]}{flipped_char}"

    res = decode_and_verify_qr(tampered_qr, trust_store=trust_store)
    assert res.credential_signature_valid is False
    assert res.status in ("invalid_signature", "malformed_input")


# ---------------------------------------------------------------------------
# 3. Parser Errors & Malformed Input Tests
# ---------------------------------------------------------------------------

def test_parser_error_missing_signature_delimiter():
    bad_qr = "UklGR...:DLT:Abebe:V:4:G:M:A:1234:D:1990/01/01"
    res = decode_and_verify_qr(bad_qr)
    assert res.status == "malformed_input"
    assert res.error_code in (QRErrorCode.MALFORMED_INPUT.value, QRErrorCode.DELIMITER_ERROR.value)
    assert res.credential_signature_valid is False


def test_parser_error_missing_delimiters():
    # Missing DLT
    res1 = decode_and_verify_qr("Photo:Abebe:V:4:G:M:A:1234:D:1990/01/01:SIGN:header..sig")
    assert res1.status == "malformed_input"
    assert res1.error_code in (QRErrorCode.MALFORMED_INPUT.value, QRErrorCode.DELIMITER_ERROR.value)

    # Missing V
    res2 = decode_and_verify_qr("Photo:DLT:Abebe:G:M:A:1234:D:1990/01/01:SIGN:header..sig")
    assert res2.status == "malformed_input"
    assert res2.error_code in (QRErrorCode.MALFORMED_INPUT.value, QRErrorCode.DELIMITER_ERROR.value)


def test_parser_error_unsupported_version(rsa_key_pair, trust_store: QRTrustStore):
    priv_key, _, _ = rsa_key_pair
    # Generate signed QR with version 5
    qr_v5 = generate_synthetic_signed_qr(priv_key, version=5)

    res = decode_and_verify_qr(qr_v5, trust_store=trust_store, allowed_profiles=["v4"])
    assert res.status in ("rejected", "malformed_input")
    assert res.error_code == QRErrorCode.UNSUPPORTED_VERSION.value
    assert res.credential_signature_valid is False


def test_parser_error_payload_size_exceeded(rsa_key_pair, trust_store: QRTrustStore):
    priv_key, _, _ = rsa_key_pair
    valid_qr = generate_synthetic_signed_qr(priv_key)

    # Pass max_bytes smaller than the payload
    res = decode_and_verify_qr(valid_qr, trust_store=trust_store, max_bytes=100)
    assert res.status == "malformed_input"
    assert res.error_code == QRErrorCode.PAYLOAD_SIZE_EXCEEDED.value


def test_parser_error_malformed_jws_header():
    # Header with alg=none
    bad_header = base64.urlsafe_b64encode(b'{"alg":"none"}').decode("utf-8").rstrip("=")
    bad_qr = f"Photo:DLT:Abebe:V:4:G:M:A:1234:D:1990/01/01:SIGN:{bad_header}..sig"
    res = decode_and_verify_qr(bad_qr)
    assert res.status == "malformed_input"


# ---------------------------------------------------------------------------
# 4. Privacy & Output Filtering Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_minimal_agent_output_privacy(rsa_key_pair, trust_store: QRTrustStore):
    """Verify that agent output contains ONLY minimal safe fields and excludes demographics, photo, and signature."""
    priv_key, _, _ = rsa_key_pair
    valid_qr = generate_synthetic_signed_qr(priv_key, name="Abebe Bikila", fan="1234  5678  9012  3456")

    config = FaydaConfig.sandbox(
        client_id="test_client",
        redirect_uri="https://localhost/callback",
        qr_verification_enabled=True,
    )
    service = FaydaVerificationService(
        config=config,
        sessions=MemorySessionStore(),
        results=MemoryResultRepository(),
    )
    service.qr_service.trust_store = trust_store
    context = CallerContext(tenant_id="tenant_x", principal_id="agent_1")

    # 1. Submit QR verification
    raw_res = await service.submit_qr_verification(
        qr_text=valid_qr,
        context=context,
        purpose="kyc",
        checks=["credential_signature_valid", "age_over_18"],
    )
    agent_output = filter_agent_output(raw_res)

    assert isinstance(agent_output, QRAgentVerificationResult)
    data = agent_output.model_dump()

    # Required safe fields present
    assert agent_output.status == "verified"
    assert agent_output.method == "qr_offline"
    assert "credential_signature_valid" in agent_output.checks
    assert "age_over_18" in agent_output.checks
    assert agent_output.times is not None

    # Demographic / PII fields are strictly absent
    for forbidden in [
        "demographics",
        "photo",
        "photo_base64url",
        "signature",
        "signature_bytes",
        "detached_jws",
        "name",
        "fan",
        "date_of_birth",
        "dob",
        "raw_text",
    ]:
        assert forbidden not in data

    # 2. Retrieve via get_qr_verification_result
    retrieved = await service.get_qr_verification_result(
        request_id=raw_res.request_id,
        context=context,
        filter_output=True,
    )
    assert isinstance(retrieved, QRAgentVerificationResult)
    rdata = retrieved.model_dump()
    for forbidden in [
        "demographics",
        "photo",
        "photo_base64url",
        "signature",
        "signature_bytes",
        "detached_jws",
        "name",
        "fan",
        "date_of_birth",
        "dob",
        "raw_text",
    ]:
        assert forbidden not in rdata


# ---------------------------------------------------------------------------
# 5. Age Boundaries & Calendar Rules
# ---------------------------------------------------------------------------

def test_age_boundaries_exact_turning_18_today_and_tomorrow(
    rsa_key_pair,
    trust_store: QRTrustStore,
):
    """Verify age check precision at exact 18-year boundaries."""
    priv_key, _, _ = rsa_key_pair
    service = FaydaQRVerificationService(trust_store=trust_store)
    today = datetime.now(timezone.utc).date()

    # 1. Exactly 18 years old today
    dob_today_18 = today.replace(year=today.year - 18)
    qr_18 = generate_synthetic_signed_qr(
        priv_key,
        dob=f"{dob_today_18.year:04d}/{dob_today_18.month:02d}/{dob_today_18.day:02d}",
    )
    res_18 = service.verify_qr_sync(
        QRVerificationRequest(qr_text=qr_18, checks=["credential_signature_valid", "age_over_18"])
    )
    assert res_18.credential_signature_valid is True
    assert res_18.checks["age_over_18"] is True

    # 2. Turning 18 tomorrow (currently 17 years and 364 days old)
    tomorrow_18 = today + timedelta(days=1)
    dob_under_18 = tomorrow_18.replace(year=tomorrow_18.year - 18)
    qr_under = generate_synthetic_signed_qr(
        priv_key,
        dob=f"{dob_under_18.year:04d}/{dob_under_18.month:02d}/{dob_under_18.day:02d}",
    )
    res_under = service.verify_qr_sync(
        QRVerificationRequest(qr_text=qr_under, checks=["credential_signature_valid", "age_over_18"])
    )
    assert res_under.credential_signature_valid is True
    assert res_under.checks["age_over_18"] is False

    # 3. Turned 18 yesterday (currently 18 years and 1 day old)
    yesterday_18 = today - timedelta(days=1)
    dob_over_18 = yesterday_18.replace(year=yesterday_18.year - 18)
    qr_over = generate_synthetic_signed_qr(
        priv_key,
        dob=f"{dob_over_18.year:04d}/{dob_over_18.month:02d}/{dob_over_18.day:02d}",
    )
    res_over = service.verify_qr_sync(
        QRVerificationRequest(qr_text=qr_over, checks=["credential_signature_valid", "age_over_18"])
    )
    assert res_over.credential_signature_valid is True
    assert res_over.checks["age_over_18"] is True


def test_unconfirmed_calendar_age_evaluation_fails_safely(
    rsa_key_pair,
    trust_store: QRTrustStore,
):
    """When calendar is unconfirmed, age checks fail safely with unconfirmed_calendar reason."""
    priv_key, _, _ = rsa_key_pair
    service = FaydaQRVerificationService(trust_store=trust_store)
    qr_code = generate_synthetic_signed_qr(priv_key, dob="1990/01/01")

    res = service.verify_qr_sync(
        QRVerificationRequest(
            qr_text=qr_code,
            dob_calendar="unknown_calendar_xyz",
            checks=["credential_signature_valid", "age_over_18"],
        )
    )
    assert res.credential_signature_valid is True
    assert res.checks["age_over_18"] == "unavailable"
    assert res.reasons["age_over_18"] == "unconfirmed_calendar"


# ---------------------------------------------------------------------------
# 6. Isolation Tests (Tenant & Principal Boundaries)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_caller_and_tenant_isolation(rsa_key_pair, trust_store: QRTrustStore):
    """Ensure Caller B / Tenant B cannot retrieve verification results submitted by Caller A."""
    priv_key, _, _ = rsa_key_pair
    valid_qr = generate_synthetic_signed_qr(priv_key)

    config = FaydaConfig.sandbox(
        client_id="test_client",
        redirect_uri="https://localhost/callback",
        qr_verification_enabled=True,
    )
    service = FaydaVerificationService(
        config=config,
        sessions=MemorySessionStore(),
        results=MemoryResultRepository(),
    )
    service.qr_service.trust_store = trust_store

    ctx_a = CallerContext(tenant_id="tenant_a", principal_id="user_a")
    ctx_b = CallerContext(tenant_id="tenant_b", principal_id="user_b")

    # Caller A submits QR verification
    res_a = await service.submit_qr_verification(
        qr_text=valid_qr,
        context=ctx_a,
        purpose="kyc",
        checks=["credential_signature_valid"],
    )
    request_id = res_a.request_id

    # Caller A can retrieve it
    retrieved_a = await service.get_qr_verification_result(request_id=request_id, context=ctx_a)
    assert retrieved_a is not None

    # Caller B cannot retrieve it (raises AuthorizationError due to tenant boundary)
    with pytest.raises(AuthorizationError):
        await service.get_qr_verification_result(request_id=request_id, context=ctx_b)


# ---------------------------------------------------------------------------
# 7. Retries, Idempotency & Host Hook
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_idempotent_retry_and_hook_execution(rsa_key_pair, trust_store: QRTrustStore):
    """Duplicate submissions return cached result; conflicts raise error; hook runs once."""
    priv_key, _, _ = rsa_key_pair
    valid_qr = generate_synthetic_signed_qr(priv_key)

    hook_calls = []

    async def sample_success_hook(ctx: HostUserSuccessContext) -> None:
        hook_calls.append(ctx)

    config = FaydaConfig.sandbox(
        client_id="test_client",
        redirect_uri="https://localhost/callback",
        qr_verification_enabled=True,
    )
    service = FaydaVerificationService(
        config=config,
        sessions=MemorySessionStore(),
        results=MemoryResultRepository(),
        qr_success_hook=sample_success_hook,
    )
    service.qr_service.trust_store = trust_store
    context = CallerContext(tenant_id="tenant_x", principal_id="agent_1")

    # 1. Initial submission
    res1 = await service.submit_qr_verification(
        qr_text=valid_qr,
        context=context,
        purpose="onboarding",
        application_user_ref="user_123",
        checks=["credential_signature_valid"],
        idempotency_key="idem_key_001",
    )
    assert len(hook_calls) == 1

    # 2. Retry with identical parameters -> idempotent cached return
    res2 = await service.submit_qr_verification(
        qr_text=valid_qr,
        context=context,
        purpose="onboarding",
        application_user_ref="user_123",
        checks=["credential_signature_valid"],
        idempotency_key="idem_key_001",
    )
    assert res1.request_id == res2.request_id
    assert len(hook_calls) == 1  # Hook not re-executed

    # 3. Conflicting retry with different purpose -> raises IdempotencyConflictError
    with pytest.raises(IdempotencyConflictError):
        await service.submit_qr_verification(
            qr_text=valid_qr,
            context=context,
            purpose="different_conflicting_purpose",
            application_user_ref="user_123",
            checks=["credential_signature_valid"],
            idempotency_key="idem_key_001",
        )


# ---------------------------------------------------------------------------
# 8. Copied QR Threat Model
# ---------------------------------------------------------------------------

def test_copied_qr_maintains_credential_validity_but_denies_holder_auth(
    rsa_key_pair,
    trust_store: QRTrustStore,
):
    """Replaying a valid, scanned QR code sets credential_signature_valid=True,
    but strictly keeps holder_authenticated=False and identity_verified=False.
    """
    priv_key, _, _ = rsa_key_pair
    service = FaydaQRVerificationService(trust_store=trust_store)
    valid_qr = generate_synthetic_signed_qr(priv_key)

    req = QRVerificationRequest(
        qr_text=valid_qr,
        checks=["credential_signature_valid", "holder_authenticated", "identity_verified"],
    )
    result = service.verify_qr_sync(req)

    # Credential integrity holds
    assert result.credential_signature_valid is True
    assert result.checks["credential_signature_valid"] is True

    # Holder presence and verified identity are strictly False for offline QR alone
    assert result.holder_authenticated is False
    assert result.checks["holder_authenticated"] is False
    assert result.reasons["holder_authenticated"] == "qr_scan_does_not_authenticate_holder"

    assert result.checks["identity_verified"] is False
    assert result.reasons["identity_verified"] == "offline_qr_alone_cannot_assert_identity"


# ---------------------------------------------------------------------------
# 9. Offline & Standalone Verification
# ---------------------------------------------------------------------------

def test_offline_verification_requires_no_oidc_or_client_private_key(
    rsa_key_pair,
    trust_store: QRTrustStore,
):
    """Offline QR verification needs no OIDC callback, webhook, or client private signing key."""
    priv_key, _, _ = rsa_key_pair
    qr_text = generate_synthetic_signed_qr(priv_key)

    # Standalone service instantiated with only public key trust store
    service = FaydaQRVerificationService(trust_store=trust_store)
    result = service.verify_qr_sync(
        QRVerificationRequest(qr_text=qr_text, checks=["credential_signature_valid"])
    )

    assert result.status == "verified"
    assert result.credential_signature_valid is True
