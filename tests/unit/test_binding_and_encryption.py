"""Unit tests for Task 03: Binding expectations, encryption at rest, and short TTL enforcement."""

import asyncio
from datetime import datetime, timedelta, timezone
import pytest

from fayda_mcp.context import CallerContext
from fayda_mcp.matching.crypto import (
    ENCRYPTION_PREFIX,
    DetailsEncryptor,
    derive_encryption_key,
)
from fayda_mcp.matching.schemas import (
    MAX_EXPECTED_DETAILS_TTL_SECONDS,
    MIN_EXPECTED_DETAILS_TTL_SECONDS,
    DetailsAlreadyBoundError,
    DetailsCallerMismatchError,
    DetailsMatchingError,
    DetailsMatchingErrorCode,
    DetailsPurposeMismatchError,
    DetailsReferenceExpiredError,
    DetailsReferenceNotFoundError,
    DetailsUserMismatchError,
    ExpectedDetails,
    ExpectedDetailsRecord,
)
from fayda_mcp.matching.service import DetailsMatchingService
from fayda_mcp.matching.storage import (
    MemoryExpectedDetailsStore,
    SessionExpectedDetailsStore,
)
from fayda_mcp.policy import VerificationPolicy
from fayda_mcp.storage.memory import MemorySessionStore


@pytest.fixture
def caller_ctx() -> CallerContext:
    return CallerContext(
        tenant_id="bank-tenant-1",
        principal_id="backend-service-a",
        scopes=["verification:create", "verification:read"],
    )


@pytest.fixture
def other_ctx() -> CallerContext:
    return CallerContext(
        tenant_id="other-tenant-2",
        principal_id="backend-service-b",
        scopes=["verification:create"],
    )


@pytest.fixture
def sample_details() -> ExpectedDetails:
    return ExpectedDetails(
        full_name="Abebe Bikila",
        date_of_birth="1990/05/12",
        dob_calendar="gregorian",
    )


# ===========================================================================
# 1. Encryption Primitives & At-Rest Storage Tests
# ===========================================================================


def test_encryptor_roundtrip(sample_details: ExpectedDetails):
    """Encrypt and decrypt details using AES-256-GCM."""
    encryptor = DetailsEncryptor()
    ciphertext = encryptor.encrypt_details(sample_details)

    assert ciphertext.startswith(ENCRYPTION_PREFIX)
    # Ensure sensitive plaintext is NOT in ciphertext
    assert "Abebe" not in ciphertext
    assert "1990" not in ciphertext

    decrypted = encryptor.decrypt_details(ciphertext)
    assert decrypted.full_name == "Abebe Bikila"
    assert decrypted.date_of_birth == "1990/05/12"
    assert decrypted.dob_calendar == "gregorian"


def test_encryptor_tamper_detection(sample_details: ExpectedDetails):
    """GCM auth tag verification detects any flipped bits."""
    encryptor = DetailsEncryptor()
    ciphertext = encryptor.encrypt_details(sample_details)

    # Tamper with the base64 payload
    tampered = ciphertext[:-4] + ("A" if ciphertext[-4] != "A" else "B") + ciphertext[-3:]
    with pytest.raises(DetailsMatchingError) as exc_info:
        encryptor.decrypt_details(tampered)
    assert exc_info.value.code == DetailsMatchingErrorCode.INVALID_EXPECTATIONS


def test_encryptor_wrong_key(sample_details: ExpectedDetails):
    """Ciphertext cannot be decrypted using a different key."""
    enc1 = DetailsEncryptor(key="key-one-secret-material")
    enc2 = DetailsEncryptor(key="key-two-secret-material")

    ciphertext = enc1.encrypt_details(sample_details)
    with pytest.raises(DetailsMatchingError):
        enc2.decrypt_details(ciphertext)


def test_derive_encryption_key_formats():
    """Key derivation handles hex, base64, raw 32 bytes, and passphrases."""
    # 32 raw bytes
    raw_32 = b"\x01" * 32
    assert derive_encryption_key(raw_32) == raw_32

    # 64 hex chars
    hex_key = "01" * 32
    assert derive_encryption_key(hex_key) == raw_32

    # Arbitrary passphrase derives 32 bytes
    derived = derive_encryption_key("my-passphrase-production-key")
    assert isinstance(derived, bytes)
    assert len(derived) == 32


@pytest.mark.asyncio
async def test_retained_details_encrypted_at_rest_in_memory_store(
    caller_ctx: CallerContext, sample_details: ExpectedDetails
):
    """Storage adapter strictly retains only ciphertext at rest in memory."""
    store = MemoryExpectedDetailsStore()
    service = DetailsMatchingService(store=store)

    resp = await service.submit_expected_details(
        application_user_ref="usr_77",
        purpose="kyc",
        expected_details=sample_details,
        context=caller_ctx,
    )

    ref = resp.expected_details_ref
    # Inspect internal store memory: plaintext details MUST BE None
    raw_stored = store._records[ref]
    assert raw_stored["expected_details"] is None
    assert raw_stored["encrypted_details"].startswith(ENCRYPTION_PREFIX)
    assert "Abebe" not in str(raw_stored["encrypted_details"])

    # Retrieving through service/store returns decrypted record
    record = await service.get_expected_details_record(ref, context=caller_ctx)
    assert record.expected_details.full_name == "Abebe Bikila"
    assert record.expected_details.date_of_birth == "1990/05/12"


@pytest.mark.asyncio
async def test_retained_details_encrypted_at_rest_in_session_store(
    caller_ctx: CallerContext, sample_details: ExpectedDetails
):
    """Storage adapter strictly retains only ciphertext in SessionStore (e.g. Redis)."""
    session_store = MemorySessionStore()
    service = DetailsMatchingService(session_store=session_store)

    resp = await service.submit_expected_details(
        application_user_ref="usr_88",
        purpose="onboarding",
        expected_details=sample_details,
        context=caller_ctx,
    )

    ref = resp.expected_details_ref
    # Inspect raw session data in session_store
    raw_session = await session_store.get_session(f"edr:{ref}")
    assert raw_session is not None
    assert raw_session["expected_details"] is None
    assert raw_session["encrypted_details"].startswith(ENCRYPTION_PREFIX)
    assert "Abebe" not in str(raw_session["encrypted_details"])

    # Retrieving through service decrypts cleanly
    record = await service.get_expected_details_record(ref, context=caller_ctx)
    assert record.expected_details.full_name == "Abebe Bikila"


# ===========================================================================
# 2. Binding Expectations Tests (Caller, User, Purpose, Request)
# ===========================================================================


@pytest.mark.asyncio
async def test_bind_expected_details_success(caller_ctx: CallerContext, sample_details: ExpectedDetails):
    """Successfully bind expected details to a verification request."""
    service = DetailsMatchingService()
    resp = await service.submit_expected_details(
        application_user_ref="usr_123",
        purpose="kyc",
        expected_details=sample_details,
        context=caller_ctx,
    )

    bound_record = await service.bind_expected_details(
        ref=resp.expected_details_ref,
        request_id="vr_req_999",
        application_user_ref="usr_123",
        purpose="kyc",
        context=caller_ctx,
    )

    assert bound_record.bound_request_id == "vr_req_999"
    assert bound_record.application_user_ref == "usr_123"
    assert bound_record.purpose == "kyc"


@pytest.mark.asyncio
async def test_bind_expected_details_idempotent(caller_ctx: CallerContext, sample_details: ExpectedDetails):
    """Re-binding with the same request_id succeeds idempotently."""
    service = DetailsMatchingService()
    resp = await service.submit_expected_details(
        application_user_ref="usr_123",
        purpose="kyc",
        expected_details=sample_details,
        context=caller_ctx,
    )

    rec1 = await service.bind_expected_details(
        ref=resp.expected_details_ref,
        request_id="vr_req_999",
        application_user_ref="usr_123",
        purpose="kyc",
        context=caller_ctx,
    )
    rec2 = await service.bind_expected_details(
        ref=resp.expected_details_ref,
        request_id="vr_req_999",
        application_user_ref="usr_123",
        purpose="kyc",
        context=caller_ctx,
    )
    assert rec1.bound_request_id == rec2.bound_request_id == "vr_req_999"


@pytest.mark.asyncio
async def test_bind_replay_different_request_conflict(
    caller_ctx: CallerContext, sample_details: ExpectedDetails
):
    """Replaying an expected_details_ref on a different request fails with DetailsAlreadyBoundError."""
    service = DetailsMatchingService()
    resp = await service.submit_expected_details(
        application_user_ref="usr_123",
        purpose="kyc",
        expected_details=sample_details,
        context=caller_ctx,
    )

    await service.bind_expected_details(
        ref=resp.expected_details_ref,
        request_id="vr_first",
        application_user_ref="usr_123",
        purpose="kyc",
        context=caller_ctx,
    )

    # Attempt binding to another request
    with pytest.raises(DetailsAlreadyBoundError):
        await service.bind_expected_details(
            ref=resp.expected_details_ref,
            request_id="vr_second",
            application_user_ref="usr_123",
            purpose="kyc",
            context=caller_ctx,
        )


@pytest.mark.asyncio
async def test_bind_caller_isolation_mismatch(
    caller_ctx: CallerContext, other_ctx: CallerContext, sample_details: ExpectedDetails
):
    """A different caller cannot bind someone else's expected details reference."""
    service = DetailsMatchingService()
    resp = await service.submit_expected_details(
        application_user_ref="usr_123",
        purpose="kyc",
        expected_details=sample_details,
        context=caller_ctx,
    )

    with pytest.raises(DetailsCallerMismatchError):
        await service.bind_expected_details(
            ref=resp.expected_details_ref,
            request_id="vr_steal",
            application_user_ref="usr_123",
            purpose="kyc",
            context=other_ctx,
        )


@pytest.mark.asyncio
async def test_bind_user_mismatch(caller_ctx: CallerContext, sample_details: ExpectedDetails):
    """Binding fails if application_user_ref does not match."""
    service = DetailsMatchingService()
    resp = await service.submit_expected_details(
        application_user_ref="usr_original",
        purpose="kyc",
        expected_details=sample_details,
        context=caller_ctx,
    )

    with pytest.raises(DetailsUserMismatchError):
        await service.bind_expected_details(
            ref=resp.expected_details_ref,
            request_id="vr_req_1",
            application_user_ref="usr_wrong",
            purpose="kyc",
            context=caller_ctx,
        )


@pytest.mark.asyncio
async def test_bind_purpose_mismatch(caller_ctx: CallerContext, sample_details: ExpectedDetails):
    """Binding fails if purpose does not match."""
    service = DetailsMatchingService()
    resp = await service.submit_expected_details(
        application_user_ref="usr_123",
        purpose="kyc",
        expected_details=sample_details,
        context=caller_ctx,
    )

    with pytest.raises(DetailsPurposeMismatchError):
        await service.bind_expected_details(
            ref=resp.expected_details_ref,
            request_id="vr_req_1",
            application_user_ref="usr_123",
            purpose="onboarding",
            context=caller_ctx,
        )


@pytest.mark.asyncio
async def test_bind_reverse_lookup_by_request_id(
    caller_ctx: CallerContext, sample_details: ExpectedDetails
):
    """Looking up bound expected details by request_id succeeds."""
    service = DetailsMatchingService()
    resp = await service.submit_expected_details(
        application_user_ref="usr_555",
        purpose="kyc",
        expected_details=sample_details,
        context=caller_ctx,
    )

    await service.bind_expected_details(
        ref=resp.expected_details_ref,
        request_id="vr_lookup_target",
        application_user_ref="usr_555",
        purpose="kyc",
        context=caller_ctx,
    )

    bound_rec = await service.get_bound_expected_details_for_request(
        request_id="vr_lookup_target",
        context=caller_ctx,
    )
    assert bound_rec.ref == resp.expected_details_ref
    assert bound_rec.expected_details.full_name == "Abebe Bikila"


# ===========================================================================
# 3. Short TTL Enforcement Tests
# ===========================================================================


@pytest.mark.asyncio
async def test_ttl_clamping_limits(caller_ctx: CallerContext, sample_details: ExpectedDetails):
    """TTL is strictly clamped between MIN (60s) and MAX (3600s)."""
    service = DetailsMatchingService()

    # Below min: clamped to 60s
    resp_min = await service.submit_expected_details(
        application_user_ref="usr_min",
        purpose="kyc",
        expected_details=sample_details,
        context=caller_ctx,
        ttl_seconds=10,
    )
    exp_min = datetime.fromisoformat(resp_min.expires_at)
    now = datetime.now(timezone.utc)
    assert 55 <= (exp_min - now).total_seconds() <= 65

    # Above max: clamped to 3600s
    resp_max = await service.submit_expected_details(
        application_user_ref="usr_max",
        purpose="kyc",
        expected_details=sample_details,
        context=caller_ctx,
        ttl_seconds=99999,
    )
    exp_max = datetime.fromisoformat(resp_max.expires_at)
    assert 3590 <= (exp_max - now).total_seconds() <= 3605


@pytest.mark.asyncio
async def test_expired_reference_purged_on_get(caller_ctx: CallerContext, sample_details: ExpectedDetails):
    """Accessing an expired reference raises DetailsReferenceExpiredError and purges it."""
    store = MemoryExpectedDetailsStore()
    service = DetailsMatchingService(store=store)

    resp = await service.submit_expected_details(
        application_user_ref="usr_exp",
        purpose="kyc",
        expected_details=sample_details,
        context=caller_ctx,
        ttl_seconds=60,
    )
    ref = resp.expected_details_ref

    # Artificially expire the record
    raw = store._records[ref]
    expired_time = (datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat()
    raw["expires_at"] = expired_time
    store._expirations[ref] = 0

    with pytest.raises(DetailsReferenceExpiredError):
        await service.get_expected_details_record(ref, context=caller_ctx)

    # Next attempt should be reference not found (it was purged)
    with pytest.raises(DetailsReferenceNotFoundError):
        await service.get_expected_details_record(ref, context=caller_ctx)


@pytest.mark.asyncio
async def test_expired_reference_cannot_be_bound(caller_ctx: CallerContext, sample_details: ExpectedDetails):
    """Binding an expired reference immediately fails with DetailsReferenceExpiredError."""
    store = MemoryExpectedDetailsStore()
    service = DetailsMatchingService(store=store)

    resp = await service.submit_expected_details(
        application_user_ref="usr_exp",
        purpose="kyc",
        expected_details=sample_details,
        context=caller_ctx,
        ttl_seconds=60,
    )
    ref = resp.expected_details_ref

    # Artificially expire
    store._records[ref]["expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat()
    store._expirations[ref] = 0

    with pytest.raises(DetailsReferenceExpiredError):
        await service.bind_expected_details(
            ref=ref,
            request_id="vr_exp_test",
            application_user_ref="usr_exp",
            purpose="kyc",
            context=caller_ctx,
        )


@pytest.mark.asyncio
async def test_purge_expected_details_cleans_reverse_index(
    caller_ctx: CallerContext, sample_details: ExpectedDetails
):
    """Purging expected details also removes reverse request lookup."""
    service = DetailsMatchingService()
    resp = await service.submit_expected_details(
        application_user_ref="usr_purge",
        purpose="kyc",
        expected_details=sample_details,
        context=caller_ctx,
    )

    await service.bind_expected_details(
        ref=resp.expected_details_ref,
        request_id="vr_purge_req",
        application_user_ref="usr_purge",
        purpose="kyc",
        context=caller_ctx,
    )

    # Purge
    deleted = await service.purge_expected_details(resp.expected_details_ref)
    assert deleted is True

    # Reverse lookup now raises DetailsReferenceNotFoundError
    with pytest.raises(DetailsReferenceNotFoundError):
        await service.get_bound_expected_details_for_request("vr_purge_req", context=caller_ctx)
