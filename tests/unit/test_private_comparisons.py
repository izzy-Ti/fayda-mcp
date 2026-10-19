"""Unit tests for keeping comparisons private (guide5 Task 13).

Verifies:
1. Reuse caller/user binding: tenant isolation, principal isolation, and user reference binding.
2. TTL enforcement: records, match outcomes, and backend comparison traces expire and are purged.
3. Rate limiting: sliding window per caller and per user, raising DetailsRateLimitExceededError when exceeded.
4. Privacy contract: names, variants, phonetic codes, and scores are kept backend-only by default.
5. Invariant verifiers: assert_comparison_privacy_invariants, assert_caller_user_binding, assert_ttl_compliance.
"""

import asyncio
from datetime import datetime, timedelta, timezone
import json
import pytest

from fayda_mcp.context import CallerContext
from fayda_mcp.matching.privacy import (
    DEFAULT_RATE_LIMIT_REQUESTS,
    DEFAULT_RATE_LIMIT_WINDOW_SECONDS,
    FORBIDDEN_LEAK_FIELDS,
    PRIVACY_SPEC_VERSION,
    BackendComparisonDetails,
    MatchingRateLimiter,
    assert_caller_user_binding,
    assert_comparison_privacy_invariants,
    assert_ttl_compliance,
    sanitize_matching_result,
)
from fayda_mcp.matching.profiles import PROFILE_ETHIOPIAN_NAME_V1, PROFILE_STRICT
from fayda_mcp.matching.schemas import (
    DetailsCallerMismatchError,
    DetailsMatchingError,
    DetailsMatchResult,
    DetailsPrivacyViolationError,
    DetailsPurposeMismatchError,
    DetailsRateLimitExceededError,
    DetailsReferenceExpiredError,
    DetailsUserMismatchError,
    ExpectedDetails,
    ExpectedDetailsRecord,
)
from fayda_mcp.matching.service import DetailsMatchingService
from fayda_mcp.matching.storage import MemoryExpectedDetailsStore


# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture
def tenant_alpha_ctx() -> CallerContext:
    return CallerContext(
        tenant_id="bank-alpha",
        principal_id="backend-service-alpha",
        scopes=["verification:create", "verification:read"],
    )


@pytest.fixture
def tenant_beta_ctx() -> CallerContext:
    return CallerContext(
        tenant_id="telecom-beta",
        principal_id="backend-service-beta",
        scopes=["verification:create", "verification:read"],
    )


@pytest.fixture
def sample_expected_details() -> ExpectedDetails:
    return ExpectedDetails(
        full_name="Abebe Bikila",
        date_of_birth="1990/05/12",
        matching_profile=PROFILE_ETHIOPIAN_NAME_V1,
    )


# ===========================================================================
# 1. Caller and User Binding Tests
# ===========================================================================


@pytest.mark.asyncio
async def test_caller_binding_isolation(
    tenant_alpha_ctx: CallerContext,
    tenant_beta_ctx: CallerContext,
    sample_expected_details: ExpectedDetails,
):
    """Caller from Tenant Beta cannot access or bind Tenant Alpha's expected details."""
    service = DetailsMatchingService()

    resp = await service.submit_expected_details(
        application_user_ref="usr_alpha_100",
        purpose="kyc",
        expected_details=sample_expected_details,
        context=tenant_alpha_ctx,
    )
    ref = resp.expected_details_ref

    # Tenant Alpha accesses successfully
    rec = await service.get_expected_details_record(ref, context=tenant_alpha_ctx)
    assert rec.ref == ref

    # Tenant Beta access is rejected
    with pytest.raises(DetailsCallerMismatchError):
        await service.get_expected_details_record(ref, context=tenant_beta_ctx)

    # Tenant Beta binding is rejected
    with pytest.raises(DetailsCallerMismatchError):
        await service.bind_expected_details(
            ref=ref,
            request_id="req_beta_1",
            application_user_ref="usr_alpha_100",
            purpose="kyc",
            context=tenant_beta_ctx,
        )


@pytest.mark.asyncio
async def test_user_and_purpose_binding_enforcement(
    tenant_alpha_ctx: CallerContext,
    sample_expected_details: ExpectedDetails,
):
    """Binding fails if application_user_ref or purpose does not match the bound expectation."""
    service = DetailsMatchingService()

    resp = await service.submit_expected_details(
        application_user_ref="usr_expected_999",
        purpose="onboarding",
        expected_details=sample_expected_details,
        context=tenant_alpha_ctx,
    )
    ref = resp.expected_details_ref

    # Wrong user ref raises DetailsUserMismatchError
    with pytest.raises(DetailsUserMismatchError):
        await service.bind_expected_details(
            ref=ref,
            request_id="req_bind_1",
            application_user_ref="usr_wrong_user",
            purpose="onboarding",
            context=tenant_alpha_ctx,
        )

    # Wrong purpose raises DetailsPurposeMismatchError
    with pytest.raises(DetailsPurposeMismatchError):
        await service.bind_expected_details(
            ref=ref,
            request_id="req_bind_1",
            application_user_ref="usr_expected_999",
            purpose="kyc",  # submitted with 'onboarding'
            context=tenant_alpha_ctx,
        )


def test_assert_caller_user_binding_helper(
    tenant_alpha_ctx: CallerContext,
    tenant_beta_ctx: CallerContext,
    sample_expected_details: ExpectedDetails,
):
    """assert_caller_user_binding correctly validates or raises for tenant/user mismatch."""
    rec = ExpectedDetailsRecord(
        ref="edr_test",
        tenant_id=tenant_alpha_ctx.tenant_id,
        principal_id=tenant_alpha_ctx.principal_id,
        application_user_ref="usr_123",
        purpose="kyc",
        expected_details=sample_expected_details,
        created_at="2026-10-18T00:00:00Z",
        expires_at="2026-10-18T00:15:00Z",
    )

    # Valid check passes
    assert assert_caller_user_binding(
        record=rec,
        context=tenant_alpha_ctx,
        application_user_ref="usr_123",
        purpose="kyc",
    ) is True

    # Cross-tenant check raises
    with pytest.raises(DetailsCallerMismatchError):
        assert_caller_user_binding(record=rec, context=tenant_beta_ctx)

    # User mismatch raises
    with pytest.raises(DetailsUserMismatchError):
        assert_caller_user_binding(record=rec, context=tenant_alpha_ctx, application_user_ref="usr_different")

    # Purpose mismatch raises
    with pytest.raises(DetailsPurposeMismatchError):
        assert_caller_user_binding(record=rec, context=tenant_alpha_ctx, purpose="different_purpose")


# ===========================================================================
# 2. TTL Enforcement Tests
# ===========================================================================


@pytest.mark.asyncio
async def test_ttl_expiration_expected_details(
    tenant_alpha_ctx: CallerContext,
    sample_expected_details: ExpectedDetails,
):
    """Expected details record cannot be retrieved once expired."""
    service = DetailsMatchingService()

    resp = await service.submit_expected_details(
        application_user_ref="usr_ttl_01",
        purpose="kyc",
        expected_details=sample_expected_details,
        context=tenant_alpha_ctx,
        ttl_seconds=60,
    )
    ref = resp.expected_details_ref

    # Artificially expire the record by adjusting its stored timestamp
    rec = await service.store.get_expected_details(ref)
    assert rec is not None

    past_iso = (datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat()
    expired_rec = ExpectedDetailsRecord(
        ref=rec.ref,
        tenant_id=rec.tenant_id,
        principal_id=rec.principal_id,
        application_user_ref=rec.application_user_ref,
        purpose=rec.purpose,
        expected_details=rec.expected_details,
        created_at=rec.created_at,
        expires_at=past_iso,
    )
    await service.store.save_expected_details(ref, expired_rec, ttl_seconds=1)

    # Fetching expired record raises DetailsReferenceExpiredError
    with pytest.raises(DetailsReferenceExpiredError):
        await service.get_expected_details_record(ref, context=tenant_alpha_ctx)


@pytest.mark.asyncio
async def test_ttl_expiration_match_results():
    """Match result returns None after expiration."""
    store = MemoryExpectedDetailsStore()

    res = DetailsMatchResult(
        request_id="req_ttl_res",
        matching_status="matched",
        matches={"full_name": True},
    )
    # Save with 1 second TTL
    await store.save_match_result("req_ttl_res", res, ttl_seconds=1)

    # Immediately retrievable
    got = await store.get_match_result("req_ttl_res")
    assert got is not None

    # Wait for expiration
    await asyncio.sleep(1.1)
    got_expired = await store.get_match_result("req_ttl_res")
    assert got_expired is None


def test_assert_ttl_compliance_helper():
    """assert_ttl_compliance correctly checks past and future expiry timestamps."""
    now = datetime.now(timezone.utc)
    future_iso = (now + timedelta(minutes=15)).isoformat()
    past_iso = (now - timedelta(minutes=1)).isoformat()

    assert assert_ttl_compliance(future_iso, now=now) is True

    with pytest.raises(DetailsReferenceExpiredError):
        assert_ttl_compliance(past_iso, now=now)


# ===========================================================================
# 3. Rate Limiter Tests
# ===========================================================================


def test_matching_rate_limiter_sliding_window():
    """Rate limiter allows requests up to max_requests and blocks afterwards."""
    limiter = MatchingRateLimiter(max_requests=3, window_seconds=60)
    key = "tenant_1:user_1"

    # First 3 requests succeed
    limiter.acquire(key)
    limiter.acquire(key)
    limiter.acquire(key)

    assert limiter.is_allowed(key) is False

    # 4th request raises DetailsRateLimitExceededError
    with pytest.raises(DetailsRateLimitExceededError) as exc_info:
        limiter.acquire(key)
    assert exc_info.value.code == "matching_rate_limit_exceeded"

    # Reset clears counts
    limiter.reset()
    assert limiter.is_allowed(key) is True
    limiter.acquire(key)


@pytest.mark.asyncio
async def test_service_rate_limit_enforcement(
    tenant_alpha_ctx: CallerContext,
    sample_expected_details: ExpectedDetails,
):
    """DetailsMatchingService enforces rate limits on submissions when limiter is configured."""
    limiter = MatchingRateLimiter(max_requests=2, window_seconds=60)
    service = DetailsMatchingService(rate_limiter=limiter)

    # First 2 submissions succeed
    await service.submit_expected_details(
        application_user_ref="usr_rate_1",
        purpose="kyc",
        expected_details=sample_expected_details,
        context=tenant_alpha_ctx,
    )
    await service.submit_expected_details(
        application_user_ref="usr_rate_2",
        purpose="kyc",
        expected_details=sample_expected_details,
        context=tenant_alpha_ctx,
    )

    # 3rd submission by the same caller exceeds caller rate limit
    with pytest.raises(DetailsRateLimitExceededError):
        await service.submit_expected_details(
            application_user_ref="usr_rate_3",
            purpose="kyc",
            expected_details=sample_expected_details,
            context=tenant_alpha_ctx,
        )


# ===========================================================================
# 4. Privacy Invariants: Backend-Only vs Agent Output
# ===========================================================================


@pytest.mark.asyncio
async def test_names_variants_phonetics_and_scores_kept_backend_only(
    tenant_alpha_ctx: CallerContext,
    sample_expected_details: ExpectedDetails,
):
    """Rich variants, phonetic codes, and scores are stored in BackendComparisonDetails and NEVER leak in DetailsMatchResult."""
    store = MemoryExpectedDetailsStore()
    service = DetailsMatchingService(store=store)

    resp = await service.submit_expected_details(
        application_user_ref="usr_priv_01",
        purpose="kyc",
        expected_details=sample_expected_details,
        context=tenant_alpha_ctx,
    )
    await service.bind_expected_details(
        ref=resp.expected_details_ref,
        request_id="req_priv_01",
        application_user_ref="usr_priv_01",
        purpose="kyc",
        context=tenant_alpha_ctx,
    )

    # Evaluate match with variations (Amharic to Latin)
    claims = {"name": "አበበ ቢቂላ", "sub": "fayda:citizen:123"}
    match_result = await service.evaluate_details_for_request(
        request_id="req_priv_01",
        claims=claims,
        expected_details_ref=resp.expected_details_ref,
    )

    # --- 1. Verify Public / Agent Match Result ---
    dumped_result = json.loads(match_result.model_dump_json())

    # Strictly no raw names in top-level fields
    assert "full_name" not in dumped_result
    assert "expected_name" not in dumped_result
    assert "provider_name" not in dumped_result

    # Strictly no candidate variants
    assert "variants" not in dumped_result
    assert "candidate_variants" not in dumped_result

    # Strictly no phonetic codes (e.g. APPP or Ethiopic phonetic codes)
    assert "phonetic_codes" not in dumped_result
    assert "matched_phonetic_code" not in dumped_result

    # Strictly no numerical similarity scores
    assert "similarity_score" not in dumped_result
    assert "overall_similarity_score" not in dumped_result
    assert "scores" not in dumped_result

    # Valid tri-state outcome only
    assert dumped_result["matching_status"] in ("matched", "mismatched", "unavailable", "pending")
    assert dumped_result["matches"]["full_name"] is True
    assert dumped_result["name_match_status"] in ("exact", "approved_equivalent", "review_required")

    # Verify assert_comparison_privacy_invariants passes on this result
    assert assert_comparison_privacy_invariants(dumped_result) is True

    # --- 2. Verify Backend-Only Rich Comparison Trace ---
    backend_cmp = await service.get_backend_comparison("req_priv_01", context=tenant_alpha_ctx)
    assert backend_cmp is not None
    assert isinstance(backend_cmp, BackendComparisonDetails)
    assert backend_cmp.expected_name == "Abebe Bikila"
    assert backend_cmp.provider_name == "አበበ ቢቂላ"
    assert len(backend_cmp.variants) > 0  # Variants retained on backend
    assert len(backend_cmp.phonetic_codes) > 0  # Phonetic codes retained on backend
    assert "overall_similarity_score" in backend_cmp.similarity_scores  # Scores retained on backend

    # Cross-tenant access to backend-only trace is strictly forbidden
    with pytest.raises(DetailsCallerMismatchError):
        await service.get_backend_comparison(
            "req_priv_01",
            context=CallerContext(tenant_id="foreign_tenant", principal_id="intruder"),
        )


def test_assert_comparison_privacy_invariants_detects_leakage():
    """assert_comparison_privacy_invariants raises DetailsPrivacyViolationError if forbidden fields leak."""
    for forbidden in FORBIDDEN_LEAK_FIELDS:
        leaky_data = {
            "request_id": "req_leak",
            "matching_status": "matched",
            forbidden: "sensitive_leaked_value",
        }
        with pytest.raises(DetailsPrivacyViolationError):
            assert_comparison_privacy_invariants(leaky_data)


def test_sanitize_matching_result_contract():
    """sanitize_matching_result validates and returns safe DetailsMatchResult."""
    res = DetailsMatchResult(
        request_id="req_safe",
        matching_status="matched",
        matches={"full_name": True},
        name_match_status="exact",
        method="exact_normalized",
    )
    sanitized = sanitize_matching_result(res)
    assert sanitized.request_id == "req_safe"
    assert sanitized.matches["full_name"] is True
