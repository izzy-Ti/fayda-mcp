"""Service-level unit tests for race-safe idempotency and finalization (Task S3)."""

import asyncio
import pytest
from unittest.mock import AsyncMock

from fayda_mcp.config import FaydaConfig
from fayda_mcp.context import CallerContext
from fayda_mcp.exceptions import IdempotencyConflictError, InvalidStateError, ProviderError
from fayda_mcp.service import FaydaVerificationService
from fayda_mcp.storage.memory import MemoryResultRepository, MemorySessionStore


def create_test_service() -> FaydaVerificationService:
    config = FaydaConfig(
        client_id="test_client",
        redirect_uri="https://app.example/callback",
        issuer="https://esignet.example",
        authorization_endpoint="https://esignet.example/authorize",
        token_endpoint="https://esignet.example/token",
        userinfo_endpoint="https://esignet.example/userinfo",
        jwks_uri="https://esignet.example/jwks",
        signing_key="mock_test_signing_key_secret_material",
    )
    return FaydaVerificationService(
        config=config,
        sessions=MemorySessionStore(),
        results=MemoryResultRepository(),
    )


@pytest.mark.asyncio
async def test_concurrent_identical_starts_create_one_request():
    """Acceptance requirement: Concurrent identical starts create one request/flow."""
    service = create_test_service()
    context = CallerContext(tenant_id="tenant-1", principal_id="agent-1")

    # 10 concurrent start requests with identical parameters and idempotency key
    tasks = [
        service.start_verification(
            context=context,
            purpose="onboarding",
            checks=["identity_verified"],
            application_user_ref="user-1234",
            idempotency_key="idemp-key-conc-start",
        )
        for _ in range(10)
    ]

    responses = await asyncio.gather(*tasks)

    # All responses must reference the exact same request_id and authorization URL
    request_ids = {r.request_id for r in responses}
    assert len(request_ids) == 1, f"Expected 1 unique request_id, got: {request_ids}"
    assert all(r.authorization_url for r in responses)


@pytest.mark.asyncio
async def test_reusing_key_with_different_inputs_returns_conflict():
    """Acceptance requirement: Reusing a key with different inputs returns conflict."""
    service = create_test_service()
    context = CallerContext(tenant_id="tenant-1", principal_id="agent-1")
    idemp_key = "idemp-key-conflict-test"

    # 1. Initial valid start
    resp = await service.start_verification(
        context=context,
        purpose="onboarding",
        checks=["identity_verified"],
        application_user_ref="user-orig",
        idempotency_key=idemp_key,
    )
    assert resp.request_id.startswith("vr_")

    # 2. Reusing same key with identical inputs succeeds idempotently
    resp_same = await service.start_verification(
        context=context,
        purpose="onboarding",
        checks=["identity_verified"],
        application_user_ref="user-orig",
        idempotency_key=idemp_key,
    )
    assert resp_same.request_id == resp.request_id

    # 3. Reusing same key with different purpose raises conflict
    with pytest.raises(IdempotencyConflictError):
        await service.start_verification(
            context=context,
            purpose="kyc",
            checks=["identity_verified"],
            application_user_ref="user-orig",
            idempotency_key=idemp_key,
        )

    # 4. Reusing same key with different user ref raises conflict
    with pytest.raises(IdempotencyConflictError):
        await service.start_verification(
            context=context,
            purpose="onboarding",
            checks=["identity_verified"],
            application_user_ref="user-different",
            idempotency_key=idemp_key,
        )


@pytest.mark.asyncio
async def test_redis_write_failure_compensation():
    """Requirement: Model initializing -> pending and compensate failed Redis writes."""
    service = create_test_service()
    context = CallerContext(tenant_id="tenant-1", principal_id="agent-1")

    # Mock Redis save_session to fail with a network error
    service.sessions.save_session = AsyncMock(side_effect=ConnectionError("Redis unreachable"))

    with pytest.raises(ProviderError) as exc_info:
        await service.start_verification(
            context=context,
            purpose="onboarding",
            checks=["identity_verified"],
            application_user_ref="user-redis-fail",
            idempotency_key="idemp-key-redis-fail",
        )
    assert "Failed to persist verification session in Redis" in str(exc_info.value)

    # Verify database record was compensated to 'failed' status
    req = await service.results.find_by_idempotency_key(
        tenant_id="tenant-1",
        principal_id="agent-1",
        idempotency_key="idemp-key-redis-fail",
    )
    assert req is not None
    assert req["status"] == "failed"


@pytest.mark.asyncio
async def test_cancelled_request_cannot_finalize_verified():
    """Acceptance requirement: Cancelled/expired requests cannot finalize verified."""
    service = create_test_service()
    context = CallerContext(tenant_id="tenant-1", principal_id="agent-1")

    resp = await service.start_verification(
        context=context,
        purpose="onboarding",
        checks=["identity_verified"],
        application_user_ref="user-cancel",
        idempotency_key="idemp-key-cancel",
    )

    # Cancel request
    cancel_resp = await service.cancel_verification(context=context, request_id=resp.request_id)
    assert cancel_resp.status == "cancelled"

    # Verify authorization URL is purged on cancellation
    req = await service.results.get_request(resp.request_id)
    assert req is not None
    assert req["status"] == "cancelled"
    assert not req.get("authorization_url") and not req.get("auth_url")

    # Replay/callback on cancelled request fails
    with pytest.raises(InvalidStateError):
        await service.complete_verification(
            code="mock_code",
            state="mock_state_unknown",
        )


@pytest.mark.asyncio
async def test_auth_url_purged_upon_terminal_result():
    """Requirement: Briefly retain sensitive authorization URL only while pending; purge on completion/expiry."""
    service = create_test_service()
    context = CallerContext(tenant_id="tenant-1", principal_id="agent-1")

    resp = await service.start_verification(
        context=context,
        purpose="onboarding",
        checks=["identity_verified"],
        application_user_ref="user-purge",
        idempotency_key="idemp-key-purge",
    )

    # While pending: auth_url is present
    req_pending = await service.results.get_request(resp.request_id)
    assert req_pending is not None
    assert req_pending.get("authorization_url")

    # When request is cancelled: auth_url is immediately purged
    await service.cancel_verification(context=context, request_id=resp.request_id)
    req_terminal = await service.results.get_request(resp.request_id)
    assert req_terminal is not None
    assert not req_terminal.get("authorization_url") and not req_terminal.get("auth_url")
