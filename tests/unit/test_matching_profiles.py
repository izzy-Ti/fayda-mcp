"""Unit tests for Task 01: Matching profile definitions, supported languages, and explicit host opt-in.

Verifies:
- Strict profile is the default; no fuzzy or transliteration allowed.
- Explicit host opt-in required for ethiopian_name_v1 profile.
- Agent cannot select or override matching profile (host-controlled only).
- Supported languages: Amharic ('am') and Latin spelling variants ('en').
- Distinct outcomes: exact, approved_equivalent, review_required, mismatch, unavailable.
- Profile metadata preserved on DetailsMatchResult.
"""

import os
import pytest
from pydantic import ValidationError

from fayda_mcp.config import FaydaConfig
from fayda_mcp.context import CallerContext
from fayda_mcp.exceptions import AuthorizationError
from fayda_mcp.matching.profiles import (
    DEFAULT_MATCHING_PROFILE,
    DEFAULT_NAME_MATCHING_LANGUAGE,
    LANGUAGE_AMHARIC,
    LANGUAGE_ENGLISH,
    METHOD_EXACT_NORMALIZED,
    NAME_MATCH_APPROVED_EQUIVALENT,
    NAME_MATCH_EXACT,
    NAME_MATCH_MISMATCH,
    NAME_MATCH_REVIEW_REQUIRED,
    NAME_MATCH_UNAVAILABLE,
    PROFILE_ETHIOPIAN_NAME_V1,
    PROFILE_STRICT,
    PROFILES,
    SUPPORTED_MATCHING_PROFILES,
    SUPPORTED_NAME_MATCH_STATUSES,
    SUPPORTED_NAME_MATCHING_LANGUAGES,
    get_profile_spec,
    validate_matching_language,
    validate_matching_profile,
)
from fayda_mcp.matching.schemas import (
    DetailsMatchingError,
    DetailsMatchingErrorCode,
    ExpectedDetails,
    ExpectedDetailsRecord,
    StartDetailsVerificationRequest,
)
from fayda_mcp.matching.service import DetailsMatchingService
from fayda_mcp.policy import VerificationPolicy
from fayda_mcp.service import FaydaVerificationService
from fayda_mcp.storage.memory import MemoryResultRepository, MemorySessionStore


class TestMatchingProfileDefinitions:
    """Verifies core profile constants, specs, and supported languages."""

    def test_default_is_strict(self):
        """Strict matching must be the default profile."""
        assert DEFAULT_MATCHING_PROFILE == PROFILE_STRICT
        assert PROFILE_STRICT in SUPPORTED_MATCHING_PROFILES
        assert PROFILE_ETHIOPIAN_NAME_V1 in SUPPORTED_MATCHING_PROFILES

    def test_supported_languages(self):
        """Supported languages start with Amharic and Latin variants."""
        assert LANGUAGE_AMHARIC in SUPPORTED_NAME_MATCHING_LANGUAGES
        assert LANGUAGE_ENGLISH in SUPPORTED_NAME_MATCHING_LANGUAGES
        assert DEFAULT_NAME_MATCHING_LANGUAGE == LANGUAGE_AMHARIC

    def test_distinct_outcomes(self):
        """Outcomes must distinguish exact, approved_equivalent, review_required, mismatch, and unavailable."""
        assert NAME_MATCH_EXACT in SUPPORTED_NAME_MATCH_STATUSES
        assert NAME_MATCH_APPROVED_EQUIVALENT in SUPPORTED_NAME_MATCH_STATUSES
        assert NAME_MATCH_REVIEW_REQUIRED in SUPPORTED_NAME_MATCH_STATUSES
        assert NAME_MATCH_MISMATCH in SUPPORTED_NAME_MATCH_STATUSES
        assert NAME_MATCH_UNAVAILABLE in SUPPORTED_NAME_MATCH_STATUSES

    def test_profile_specs(self):
        """Inspects rules for strict vs ethiopian_name_v1 profiles."""
        strict_spec = get_profile_spec(PROFILE_STRICT)
        assert strict_spec.name == "strict"
        assert strict_spec.version == "details-v1"
        assert not strict_spec.allows_transliteration
        assert not strict_spec.allows_phonetics
        assert not strict_spec.requires_explicit_host_opt_in

        eth_spec = get_profile_spec(PROFILE_ETHIOPIAN_NAME_V1)
        assert eth_spec.name == "ethiopian_name_v1"
        assert eth_spec.version == "ethiopian_name_v1"
        assert eth_spec.allows_transliteration
        assert eth_spec.allows_phonetics
        assert eth_spec.requires_explicit_host_opt_in

    def test_unknown_profile_rejected(self):
        """Requesting an unknown profile spec raises ValueError."""
        with pytest.raises(ValueError, match="Unsupported matching profile"):
            get_profile_spec("unknown_profile")

        with pytest.raises(ValueError, match="Unsupported matching profile"):
            validate_matching_profile("unknown_profile")

    def test_unsupported_language_rejected(self):
        """Unsupported languages raise ValueError."""
        with pytest.raises(ValueError, match="Unsupported name matching language"):
            validate_matching_language("fr")


class TestHostOptInSchemas:
    """Verifies that host backend specifies matching profile on ExpectedDetails submission."""

    def test_expected_details_defaults_to_none_profile(self):
        """When not specified, profile is None (inherits host config default)."""
        details = ExpectedDetails(full_name="Abebe Bikila")
        assert details.matching_profile is None
        assert details.language is None

    def test_expected_details_explicit_ethiopian_profile(self):
        """Host explicitly opts in to ethiopian_name_v1."""
        details = ExpectedDetails(
            full_name="አበበ ቢቂላ",
            matching_profile="ethiopian_name_v1",
            language="am",
        )
        assert details.matching_profile == "ethiopian_name_v1"
        assert details.language == "am"

    def test_expected_details_rejects_invalid_profile(self):
        """Invalid profile in ExpectedDetails raises validation error."""
        with pytest.raises(ValidationError):
            ExpectedDetails(
                full_name="Abebe Bikila",
                matching_profile="custom_profile",
            )

    def test_expected_details_rejects_unsupported_language(self):
        """Unsupported language in ExpectedDetails raises validation error."""
        with pytest.raises(ValidationError):
            ExpectedDetails(
                full_name="Abebe Bikila",
                matching_profile="ethiopian_name_v1",
                language="de",
            )

    def test_agent_cannot_choose_matching_profile(self):
        """StartDetailsVerificationRequest (called by agent) forbids matching_profile."""
        with pytest.raises(ValidationError):
            StartDetailsVerificationRequest(
                expected_details_ref="edr_12345",
                purpose="onboarding",
                application_user_ref="user_1",
                idempotency_key="idemp_1",
                matching_profile="ethiopian_name_v1",  # type: ignore[call-arg]
            )


class TestHostConfigurationAndOptIn:
    """Verifies host configuration options and service enforcement."""

    def test_fayda_config_default_profile(self):
        """FaydaConfig defaults to strict profile."""
        config = FaydaConfig(
            client_id="test_client",
            redirect_uri="http://localhost/cb",
            issuer="https://esignet.example.com",
            authorization_endpoint="https://esignet.example.com/auth",
            token_endpoint="https://esignet.example.com/token",
            userinfo_endpoint="https://esignet.example.com/userinfo",
            jwks_uri="https://esignet.example.com/jwks",
        )
        assert config.name_matching_profile == "strict"
        assert "strict" in config.name_matching_allowed_profiles
        assert "ethiopian_name_v1" in config.name_matching_allowed_profiles
        assert config.name_matching_languages == ["am", "en"]

    def test_fayda_config_from_env_opt_in(self, monkeypatch):
        """Host opts in to ethiopian_name_v1 via environment variables."""
        monkeypatch.setenv("FAYDA_CLIENT_ID", "test_client")
        monkeypatch.setenv("FAYDA_REDIRECT_URI", "http://localhost/cb")
        monkeypatch.setenv("FAYDA_ISSUER", "https://esignet.example.com")
        monkeypatch.setenv("FAYDA_AUTHORIZATION_ENDPOINT", "https://esignet.example.com/auth")
        monkeypatch.setenv("FAYDA_TOKEN_ENDPOINT", "https://esignet.example.com/token")
        monkeypatch.setenv("FAYDA_USERINFO_ENDPOINT", "https://esignet.example.com/userinfo")
        monkeypatch.setenv("FAYDA_JWKS_URI", "https://esignet.example.com/jwks")
        monkeypatch.setenv("FAYDA_NAME_MATCHING_PROFILE", "ethiopian_name_v1")
        monkeypatch.setenv("FAYDA_NAME_MATCHING_ALLOWED_PROFILES", "strict,ethiopian_name_v1")
        monkeypatch.setenv("FAYDA_NAME_MATCHING_LANGUAGES", "am,en")

        config = FaydaConfig.from_env()
        assert config.name_matching_profile == "ethiopian_name_v1"
        assert config.name_matching_allowed_profiles == ["strict", "ethiopian_name_v1"]
        assert config.name_matching_languages == ["am", "en"]

    @pytest.mark.asyncio
    async def test_submit_defaults_to_strict(self):
        """Backend submission without explicit profile uses host default (strict)."""
        service = DetailsMatchingService(
            policy=VerificationPolicy(allowed_purposes=["onboarding"]),
        )
        ctx = CallerContext(scopes=["verification:create"])
        sub = await service.submit_expected_details(
            application_user_ref="user_101",
            purpose="onboarding",
            expected_details=ExpectedDetails(full_name="Abebe Bikila"),
            context=ctx,
        )
        record = await service.get_expected_details_record(sub.expected_details_ref, context=ctx)
        assert record.matching_profile == "strict"
        assert record.language is None

    @pytest.mark.asyncio
    async def test_submit_explicit_host_opt_in(self):
        """Host backend explicitly submits with ethiopian_name_v1 profile."""
        service = DetailsMatchingService(
            policy=VerificationPolicy(allowed_purposes=["onboarding"]),
        )
        ctx = CallerContext(scopes=["verification:create"])
        sub = await service.submit_expected_details(
            application_user_ref="user_102",
            purpose="onboarding",
            expected_details=ExpectedDetails(
                full_name="አበበ ቢቂላ",
                matching_profile="ethiopian_name_v1",
                language="am",
            ),
            context=ctx,
        )
        record = await service.get_expected_details_record(sub.expected_details_ref, context=ctx)
        assert record.matching_profile == "ethiopian_name_v1"
        assert record.language == "am"

    @pytest.mark.asyncio
    async def test_host_restriction_disallows_profile(self):
        """If host configuration restricts allowed profiles, unpermitted profile is rejected."""
        service = DetailsMatchingService(
            policy=VerificationPolicy(allowed_purposes=["onboarding"]),
            allowed_profiles=["strict"],  # Host explicitly disallows ethiopian_name_v1
        )
        ctx = CallerContext(scopes=["verification:create"])
        with pytest.raises(DetailsMatchingError) as exc_info:
            await service.submit_expected_details(
                application_user_ref="user_103",
                purpose="onboarding",
                expected_details=ExpectedDetails(
                    full_name="አበበ ቢቂላ",
                    matching_profile="ethiopian_name_v1",
                ),
                context=ctx,
            )
        assert exc_info.value.code == DetailsMatchingErrorCode.INVALID_EXPECTATIONS

    @pytest.mark.asyncio
    async def test_evaluate_preserves_profile_metadata(self):
        """DetailsMatchResult includes matching_profile, profile_version, and name_match_status."""
        service = DetailsMatchingService(
            policy=VerificationPolicy(allowed_purposes=["onboarding"]),
        )
        ctx = CallerContext(scopes=["verification:create"])
        sub = await service.submit_expected_details(
            application_user_ref="user_104",
            purpose="onboarding",
            expected_details=ExpectedDetails(full_name="Abebe Bikila"),
            context=ctx,
        )
        await service.bind_expected_details(
            ref=sub.expected_details_ref,
            request_id="req_match_104",
            application_user_ref="user_104",
            purpose="onboarding",
            context=ctx,
        )

        # Exact match under strict profile
        res_exact = await service.evaluate_details_for_request(
            request_id="req_match_104",
            claims={"name": "Abebe Bikila"},
        )
        assert res_exact.matching_profile == "strict"
        assert res_exact.profile_version == "details-v1"
        assert res_exact.name_match_status == NAME_MATCH_EXACT
        assert res_exact.name_match_method == METHOD_EXACT_NORMALIZED
        assert res_exact.matches["full_name"] is True
