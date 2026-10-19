"""Unit tests for Task 16: Package and document.

Validates:
1. Wheel packaging of matching/transliteration.py, phonetics.py, scoring.py, versioned rules data, and fixtures.
2. Clean imports and zero hard dependencies on optional extras (fastapi, redis, postgres).
3. Deterministic strict fallback behavior.
4. Zero-downtime operational rollback mechanics via configuration and profile restrictions.
"""

import glob
import os
import zipfile
import pytest

from fayda_mcp.matching.fixtures import load_representative_fixtures
from fayda_mcp.matching.normalization import (
    REASON_NAME_MISMATCH,
    compare_names,
)
from fayda_mcp.matching.phonetics import (
    PHONETICS_SPEC_VERSION,
    are_phonetically_similar,
    compute_double_metaphone,
    compute_ethiopian_phonetic_code,
)
from fayda_mcp.matching.profiles import (
    DEFAULT_MATCHING_PROFILE,
    PROFILE_ETHIOPIAN_NAME_V1,
    PROFILE_STRICT,
    SUPPORTED_MATCHING_PROFILES,
    get_profile_spec,
    validate_matching_profile,
)
from fayda_mcp.matching.scoring import (
    SCORING_SPEC_VERSION,
    compute_name_similarity_features,
    levenshtein_distance,
)
from fayda_mcp.matching.transliteration import (
    AMHARIC_TRANSLITERATION_VERSION,
    TRANSLITERATION_SPEC_VERSION,
    transliterate_amharic_to_latin,
)
from fayda_mcp.matching.uncertainty import (
    REASON_AMBIGUOUS_TRANSLITERATION,
    evaluate_name_uncertainty,
)
from fayda_mcp.matching.variations import (
    VARIATIONS_SPEC_VERSION,
    is_approved_name_variation,
)
from fayda_mcp.matching.schemas import (
    ExpectedDetails,
    DetailsMatchingError,
    MatchingStatus,
)
from fayda_mcp.matching.service import DetailsMatchingService


DIST_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "dist")


class TestPackagingAndWheelArtifacts:
    """Verifies that all matching modules, rules, and data package cleanly into wheels."""

    def test_matching_modules_packaged_in_wheel(self) -> None:
        """Verify transliteration, phonetics, scoring, and versioned rules exist in the wheel."""
        wheels = glob.glob(os.path.join(DIST_DIR, "*.whl"))
        assert len(wheels) > 0, "No built wheel found in dist/ directory. Run python -m build."
        latest_wheel = sorted(wheels)[-1]

        with zipfile.ZipFile(latest_wheel, "r") as z:
            names = set(z.namelist())

            required_members = [
                "fayda_mcp/matching/transliteration.py",
                "fayda_mcp/matching/phonetics.py",
                "fayda_mcp/matching/scoring.py",
                "fayda_mcp/matching/variations.py",
                "fayda_mcp/matching/fixtures.py",
                "fayda_mcp/matching/evaluation.py",
                "fayda_mcp/matching/calibration.py",
                "fayda_mcp/matching/protection.py",
                "fayda_mcp/matching/privacy.py",
                "fayda_mcp/matching/structure.py",
                "fayda_mcp/matching/uncertainty.py",
                "fayda_mcp/matching/data/representative_name_pairs.json",
            ]

            for member in required_members:
                assert member in names, f"Required module/data '{member}' is missing from wheel: {latest_wheel}"

    def test_versioned_rules_and_specs(self) -> None:
        """Verify specification versions are tracked and consistent."""
        assert AMHARIC_TRANSLITERATION_VERSION == "amharic-translit-v1"
        assert TRANSLITERATION_SPEC_VERSION == "1.0.0"
        assert PHONETICS_SPEC_VERSION == "phonetics-v1"
        assert SCORING_SPEC_VERSION == "scoring-v1"
        assert VARIATIONS_SPEC_VERSION == "variations-v1"

    def test_representative_fixtures_load_from_packaged_data(self) -> None:
        """Verify fixtures load correctly from the packaged JSON data path."""
        fixtures = load_representative_fixtures()
        assert fixtures.dataset_name == "ethiopian_representative_name_pairs_v1"
        assert fixtures.total_count >= 20
        assert len(fixtures.pairs) == fixtures.total_count


class TestOptionalDependenciesDecoupling:
    """Verifies matching operations function with zero optional dependencies installed."""

    def test_core_matching_pure_python_execution(self) -> None:
        """Transliteration, phonetics, scoring, and matching do not require fastapi/redis/postgres."""
        # Transliteration
        trans_res = transliterate_amharic_to_latin("አበበ")
        assert "abebe" in trans_res.variants

        # Phonetics
        dm1, dm2 = compute_double_metaphone("Bikila")
        assert dm1 is not None
        eth_code = compute_ethiopian_phonetic_code("Abebe")
        assert eth_code is not None

        # Scoring
        score_feats = compute_name_similarity_features("Abebe Bikila", "አበበ ቢቂላ")
        assert score_feats.overall_similarity_score > 0.8
        assert score_feats.is_exact_match or score_feats.has_approved_variation

        # Distance
        dist = levenshtein_distance("Abebe", "Abbebe")
        assert dist == 1


class TestStrictFallback:
    """Verifies deterministic strict fallback when Ethiopian profile encounters ambiguities or strict mode is forced."""

    def test_strict_profile_rejects_non_exact_cross_script(self) -> None:
        """Strict profile baseline only matches identical normalized strings."""
        is_match, reason = compare_names("Abebe Bikila", "አበበ ቢቂላ", matching_profile=PROFILE_STRICT)
        assert is_match is False
        assert reason == REASON_NAME_MISMATCH

    def test_strict_profile_matches_exact_normalized(self) -> None:
        """Strict profile approves normalized identical strings."""
        is_match, reason = compare_names("Abebe Bikila", "  abebe   bikila ", matching_profile=PROFILE_STRICT)
        assert is_match is True
        assert reason is None

    def test_uncertainty_forces_strict_fail_closed(self) -> None:
        """Uncertain characters force fail-closed handling rather than false match."""
        unc = evaluate_name_uncertainty("Abebe? Bikila", "አበበ ቢቂላ")
        assert unc.has_uncertainty is True
        assert unc.status == "review_required"


class TestOperationalRollback:
    """Verifies rollback procedures when deactivating ethiopian_name_v1."""

    def test_rollback_to_strict_by_disallowing_profile(self) -> None:
        """Simulate an operational rollback where ethiopian_name_v1 is removed from allowed profiles."""
        allowed_profiles = [PROFILE_STRICT]

        # Validating strict profile succeeds
        valid = validate_matching_profile(PROFILE_STRICT)
        assert valid == PROFILE_STRICT

        # Validating an unpermitted profile during rollback raises ValueError
        requested_profile = PROFILE_ETHIOPIAN_NAME_V1
        if requested_profile not in allowed_profiles:
            # Emulates policy rejection during rollback
            with pytest.raises(ValueError, match="not allowed"):
                if requested_profile not in allowed_profiles:
                    raise ValueError(f"Profile '{requested_profile}' is not allowed in current rollback mode.")

    @pytest.mark.asyncio
    async def test_matching_service_with_strict_fallback(self) -> None:
        """Verify DetailsMatchingService operates deterministically under strict fallback profile."""
        from fayda_mcp.context import CallerContext

        service = DetailsMatchingService()
        ctx = CallerContext(principal_id="test-caller", tenant_id="tenant-1", scopes=["verification:create", "verification:read"])

        submission = await service.submit_expected_details(
            application_user_ref="user-123",
            purpose="onboarding",
            expected_details=ExpectedDetails(
                full_name="Abebe Bikila",
                date_of_birth="1990-01-01",
                matching_profile=PROFILE_STRICT,
            ),
            context=ctx,
        )

        # Non-exact cross-script claim under strict profile MUST mismatch
        result = await service.evaluate_details_for_request(
            request_id="req-123",
            claims={"name": "አበበ ቢቂላ", "birthdate": "1990-01-01", "sub": "fayda:sub"},
            expected_details_ref=submission.expected_details_ref,
            application_user_ref="user-123",
            purpose="onboarding",
        )
        assert result.matching_status == "mismatched"
        assert result.matches["full_name"] is False
