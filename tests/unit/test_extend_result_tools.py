"""Unit tests for extending existing result tools with name match metadata (guide5 Task 12).

Verifies:
- DetailsMatchResult includes name_match_status, method, reason, and profile_version.
- Phonetic-only review keeps matches.full_name=null (None in Python).
- FastMCP tool get_details_match_result returns all extended fields.
"""

import json
import pytest

from fayda_mcp.matching.profiles import (
    METHOD_APPROVED_VARIATION,
    METHOD_EXACT_NORMALIZED,
    METHOD_PHONETIC,
    METHOD_TRANSLITERATION,
    NAME_MATCH_APPROVED_EQUIVALENT,
    NAME_MATCH_EXACT,
    NAME_MATCH_MISMATCH,
    NAME_MATCH_REVIEW_REQUIRED,
    PROFILE_ETHIOPIAN_NAME_V1,
    PROFILE_STRICT,
)
from fayda_mcp.matching.schemas import DetailsMatchResult, ExpectedDetails
from fayda_mcp.matching.service import DetailsMatchingService
from fayda_mcp.matching.storage import MemoryExpectedDetailsStore
from fayda_mcp.service import FaydaVerificationService


class TestDetailsMatchResultSchemaExtension:
    """Tests for DetailsMatchResult schema extension with name matching metadata."""

    def test_schema_includes_extended_fields(self):
        res = DetailsMatchResult(
            request_id="req_schema_test",
            matching_status="matched",
            matches={"full_name": True},
            matching_profile=PROFILE_ETHIOPIAN_NAME_V1,
            profile_version="ethiopian_name_v1",
            name_match_status=NAME_MATCH_EXACT,
            name_match_method=METHOD_EXACT_NORMALIZED,
            name_match_reason=None,
        )

        assert res.name_match_status == NAME_MATCH_EXACT
        assert res.name_match_method == METHOD_EXACT_NORMALIZED
        assert res.method == METHOD_EXACT_NORMALIZED
        assert res.profile_version == "ethiopian_name_v1"
        assert res.matches["full_name"] is True

        # JSON serialization test
        dumped = json.loads(res.model_dump_json())
        assert dumped["name_match_status"] == "exact"
        assert dumped["method"] == "exact_normalized"
        assert dumped["profile_version"] == "ethiopian_name_v1"

    def test_phonetic_only_review_keeps_matches_full_name_null(self):
        res = DetailsMatchResult(
            request_id="req_phonetic_null",
            matching_status="unavailable",
            matches={"full_name": None},  # null in JSON
            matching_profile=PROFILE_ETHIOPIAN_NAME_V1,
            profile_version="ethiopian_name_v1",
            name_match_status=NAME_MATCH_REVIEW_REQUIRED,
            name_match_method=METHOD_PHONETIC,
            name_match_reason="phonetic_only_agreement",
            reasons={"full_name": "phonetic_only_agreement"},
        )

        assert res.matches["full_name"] is None
        assert res.name_match_status == NAME_MATCH_REVIEW_REQUIRED
        assert res.method == METHOD_PHONETIC
        assert res.reason == "phonetic_only_agreement"

        dumped = json.loads(res.model_dump_json())
        assert dumped["matches"]["full_name"] is None  # serializes to JSON null
        assert dumped["name_match_status"] == "review_required"
        assert dumped["method"] == "phonetic"
        assert dumped["reason"] == "phonetic_only_agreement"


@pytest.mark.asyncio
class TestServiceEvaluationExtendedFields:
    """Tests for DetailsMatchingService producing extended fields across match types."""

    async def test_exact_normalized_match_metadata(self):
        store = MemoryExpectedDetailsStore()
        service = DetailsMatchingService(store=store)

        resp = await service.submit_expected_details(
            application_user_ref="usr_ext_01",
            purpose="kyc",
            expected_details=ExpectedDetails(
                full_name="Abebe Bikila",
                matching_profile=PROFILE_ETHIOPIAN_NAME_V1,
            ),
        )
        await service.bind_expected_details(
            ref=resp.expected_details_ref,
            request_id="req_ext_01",
            application_user_ref="usr_ext_01",
            purpose="kyc",
        )

        res = await service.evaluate_details_for_request(
            request_id="req_ext_01",
            claims={"name": "Abebe Bikila"},
        )

        assert res.name_match_status == NAME_MATCH_EXACT
        assert res.method == METHOD_EXACT_NORMALIZED
        assert res.profile_version == "ethiopian_name_v1"
        assert res.matches["full_name"] is True

    async def test_approved_variation_match_metadata(self):
        store = MemoryExpectedDetailsStore()
        service = DetailsMatchingService(store=store)

        resp = await service.submit_expected_details(
            application_user_ref="usr_ext_02",
            purpose="kyc",
            expected_details=ExpectedDetails(
                full_name="Abebe Bikila",
                matching_profile=PROFILE_ETHIOPIAN_NAME_V1,
            ),
        )
        await service.bind_expected_details(
            ref=resp.expected_details_ref,
            request_id="req_ext_02",
            application_user_ref="usr_ext_02",
            purpose="kyc",
        )

        res = await service.evaluate_details_for_request(
            request_id="req_ext_02",
            claims={"name": "Abbebe Biqila"},
        )

        assert res.name_match_status == NAME_MATCH_APPROVED_EQUIVALENT
        assert res.method == METHOD_APPROVED_VARIATION
        assert res.profile_version == "ethiopian_name_v1"
        assert res.matches["full_name"] is True

    async def test_transliteration_match_metadata(self):
        store = MemoryExpectedDetailsStore()
        service = DetailsMatchingService(store=store)

        resp = await service.submit_expected_details(
            application_user_ref="usr_ext_03",
            purpose="kyc",
            expected_details=ExpectedDetails(
                full_name="አበበ ቢቂላ",
                matching_profile=PROFILE_ETHIOPIAN_NAME_V1,
                language="am",
            ),
        )
        await service.bind_expected_details(
            ref=resp.expected_details_ref,
            request_id="req_ext_03",
            application_user_ref="usr_ext_03",
            purpose="kyc",
        )

        res = await service.evaluate_details_for_request(
            request_id="req_ext_03",
            claims={"name": "Abebe Bikila"},
        )

        assert res.name_match_status == NAME_MATCH_APPROVED_EQUIVALENT
        assert res.method == METHOD_TRANSLITERATION
        assert res.profile_version == "ethiopian_name_v1"
        assert res.matches["full_name"] is True

    async def test_phonetic_only_review_metadata_and_null_outcome(self):
        store = MemoryExpectedDetailsStore()
        service = DetailsMatchingService(store=store)

        resp = await service.submit_expected_details(
            application_user_ref="usr_ext_04",
            purpose="kyc",
            expected_details=ExpectedDetails(
                full_name="Abebe Bekile",
                matching_profile=PROFILE_ETHIOPIAN_NAME_V1,
            ),
        )
        await service.bind_expected_details(
            ref=resp.expected_details_ref,
            request_id="req_ext_04",
            application_user_ref="usr_ext_04",
            purpose="kyc",
        )

        res = await service.evaluate_details_for_request(
            request_id="req_ext_04",
            claims={"name": "Abebe Bekele"},
        )

        # Phonetic-only review keeps matches.full_name=null (None)
        assert res.matches["full_name"] is None
        assert res.name_match_status == NAME_MATCH_REVIEW_REQUIRED
        assert res.method == METHOD_PHONETIC
        assert res.reason == "phonetic_only_agreement"
        assert res.profile_version == "ethiopian_name_v1"
        assert res.matching_status == "unavailable"
