"""Comprehensive unit tests for L3: Provider language mapping and BCP 47 normalization.

Validates:
- Case-insensitive BCP 47 normalization and subtag preservation (scripts, regions).
- Provider-specific code catalog mapping (amh, eng, orm/oro, som, tir/tig, sid, wal/wol).
- Strict resolution order: Exact preference -> Primary language -> Configured fallback -> Untagged field.
- Localized keys (name#om), dictionary/list payloads, and all seven regional language targets.
- Unknown tags, malformed values, and prevention of object stringification.
- Transient demographics rule: verification results never expose raw names or residency to agents.
"""

import json
from pathlib import Path
from typing import Any, Dict
import pytest

from fayda_mcp.localization.languages import (
    PROVIDER_LANGUAGE_CATALOG,
    SUPPORTED_LOCALES,
    extract_localized_claim,
    normalize_language_tag,
    parse_bcp47,
    select_localized_value,
)
from fayda_mcp.oidc.mapping import normalize_claims
from fayda_mcp.schemas import VerificationResult


@pytest.fixture
def fixtures_data() -> dict:
    fixture_path = Path(__file__).parent.parent / "fixtures" / "localized_claims_fixtures.json"
    with open(fixture_path, "r", encoding="utf-8") as f:
        return json.load(f)


class TestBcp47NormalizationAndCatalog:
    """Test BCP 47 case-insensitivity, subtag preservation, and provider code catalog."""

    def test_case_insensitivity(self) -> None:
        assert normalize_language_tag("EN") == "en"
        assert normalize_language_tag("en-us") == "en-US"
        assert normalize_language_tag("EN-US") == "en-US"
        assert normalize_language_tag("am_et") == "am-ET"
        assert normalize_language_tag("AM-ET") == "am-ET"

    def test_preserve_valid_subtags_scripts_and_regions(self) -> None:
        """Script in Titlecase, Region in UPPERCASE."""
        canon, primary = parse_bcp47("om-latn-et")  # type: ignore
        assert canon == "om-Latn-ET"
        assert primary == "om"

        canon_ti, primary_ti = parse_bcp47("ti-ethi-er")  # type: ignore
        assert canon_ti == "ti-Ethi-ER"
        assert primary_ti == "ti"

        canon_gb, primary_gb = parse_bcp47("en-gb")  # type: ignore
        assert canon_gb == "en-GB"
        assert primary_gb == "en"

    def test_provider_code_catalog(self) -> None:
        """Provider codes map strictly through the explicit catalog."""
        # Amharic
        assert normalize_language_tag("amh") == "am"
        assert normalize_language_tag("amh-ET") == "am-ET"
        # English
        assert normalize_language_tag("eng") == "en"
        assert normalize_language_tag("eng-US") == "en-US"
        # Afaan Oromoo
        assert normalize_language_tag("orm") == "om"
        assert normalize_language_tag("oro") == "om"
        assert normalize_language_tag("orm-Latn-ET") == "om-Latn-ET"
        # Somali
        assert normalize_language_tag("som") == "so"
        assert normalize_language_tag("som-ET") == "so-ET"
        # Tigrinya
        assert normalize_language_tag("tir") == "ti"
        assert normalize_language_tag("tig") == "ti"
        assert normalize_language_tag("tir-ER") == "ti-ER"
        # Sidama
        assert normalize_language_tag("sid") == "sid"
        assert normalize_language_tag("sid-ET") == "sid-ET"
        # Wolaytta
        assert normalize_language_tag("wal") == "wal"
        assert normalize_language_tag("wol") == "wal"
        assert normalize_language_tag("wal-ET") == "wal-ET"


class TestResolutionOrder:
    """Validate exact order: Exact preference -> Primary language -> Configured fallback -> Untagged field."""

    def test_step_1_exact_preference_match(self) -> None:
        """Exact preference matches specific regional dialect."""
        payload = [
            {"@value": "Color", "@language": "en-US"},
            {"@value": "Colour", "@language": "en-GB"},
        ]
        # Prefer en-GB
        assert select_localized_value(payload, preferred_locales=["en-GB"]) == "Colour"
        # Prefer en-US
        assert select_localized_value(payload, preferred_locales=["en-US"]) == "Color"

    def test_step_2_primary_language_match(self) -> None:
        """When specific dialect is absent, match primary language."""
        payload = [
            {"@value": "Color", "@language": "en-US"},
            {"@value": "ቀለም", "@language": "am-ET"},
        ]
        # Prefer en-CA (Canadian English not in payload; matches en-US via primary 'en')
        assert select_localized_value(payload, preferred_locales=["en-CA"]) == "Color"

        # Prefer am (matches am-ET via primary 'am')
        assert select_localized_value(payload, preferred_locales=["am"]) == "ቀለም"

    def test_step_3_configured_fallback(self) -> None:
        """When preferred language is absent, use configured fallback locale."""
        payload = [
            {"@value": "Abebe", "@language": "en-US"},
            {"@value": "አበበ", "@language": "am-ET"},
        ]
        # Prefer Oromo (not in payload); fallback is English
        assert (
            select_localized_value(
                payload, preferred_locales=["om"], fallback_locale="en"
            )
            == "Abebe"
        )
        # Prefer Tigrinya (not in payload); fallback is Amharic
        assert (
            select_localized_value(
                payload, preferred_locales=["ti"], fallback_locale="am"
            )
            == "አበበ"
        )

    def test_step_4_untagged_field(self) -> None:
        """When preference and fallback do not match, use untagged field."""
        payload = {
            "so": "Maxamed",
            "ti": "ኣብርሃም",
            "default": "Default Name",
        }
        # Prefer Oromo, fallback English (neither in dict); falls back to untagged 'default'
        assert (
            select_localized_value(
                payload, preferred_locales=["om"], fallback_locale="en"
            )
            == "Default Name"
        )


class TestPayloadFormatsAndAllSevenTargets:
    """Test localized keys, dictionary/list payloads, and all seven languages."""

    def test_all_seven_language_targets(self, fixtures_data: dict) -> None:
        """Verify each of the 7 languages selects correctly from provider codes and Unicode."""
        fixtures = fixtures_data["regional_language_fixtures"]
        assert len(fixtures) == 7

        for f in fixtures:
            lang = f["language"]
            expected_name = f["name_unicode"]
            payload = f["payload_dict"]

            # Direct dictionary selection
            selected = select_localized_value(payload, preferred_locales=[lang])
            assert selected == expected_name, f"Failed selecting language {lang}"

            # Claim extraction with localized key
            claims_dict = {f["localized_key"]: expected_name, "sub": "123"}
            extracted = extract_localized_claim(claims_dict, "name", preferred_locales=[lang])
            assert extracted == expected_name, f"Failed extracting claim key for {lang}"

    def test_localized_claim_keys_preference(self) -> None:
        """Test claim dictionary containing multiple localized keys."""
        claims = {
            "sub": "user-1",
            "name#om": "Caaltuu",
            "name#am": "ጫልቱ",
            "name#ti": "ቻልቱ",
            "name#en": "Chaltu",
            "name": "Chaltu Generic",
        }
        assert extract_localized_claim(claims, "name", preferred_locales=["om"]) == "Caaltuu"
        assert extract_localized_claim(claims, "name", preferred_locales=["am"]) == "ጫልቱ"
        assert extract_localized_claim(claims, "name", preferred_locales=["ti"]) == "ቻልቱ"
        assert extract_localized_claim(claims, "name", preferred_locales=["en"]) == "Chaltu"


class TestUnknownTagsAndMalformedValues:
    """Test safety: unknown tags, malformed values, and no raw object stringification."""

    def test_unknown_language_tags(self) -> None:
        payload = {
            "klingon": "tlhIngan",
            "xx-YY": "unrecognized",
            "en": "Standard English",
        }
        # Unknown tags do not hijack standard English fallback
        assert (
            select_localized_value(
                payload, preferred_locales=["am"], fallback_locale="en"
            )
            == "Standard English"
        )

    def test_never_stringify_raw_objects(self, fixtures_data: dict) -> None:
        """Never return raw dictionary representation as name."""
        for malformed in fixtures_data["malformed_payloads"]:
            val = malformed.get("name")
            res = select_localized_value(val)
            # Must be None or a clean string, NEVER a stringified dict
            assert res is None or not (res.startswith("{") and res.endswith("}"))

        # Explicit test with nested dict
        nested_raw = {"@value": {"first": "Abebe", "last": "Bikila"}, "@language": "en"}
        assert select_localized_value(nested_raw) is None

    def test_empty_and_whitespace_values_ignored(self) -> None:
        payload = {"am": "   ", "en": "Valid Name"}
        assert (
            select_localized_value(payload, preferred_locales=["am"], fallback_locale="en")
            == "Valid Name"
        )


class TestTransientDemographicsAndPrivacyBoundary:
    """Verify demographics (names, DOB) are kept transient and never exposed in agent results."""

    def test_result_schema_does_not_contain_names_or_demographics(self) -> None:
        """VerificationResult schema must only expose safe predicates, not citizen names."""
        result = VerificationResult(
            request_id="req-123",
            status="verified",
            checks={"identity_verified": True, "age_over_18": True},
            policy_version="v1",
            evidence_ref="evidence-456",
            verified_at="2026-10-07T12:00:00Z",
            expires_at="2026-10-07T12:15:00Z",
        )
        res_dict = result.model_dump()
        assert "name" not in res_dict
        assert "birthdate" not in res_dict
        assert "dob" not in res_dict
        assert "residency" not in res_dict
        assert res_dict["checks"] == {"identity_verified": True, "age_over_18": True}

    def test_normalize_claims_preserves_unicode_without_transliteration(self) -> None:
        raw = {
            "sub": "user-999",
            "name#am": "አበበ ቢቂላ",
            "name#om": "Caaltuu Gurmuu",
        }
        normalized = normalize_claims(raw, preferred_locales=["am"])
        assert normalized["name"] == "አበበ ቢቂላ"
        # Check that Amharic characters remain untransliterated Ge'ez
        assert "አበበ" in normalized["name"]
