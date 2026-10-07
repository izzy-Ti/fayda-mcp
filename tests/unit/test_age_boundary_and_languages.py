"""Comprehensive unit tests for L2: Age evaluation, anniversary boundaries, and regional languages."""

from datetime import date
from typing import Any, Dict
import pytest

from fayda_mcp.claims import calculate_age, evaluate_checks
from fayda_mcp.localization.languages import (
    SUPPORTED_LOCALES,
    extract_localized_claim,
    normalize_language_tag,
    select_localized_value,
)
from fayda_mcp.oidc.mapping import extract_localized_string, normalize_claims
from fayda_mcp.policy import VerificationPolicy


class TestAgeBoundaryAndAnniversaryRules:
    """Tests covering the day before, on, and after threshold birthdays."""

    def test_day_before_on_and_after_18th_birthday(self) -> None:
        """Citizen born 2000-05-15 turns 18 on 2018-05-15."""
        dob = "2000-05-15"

        # Day before
        day_before = date(2018, 5, 14)
        assert calculate_age(dob, as_of=day_before) == 17
        res_before = evaluate_checks({"birthdate": dob}, ["age_over_18"], as_of=day_before)
        assert res_before["age_over_18"] is False

        # On threshold birthday
        on_birthday = date(2018, 5, 15)
        assert calculate_age(dob, as_of=on_birthday) == 18
        res_on = evaluate_checks({"birthdate": dob}, ["age_over_18"], as_of=on_birthday)
        assert res_on["age_over_18"] is True

        # Day after
        day_after = date(2018, 5, 16)
        assert calculate_age(dob, as_of=day_after) == 18
        res_after = evaluate_checks({"birthdate": dob}, ["age_over_18"], as_of=day_after)
        assert res_after["age_over_18"] is True

    def test_day_before_on_and_after_21st_birthday(self) -> None:
        """Citizen born 2002-11-20 turns 21 on 2023-11-20."""
        dob = "2002-11-20"

        # Day before
        day_before = date(2023, 11, 19)
        assert calculate_age(dob, as_of=day_before) == 20
        res_before = evaluate_checks({"birthdate": dob}, ["age_over_21"], as_of=day_before)
        assert res_before["age_over_21"] is False

        # On threshold birthday
        on_birthday = date(2023, 11, 20)
        assert calculate_age(dob, as_of=on_birthday) == 21
        res_on = evaluate_checks({"birthdate": dob}, ["age_over_21"], as_of=on_birthday)
        assert res_on["age_over_21"] is True

        # Day after
        day_after = date(2023, 11, 21)
        assert calculate_age(dob, as_of=day_after) == 21
        res_after = evaluate_checks({"birthdate": dob}, ["age_over_21"], as_of=day_after)
        assert res_after["age_over_21"] is True

    def test_no_division_of_day_counts_by_365(self) -> None:
        """Verification must not divide total days by 365 or 365.25.

        In 18 years spanning 4 leap years (6574 days):
        On the day before the birthday, total days is 6573.
        6573 / 365 = 18.008, which naive 365 division would incorrectly count as age 18!
        """
        dob = "2000-01-01"
        day_before = date(2017, 12, 31)

        # Naive check: (day_before - dob).days // 365 would be 18
        naive_age = (day_before - date(2000, 1, 1)).days // 365
        assert naive_age == 18, "Sanity check on why day count division is flawed"

        # Correct exact calendar anniversary rule:
        assert calculate_age(dob, as_of=day_before) == 17
        res = evaluate_checks({"birthdate": dob}, ["age_over_18"], as_of=day_before)
        assert res["age_over_18"] is False


class TestFebruary29Handling:
    """Tests for leap day (February 29) anniversaries in common and leap years."""

    def test_feb_29_common_year_march_1_rule(self) -> None:
        """Born 2004-02-29. In 2022 (common year), turning 18 under 'march_1' default policy."""
        dob = "2004-02-29"

        # 2022-02-28: day before anniversary
        before = date(2022, 2, 28)
        assert calculate_age(dob, as_of=before, february_29_anniversary="march_1") == 17
        res_before = evaluate_checks(
            {"birthdate": dob}, ["age_over_18"], as_of=before, february_29_anniversary="march_1"
        )
        assert res_before["age_over_18"] is False

        # 2022-03-01: anniversary day
        on_anniv = date(2022, 3, 1)
        assert calculate_age(dob, as_of=on_anniv, february_29_anniversary="march_1") == 18
        res_on = evaluate_checks(
            {"birthdate": dob}, ["age_over_18"], as_of=on_anniv, february_29_anniversary="march_1"
        )
        assert res_on["age_over_18"] is True

        # 2022-03-02: day after
        after = date(2022, 3, 2)
        assert calculate_age(dob, as_of=after, february_29_anniversary="march_1") == 18

    def test_feb_29_common_year_february_28_rule(self) -> None:
        """Born 2004-02-29. In 2022 (common year), under 'february_28' policy."""
        dob = "2004-02-29"

        # 2022-02-27: day before
        before = date(2022, 2, 27)
        assert calculate_age(dob, as_of=before, february_29_anniversary="february_28") == 17

        # 2022-02-28: reaches age 18 under earlier-day rule
        on_anniv = date(2022, 2, 28)
        assert calculate_age(dob, as_of=on_anniv, february_29_anniversary="february_28") == 18
        res_on = evaluate_checks(
            {"birthdate": dob}, ["age_over_18"], as_of=on_anniv, february_29_anniversary="february_28"
        )
        assert res_on["age_over_18"] is True

    def test_feb_29_in_leap_year(self) -> None:
        """Born 2004-02-29. In 2024 (leap year), turning 20 on February 29."""
        dob = "2004-02-29"

        before = date(2024, 2, 28)
        assert calculate_age(dob, as_of=before) == 19

        on_leap_day = date(2024, 2, 29)
        assert calculate_age(dob, as_of=on_leap_day) == 20

        after = date(2024, 3, 1)
        assert calculate_age(dob, as_of=after) == 20


class TestMissingPartialAndAmbiguousDob:
    """Missing, partial, or ambiguous DOB must produce 'unavailable'."""

    def test_missing_dob_returns_unavailable(self) -> None:
        res = evaluate_checks({}, ["age_over_18"])
        assert res["age_over_18"] == "unavailable"

        res_none = evaluate_checks({"birthdate": None}, ["age_over_18"])
        assert res_none["age_over_18"] == "unavailable"

    def test_partial_dob_returns_unavailable(self) -> None:
        """Partial dates (YYYY-MM and 0000-MM-DD) do not contain sufficient day data for age evaluation."""
        assert calculate_age("1995-05") is None
        res_partial_month = evaluate_checks({"birthdate": "1995-05"}, ["age_over_18"])
        assert res_partial_month["age_over_18"] == "unavailable"

        assert calculate_age("0000-11-20") is None
        res_partial_year = evaluate_checks({"birthdate": "0000-11-20"}, ["age_over_18"])
        assert res_partial_year["age_over_18"] == "unavailable"

    def test_malformed_dob_returns_unavailable(self) -> None:
        assert calculate_age("invalid-date") is None
        res = evaluate_checks({"birthdate": "not-a-date"}, ["age_over_18"])
        assert res["age_over_18"] == "unavailable"


class TestPolicyTimezoneAndConfig:
    """Test policy definition of host timezone and leap-day handling."""

    def test_policy_defaults(self) -> None:
        pol = VerificationPolicy()
        assert pol.evaluation_timezone == "Africa/Addis_Ababa"
        assert pol.february_29_anniversary == "march_1"

    def test_calculate_age_default_timezone(self) -> None:
        """Default evaluation with as_of=None uses Africa/Addis_Ababa."""
        dob = "1990-01-01"
        age = calculate_age(dob, timezone_name="Africa/Addis_Ababa")
        assert age is not None
        assert age >= 34


class TestRegionalLanguageSelection:
    """Tests for regional languages (en, am, om, so, ti, sid, wal)."""

    def test_supported_locales_set(self) -> None:
        assert SUPPORTED_LOCALES == {"en", "am", "om", "so", "ti", "sid", "wal"}

    def test_provider_code_catalog_mapping(self) -> None:
        assert normalize_language_tag("amh") == "am"
        assert normalize_language_tag("eng") == "en"
        assert normalize_language_tag("orm") == "om"
        assert normalize_language_tag("oro") == "om"
        assert normalize_language_tag("som") == "so"
        assert normalize_language_tag("tir") == "ti"
        assert normalize_language_tag("tig") == "ti"
        assert normalize_language_tag("sid") == "sid"
        assert normalize_language_tag("wal") == "wal"
        assert normalize_language_tag("wol") == "wal"
        # BCP 47 subtags
        assert normalize_language_tag("am-ET") == "am"
        assert normalize_language_tag("en-US") == "en"
        assert normalize_language_tag("om-et") == "om"

    def test_preserve_unicode_and_no_transliteration(self) -> None:
        """Original Unicode text in Ethiopic or Latin script must be preserved exactly."""
        amharic_name = "አበበ ቢቂላ"
        assert select_localized_value(amharic_name) == amharic_name

        tigrinya_name = "ኣብርሃም"
        assert select_localized_value(tigrinya_name) == tigrinya_name

        oromo_name = "Caaltuu Gurmuu"
        assert select_localized_value(oromo_name) == oromo_name

    def test_localized_claim_keys(self) -> None:
        """Accept localized claim keys such as name#om, name#am, name#ti."""
        raw_claims = {
            "sub": "urn:fayda:user:1",
            "name#om": "Caaltuu",
            "name#am": "ጫልቱ",
            "name#en": "Chaltu",
        }
        # Preference: om
        extracted_om = extract_localized_claim(raw_claims, "name", preferred_locales=["om", "en"])
        assert extracted_om == "Caaltuu"

        # Preference: am
        extracted_am = extract_localized_claim(raw_claims, "name", preferred_locales=["am", "en"])
        assert extracted_am == "ጫልቱ"

        # Preference: en
        extracted_en = extract_localized_claim(raw_claims, "name", preferred_locales=["en"])
        assert extracted_en == "Chaltu"

    def test_localized_dictionary_and_list_payloads(self) -> None:
        """Accept dictionary or list eSignet structures."""
        # Dict payload
        dict_payload = {"en": "Almaz Ayana", "am": "አልማዝ አያና"}
        assert select_localized_value(dict_payload, preferred_locales=["am"]) == "አልማዝ አያና"
        assert select_localized_value(dict_payload, preferred_locales=["en"]) == "Almaz Ayana"

        # List payload
        list_payload = [
            {"@value": "Haile Gebrselassie", "@language": "eng"},
            {"@value": "ኃይሌ ገብረሥላሴ", "@language": "amh"},
        ]
        assert select_localized_value(list_payload, preferred_locales=["am"]) == "ኃይሌ ገብረሥላሴ"
        assert select_localized_value(list_payload, preferred_locales=["en"]) == "Haile Gebrselassie"

    def test_never_stringify_raw_object(self) -> None:
        """Never return raw dictionary representation as name."""
        raw = {"@unknown": "value"}
        result = select_localized_value(raw)
        assert result is None  # Does NOT return "{'@unknown': 'value'}"

    def test_normalize_claims_integration_with_languages(self) -> None:
        """normalize_claims selects language preference and strips non-selected tags."""
        raw_claims: Dict[str, Any] = {
            "sub": "12345",
            "name#ti": "ተስፋይ",
            "name#en": "Tesfay",
            "name": "Tesfay",
            "birthdate": "1998-04-20",
        }
        normalized = normalize_claims(raw_claims, preferred_locales=["ti", "en"])
        assert normalized["name"] == "ተስፋይ"
        assert "name#ti" not in normalized
        assert "name#en" not in normalized
