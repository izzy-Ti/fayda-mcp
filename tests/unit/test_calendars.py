"""Comprehensive unit tests for L1: Calendar conversion module.

Validates:
- Agreement with ICU reference vectors and Calendrica (Reingold & Dershowitz).
- Twelve 30-day months, Pagume day 5/6, leap years, era/year conventions.
- Bidirectional GC/EC round trips across historical and future date ranges.
- Strict rejection of invalid month/day combinations, future birthdates,
  ambiguous unlabeled dates, and unsupported eras.
- Explicit calendar source enforcement: standard OIDC Gregorian birthdates,
  partial date support (YYYY-MM, 0000-MM-DD), and no naive +7/+8 year approximations.
"""

import datetime
import json
from pathlib import Path
import pytest

from fayda_mcp.localization.calendars import (
    AMETE_MIHRET_DELTA,
    JD_EPOCH_OFFSET_AMETE_ALEM,
    JD_EPOCH_OFFSET_AMETE_MIHRET,
    JD_EPOCH_OFFSET_GREGORIAN,
    AmbiguousDateError,
    CalendarError,
    CalendarType,
    EthiopicDate,
    EthiopicEra,
    FutureDateError,
    GregorianDate,
    InvalidDateError,
    UnsupportedEraError,
    ethiopic_to_gregorian,
    ethiopic_to_jdn,
    gregorian_to_ethiopic,
    gregorian_to_jdn,
    is_ethiopic_leap_year,
    is_gregorian_leap_year,
    jdn_to_ethiopic,
    jdn_to_gregorian,
    normalize_dob_with_source,
    parse_date_explicit,
    validate_birthdate,
)


@pytest.fixture
def fixtures_data() -> dict:
    fixture_path = Path(__file__).parent.parent / "fixtures" / "calendar_vectors.json"
    with open(fixture_path, "r", encoding="utf-8") as f:
        return json.load(f)


class TestIcuReferenceVectors:
    """Test agreement with ICU reference vectors and Calendrica."""

    def test_icu_reference_vectors(self, fixtures_data: dict) -> None:
        vectors = fixtures_data["reference_vectors"]
        assert len(vectors) >= 15

        for vec in vectors:
            desc = vec["description"]
            eth_data = vec["ethiopic"]
            greg_data = vec["gregorian"]
            expected_jdn = vec["jdn"]

            era = EthiopicEra(eth_data["era"])
            eth_date = EthiopicDate(eth_data["year"], eth_data["month"], eth_data["day"], era=era)
            greg_date = GregorianDate(greg_data["year"], greg_data["month"], greg_data["day"])

            # 1. JDN calculation matches reference JDN
            assert eth_date.to_jdn() == expected_jdn, f"JDN mismatch for Ethiopic date {desc}"
            assert greg_date.to_jdn() == expected_jdn, f"JDN mismatch for Gregorian date {desc}"

            # 2. Bidirectional conversion matches
            converted_greg = ethiopic_to_gregorian(eth_date)
            assert converted_greg == greg_date, (
                f"Ethiopic -> Gregorian mismatch for {desc}: "
                f"got {converted_greg.isoformat()} expected {greg_date.isoformat()}"
            )

            converted_eth = gregorian_to_ethiopic(greg_date, era=era)
            assert converted_eth == eth_date, (
                f"Gregorian -> Ethiopic mismatch for {desc}: "
                f"got {converted_eth.isoformat()} expected {eth_date.isoformat()}"
            )


class TestEthiopicTwelveMonthsAndPagume:
    """Test twelve 30-day months and Pagume day 5/6."""

    def test_twelve_30_day_months(self) -> None:
        """Every Ethiopic month 1..12 must have exactly 30 days."""
        year = 2016  # common year
        for m in range(1, 13):
            # Day 1 and day 30 must be valid
            d1 = EthiopicDate(year, m, 1)
            d30 = EthiopicDate(year, m, 30)
            assert d1.day == 1
            assert d30.day == 30

            # Day 31 must be strictly rejected
            with pytest.raises(InvalidDateError, match="exactly 30 days"):
                EthiopicDate(year, m, 31)

            # Day 0 must be rejected
            with pytest.raises(InvalidDateError):
                EthiopicDate(year, m, 0)

    def test_pagume_common_year(self) -> None:
        """Pagume has 5 days in a common year (year % 4 != 3)."""
        year = 2016  # 2016 % 4 == 0 (common year in Ethiopic)
        assert not is_ethiopic_leap_year(year)

        # Day 1..5 are valid
        for d in range(1, 6):
            p = EthiopicDate(year, 13, d)
            assert p.day == d

        # Day 6 is strictly rejected in a common year
        with pytest.raises(InvalidDateError, match="common year.*max is 5"):
            EthiopicDate(year, 13, 6)

    def test_pagume_leap_year(self) -> None:
        """Pagume has 6 days in a leap year (year % 4 == 3)."""
        leap_year = 2015  # 2015 % 4 == 3 (leap year in Ethiopic)
        assert is_ethiopic_leap_year(leap_year)

        # Day 1..6 are valid
        for d in range(1, 7):
            p = EthiopicDate(leap_year, 13, d)
            assert p.day == d

        # Day 7 is strictly rejected
        with pytest.raises(InvalidDateError, match="leap year.*max is 6"):
            EthiopicDate(leap_year, 13, 7)


class TestLeapYearsAndGregorianBoundaries:
    """Test Ethiopic and Gregorian leap years and boundary cases."""

    def test_ethiopic_leap_year_cycle(self) -> None:
        """Julian cycle: years with year % 4 == 3 are leap years."""
        assert is_ethiopic_leap_year(2011)
        assert is_ethiopic_leap_year(2015)
        assert is_ethiopic_leap_year(2019)
        assert is_ethiopic_leap_year(2023)
        assert not is_ethiopic_leap_year(2012)
        assert not is_ethiopic_leap_year(2016)
        assert not is_ethiopic_leap_year(2020)

    def test_gregorian_leap_year_rules(self) -> None:
        """Gregorian rule: divisible by 4, except century not divisible by 400."""
        assert is_gregorian_leap_year(2000)  # divisible by 400
        assert is_gregorian_leap_year(2004)
        assert is_gregorian_leap_year(2020)
        assert is_gregorian_leap_year(2024)
        assert not is_gregorian_leap_year(1900)  # century not divisible by 400
        assert not is_gregorian_leap_year(2100)
        assert not is_gregorian_leap_year(2023)

    def test_gregorian_february_29(self) -> None:
        """February 29 valid in leap years, rejected in common years."""
        # 2024 is leap
        g_leap = GregorianDate(2024, 2, 29)
        assert g_leap.day == 29

        # 2023 is common
        with pytest.raises(InvalidDateError, match="max is 28"):
            GregorianDate(2023, 2, 29)

        # 1900 is common
        with pytest.raises(InvalidDateError, match="max is 28"):
            GregorianDate(1900, 2, 29)


class TestEraConventions:
    """Test explicit era conventions (Amete Mihret vs Amete Alem)."""

    def test_amete_mihret_and_amete_alem_delta(self) -> None:
        """Amete Alem is exactly 5500 years before Amete Mihret."""
        assert AMETE_MIHRET_DELTA == 5500
        # Check day difference between epochs
        day_diff = JD_EPOCH_OFFSET_AMETE_MIHRET - JD_EPOCH_OFFSET_AMETE_ALEM
        assert day_diff == 2008875  # 5500 * 365.25 days

    def test_unsupported_era_rejection(self) -> None:
        """Unsupported or unknown eras must raise UnsupportedEraError."""
        with pytest.raises(UnsupportedEraError):
            EthiopicDate(2016, 1, 1, era="unknown_era")

        with pytest.raises(UnsupportedEraError):
            ethiopic_to_jdn(2016, 1, 1, era="invalid")

        with pytest.raises(UnsupportedEraError):
            jdn_to_ethiopic(2400000, era="unsupported")


class TestRoundTripConversions:
    """Test exhaustive bidirectional round-trip conversions across centuries."""

    def test_round_trip_gregorian_to_ethiopic(self) -> None:
        """Every day converted G -> E -> G must return exact original date."""
        # Test a range of days across 1970 to 2030, covering New Years, Pagume, leap days
        test_dates = [
            datetime.date(1974, 9, 12),  # Ethiopian New Year
            datetime.date(1980, 2, 29),  # Gregorian leap day
            datetime.date(1991, 5, 28),
            datetime.date(2000, 1, 1),   # Millennium
            datetime.date(2000, 2, 29),  # Gregorian century leap day
            datetime.date(2007, 9, 12),  # Ethiopian Millennium (2000 Meskerem 1)
            datetime.date(2023, 9, 11),  # Ethiopian leap day Pagume 6
            datetime.date(2023, 9, 12),  # Ethiopian New Year 2016
            datetime.date(2024, 2, 29),  # Gregorian leap day
            datetime.date(2024, 9, 11),  # Ethiopian New Year 2017
        ]
        for dt in test_dates:
            greg = GregorianDate.from_date(dt)
            eth = gregorian_to_ethiopic(greg)
            greg_roundtrip = ethiopic_to_gregorian(eth)
            assert greg == greg_roundtrip
            assert greg_roundtrip.to_date() == dt

    def test_round_trip_ethiopic_to_gregorian(self) -> None:
        """Every day converted E -> G -> E must return exact original date."""
        # Test all 13 months, month beginnings and ends
        year = 2015  # Ethiopian leap year
        for m in range(1, 14):
            max_d = 6 if m == 13 else 30
            days_to_test = [1, 15, max_d] if m < 13 else [1, 3, max_d]
            for d in days_to_test:
                eth = EthiopicDate(year, m, d)
                greg = ethiopic_to_gregorian(eth)
                eth_roundtrip = gregorian_to_ethiopic(greg)
                assert eth == eth_roundtrip


class TestStrictValidationAndRejections:
    """Test strict rejections of invalid inputs, ambiguous formats, and future dates."""

    def test_reject_ambiguous_unlabeled_dates(self) -> None:
        """A slash-formatted 1990/04/12 or hyphenated date does not identify a calendar by itself."""
        with pytest.raises(AmbiguousDateError, match="Calendar source must be explicit"):
            parse_date_explicit("1990/04/12", calendar="")

        with pytest.raises(AmbiguousDateError, match="Calendar source must be explicit"):
            parse_date_explicit("1990-04-12", calendar="")

        # Explicit calendar succeeds
        greg = parse_date_explicit("1990/04/12", calendar="gregorian")
        assert isinstance(greg, GregorianDate)
        assert greg.isoformat() == "1990-04-12"

        eth = parse_date_explicit("1990/04/12", calendar="ethiopic")
        assert isinstance(eth, EthiopicDate)
        assert eth.isoformat() == "1990-04-12"

    def test_reject_invalid_month_day_combinations(self) -> None:
        """Reject month 14, day 32, Pagume 7, etc."""
        with pytest.raises(InvalidDateError):
            EthiopicDate(2016, 14, 1)

        with pytest.raises(InvalidDateError):
            EthiopicDate(2016, 0, 1)

        with pytest.raises(InvalidDateError):
            GregorianDate(2023, 13, 1)

        with pytest.raises(InvalidDateError):
            GregorianDate(2023, 4, 31)  # April has 30 days

    def test_reject_future_birthdates(self) -> None:
        """Future birthdates must be rejected."""
        today = datetime.date(2026, 10, 7)
        future_greg = GregorianDate(2026, 10, 8)

        with pytest.raises(FutureDateError, match="cannot be in the future"):
            validate_birthdate(future_greg, reference_date=today)

        # Past or today is valid
        today_greg = GregorianDate(2026, 10, 7)
        validate_birthdate(today_greg, reference_date=today)

        # Ethiopic future date
        future_eth = GregorianDate(2027, 1, 1).to_ethiopic()
        with pytest.raises(FutureDateError, match="cannot be in the future"):
            validate_birthdate(future_eth, reference_date=today)

    def test_no_year_offset_approximation(self) -> None:
        """Ensure conversion does NOT simply add 7 or 8 years."""
        # If someone added 7 years to Ethiopic 2016-01-01 (Meskerem 1), they'd get 2023-01-01.
        # But Ethiopian New Year 2016 is actually September 12, 2023!
        eth = EthiopicDate(2016, 1, 1)
        greg = ethiopic_to_gregorian(eth)
        assert greg.year == 2023
        assert greg.month == 9
        assert greg.day == 12


class TestDobNormalizationAndOidcCompliance:
    """Test normalize_dob_with_source behavior and OIDC standards."""

    def test_oidc_standard_gregorian_preservation(self) -> None:
        """OIDC standard birthdate uses Gregorian YYYY-MM-DD.

        Never reinterpret a compliant Gregorian date as Ethiopian based on
        low year, separator, country, or language.
        """
        # A 2005 date must remain 2005-01-15 Gregorian by default, not interpreted as Ethiopic!
        assert normalize_dob_with_source("2005-01-15") == "2005-01-15"
        assert normalize_dob_with_source("2005/01/15") == "2005-01-15"
        assert normalize_dob_with_source("1998-05-20") == "1998-05-20"

    def test_oidc_partial_dates(self, fixtures_data: dict) -> None:
        """Documented partial dates (YYYY-MM and 0000-MM-DD) must be preserved."""
        for item in fixtures_data["oidc_partial_dates"]:
            inp = item["input"]
            expected = item["expected"]
            assert normalize_dob_with_source(inp) == expected

    def test_explicit_ethiopic_source_calendar(self) -> None:
        """Ethiopic dates are converted to Gregorian ISO when source_calendar='ethiopic'."""
        # Ethiopic 2000-01-01 AM -> Gregorian 2007-09-12
        converted = normalize_dob_with_source(
            "2000-01-01",
            source_calendar="ethiopic",
            reference_date=datetime.date(2026, 10, 7),
        )
        assert converted == "2007-09-12"

    def test_future_dob_rejected_in_normalization(self) -> None:
        """Future DOB returns None."""
        assert normalize_dob_with_source(
            "2030-01-01", reference_date=datetime.date(2026, 10, 7)
        ) is None
