"""Strict Ethiopian and Gregorian calendar conversion and validation module.

Implements bidirectional conversion through an absolute Julian Day Number (JDN)
representation matching ICU (International Components for Unicode) reference vectors
and Calendrica specifications (Reingold & Dershowitz).

Calendar source must be explicit:
- Standard OIDC birthdate is Gregorian YYYY-MM-DD (including documented partial dates).
- Never reinterpret compliant Gregorian dates based on separators, low years, or language.
- Ethiopic dates are supported only when explicitly specified via source calendar or metadata.
- Approximations like adding 7 or 8 years are strictly prohibited.
"""

from __future__ import annotations

import datetime
from enum import Enum
import math
import re
from typing import Optional, Tuple, Union


class CalendarType(str, Enum):
    """Supported calendar types."""

    GREGORIAN = "gregorian"
    ETHIOPIC = "ethiopic"


class EthiopicEra(str, Enum):
    """Ethiopic calendar eras.

    - AMETE_MIHRET: ዓ/ም (Era of the Incarnation / Era of Mercy, ICU era 0).
      Epoch offset JD 1,723,856.
    - AMETE_ALEM: ዓ/ዓ (Era of the World / Anno Mundi, ICU era 1).
      Epoch offset JD -285,019. Difference of exactly 5,500 years from Amete Mihret.
    """

    AMETE_MIHRET = "amete_mihret"
    AMETE_ALEM = "amete_alem"


# Julian Day Number Epoch Offsets matching ICU and Calendrical Calculations
JD_EPOCH_OFFSET_AMETE_MIHRET = 1723856  # 1/1/1 AM in Julian Day Number
JD_EPOCH_OFFSET_AMETE_ALEM = -285019    # 1/1/1 AA in Julian Day Number
JD_EPOCH_OFFSET_GREGORIAN = 1721426     # 1/1/1 CE Gregorian in Julian Day Number
AMETE_MIHRET_DELTA = 5500               # 5501 - 1 = 5500 years difference

# Month metadata for Ethiopian Calendar
ETHIOPIC_MONTH_NAMES = {
    1: ("Meskerem", "መስከረም"),
    2: ("Tikimt", "ጥቅምት"),
    3: ("Hidar", "ኅዳር"),
    4: ("Tahsas", "ታኅሣሥ"),
    5: ("Tir", "ጥር"),
    6: ("Yekatit", "የካቲት"),
    7: ("Megabit", "መጋቢት"),
    8: ("Miazia", "ሚያዝያ"),
    9: ("Ginbot", "ግንቦት"),
    10: ("Sene", "ሰኔ"),
    11: ("Hamle", "ሐምሌ"),
    12: ("Nehase", "ነሐሴ"),
    13: ("Pagume", "ጳጉሜ"),
}


class CalendarError(ValueError):
    """Base exception for calendar errors."""


class InvalidDateError(CalendarError):
    """Raised when date components are mathematically or chronologically invalid."""


class AmbiguousDateError(CalendarError):
    """Raised when date string lacks an explicit calendar source."""


class UnsupportedEraError(CalendarError):
    """Raised when an unrecognized or unsupported calendar era is provided."""


class FutureDateError(CalendarError):
    """Raised when a birthdate is in the future."""


def _quotient(i: int, j: int) -> int:
    return math.floor(i / j)


def _mod(i: int, j: int) -> int:
    return int(i - (j * _quotient(i, j)))


def is_ethiopic_leap_year(year: int) -> bool:
    """Determine whether an Ethiopic year is a leap year.

    In the Ethiopic calendar (Julian cycle), every year where year % 4 == 3
    is a leap year with 6 days in Pagume (month 13).
    """
    return (year % 4) == 3


def is_gregorian_leap_year(year: int) -> bool:
    """Determine whether a Gregorian year is a leap year."""
    return (year % 4 == 0) and ((year % 100 != 0) or (year % 400 == 0))


def max_days_in_ethiopic_month(year: int, month: int) -> int:
    """Return maximum valid days in given Ethiopic year and month."""
    if not 1 <= month <= 13:
        raise InvalidDateError(f"Ethiopic month must be 1..13, got {month}")
    if month <= 12:
        return 30
    return 6 if is_ethiopic_leap_year(year) else 5


def max_days_in_gregorian_month(year: int, month: int) -> int:
    """Return maximum valid days in given Gregorian year and month."""
    if not 1 <= month <= 12:
        raise InvalidDateError(f"Gregorian month must be 1..12, got {month}")
    if month in (1, 3, 5, 7, 8, 10, 12):
        return 31
    if month in (4, 6, 9, 11):
        return 30
    return 29 if is_gregorian_leap_year(year) else 28


def _resolve_era_enum(era: Union[EthiopicEra, str]) -> EthiopicEra:
    if isinstance(era, EthiopicEra):
        return era
    if isinstance(era, str):
        era_lower = era.lower().strip()
        if era_lower in ("amete_mihret", "am", "incarnation", "ዓ/ም"):
            return EthiopicEra.AMETE_MIHRET
        elif era_lower in ("amete_alem", "aa", "mundi", "ዓ/ዓ"):
            return EthiopicEra.AMETE_ALEM
        else:
            raise UnsupportedEraError(
                f"Unsupported Ethiopic era '{era}'. Must be 'amete_mihret' (ዓ/ም) or 'amete_alem' (ዓ/ዓ)."
            )
    raise UnsupportedEraError(f"Unsupported era type: {type(era)}")


def _resolve_era_offset(era: Union[EthiopicEra, str]) -> int:
    resolved = _resolve_era_enum(era)
    if resolved == EthiopicEra.AMETE_MIHRET:
        return JD_EPOCH_OFFSET_AMETE_MIHRET
    return JD_EPOCH_OFFSET_AMETE_ALEM


def ethiopic_to_jdn(
    year: int,
    month: int,
    day: int,
    era: Union[EthiopicEra, str] = EthiopicEra.AMETE_MIHRET,
) -> int:
    """Convert an Ethiopic calendar date into an absolute Julian Day Number (JDN).

    Uses the vetted ICU / Beyene-Kudlek calendrical algorithm.
    """
    era_offset = _resolve_era_offset(era)
    return (
        (era_offset + 365)
        + 365 * (year - 1)
        + _quotient(year, 4)
        + 30 * month
        + day
        - 31
    )


def jdn_to_ethiopic(
    jdn: int,
    era: Union[EthiopicEra, str] = EthiopicEra.AMETE_MIHRET,
) -> Tuple[int, int, int]:
    """Convert an absolute Julian Day Number (JDN) into an Ethiopic date (year, month, day)."""
    era_offset = _resolve_era_offset(era)
    r = _mod(jdn - era_offset, 1461)
    n = _mod(r, 365) + 365 * _quotient(r, 1460)

    year = 4 * _quotient(jdn - era_offset, 1461) + _quotient(r, 365) - _quotient(r, 1460)
    month = _quotient(n, 30) + 1
    day = _mod(n, 30) + 1
    return year, month, day


def gregorian_to_jdn(year: int, month: int, day: int) -> int:
    """Convert a Gregorian calendar date into an absolute Julian Day Number (JDN)."""
    s = (
        _quotient(year, 4)
        - _quotient(year - 1, 4)
        - _quotient(year, 100)
        + _quotient(year - 1, 100)
        + _quotient(year, 400)
        - _quotient(year - 1, 400)
    )
    t = _quotient(14 - month, 12)
    n = (
        31 * t * (month - 1)
        + (1 - t) * (59 + s + 30 * (month - 3) + _quotient(3 * month - 7, 5))
        + day
        - 1
    )
    return (
        JD_EPOCH_OFFSET_GREGORIAN
        + 365 * (year - 1)
        + _quotient(year - 1, 4)
        - _quotient(year - 1, 100)
        + _quotient(year - 1, 400)
        + n
    )


def jdn_to_gregorian(jdn: int) -> Tuple[int, int, int]:
    """Convert an absolute Julian Day Number (JDN) into a Gregorian date (year, month, day)."""
    r2000 = _mod(jdn - JD_EPOCH_OFFSET_GREGORIAN, 730485)
    r400 = _mod(jdn - JD_EPOCH_OFFSET_GREGORIAN, 146097)
    r100 = _mod(r400, 36524)
    r4 = _mod(r100, 1461)

    n = _mod(r4, 365) + 365 * _quotient(r4, 1460)
    aprime = (
        400 * _quotient(jdn - JD_EPOCH_OFFSET_GREGORIAN, 146097)
        + 100 * _quotient(r400, 36524)
        + 4 * _quotient(r100, 1461)
        + _quotient(r4, 365)
        - _quotient(r4, 1460)
        - _quotient(r2000, 730484)
    )
    year = aprime + 1
    n += 1 - _quotient(r2000, 730484)

    if r100 == 0 and n == 0 and r400 != 0:
        return year, 12, 31

    month_days = [
        0,
        31,
        29 if is_gregorian_leap_year(year) else 28,
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ]
    for m in range(1, 13):
        if n <= month_days[m]:
            return year, m, n
        n -= month_days[m]

    return year, 12, 31


class GregorianDate:
    """Strictly validated Gregorian calendar date."""

    def __init__(self, year: int, month: int, day: int) -> None:
        if not isinstance(year, int) or not isinstance(month, int) or not isinstance(day, int):
            raise InvalidDateError("Year, month, and day must be integers")
        if not 1 <= month <= 12:
            raise InvalidDateError(f"Invalid Gregorian month {month}; must be 1..12")
        max_day = max_days_in_gregorian_month(year, month)
        if not 1 <= day <= max_day:
            raise InvalidDateError(
                f"Invalid Gregorian day {day} for {year:04d}-{month:02d}; max is {max_day}"
            )
        self.year = year
        self.month = month
        self.day = day

    @property
    def is_leap_year(self) -> bool:
        return is_gregorian_leap_year(self.year)

    def to_jdn(self) -> int:
        return gregorian_to_jdn(self.year, self.month, self.day)

    def to_date(self) -> datetime.date:
        return datetime.date(self.year, self.month, self.day)

    @classmethod
    def from_date(cls, d: datetime.date) -> GregorianDate:
        return cls(d.year, d.month, d.day)

    @classmethod
    def from_jdn(cls, jdn: int) -> GregorianDate:
        y, m, d = jdn_to_gregorian(jdn)
        return cls(y, m, d)

    def to_ethiopic(
        self, era: Union[EthiopicEra, str] = EthiopicEra.AMETE_MIHRET
    ) -> EthiopicDate:
        resolved_era = _resolve_era_enum(era)
        jdn = self.to_jdn()
        ey, em, ed = jdn_to_ethiopic(jdn, era=resolved_era)
        return EthiopicDate(ey, em, ed, era=resolved_era)

    def isoformat(self) -> str:
        return f"{self.year:04d}-{self.month:02d}-{self.day:02d}"

    def __str__(self) -> str:
        return self.isoformat()

    def __repr__(self) -> str:
        return f"GregorianDate({self.year}, {self.month}, {self.day})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, GregorianDate):
            return False
        return (self.year, self.month, self.day) == (other.year, other.month, other.day)

    def __lt__(self, other: GregorianDate) -> bool:
        return (self.year, self.month, self.day) < (other.year, other.month, other.day)


class EthiopicDate:
    """Strictly validated Ethiopic calendar date.

    Supports twelve 30-day months and Pagume (month 13, 5 or 6 days).
    Requires explicit era specification (defaulting to Amete Mihret).
    """

    def __init__(
        self,
        year: int,
        month: int,
        day: int,
        era: Union[EthiopicEra, str] = EthiopicEra.AMETE_MIHRET,
    ) -> None:
        if not isinstance(year, int) or not isinstance(month, int) or not isinstance(day, int):
            raise InvalidDateError("Year, month, and day must be integers")
        if year < 1:
            raise InvalidDateError(f"Ethiopic year must be positive, got {year}")

        self.era = _resolve_era_enum(era)

        if not 1 <= month <= 13:
            raise InvalidDateError(f"Invalid Ethiopic month {month}; must be 1..13")

        max_day = max_days_in_ethiopic_month(year, month)
        if not 1 <= day <= max_day:
            if month == 13:
                leap_text = "leap year" if is_ethiopic_leap_year(year) else "common year"
                raise InvalidDateError(
                    f"Invalid Pagume day {day} for Ethiopic year {year} ({leap_text}); max is {max_day}"
                )
            raise InvalidDateError(
                f"Invalid Ethiopic day {day} for month {month}; Ethiopic months 1..12 have exactly 30 days"
            )

        self.year = year
        self.month = month
        self.day = day

    @property
    def is_leap_year(self) -> bool:
        return is_ethiopic_leap_year(self.year)

    @property
    def month_name(self) -> str:
        return ETHIOPIC_MONTH_NAMES[self.month][0]

    @property
    def month_name_geez(self) -> str:
        return ETHIOPIC_MONTH_NAMES[self.month][1]

    def to_jdn(self) -> int:
        return ethiopic_to_jdn(self.year, self.month, self.day, era=self.era)

    @classmethod
    def from_jdn(
        cls,
        jdn: int,
        era: Union[EthiopicEra, str] = EthiopicEra.AMETE_MIHRET,
    ) -> EthiopicDate:
        y, m, d = jdn_to_ethiopic(jdn, era=era)
        return cls(y, m, d, era=era)

    def to_gregorian(self) -> GregorianDate:
        jdn = self.to_jdn()
        gy, gm, gd = jdn_to_gregorian(jdn)
        return GregorianDate(gy, gm, gd)

    def isoformat(self) -> str:
        return f"{self.year:04d}-{self.month:02d}-{self.day:02d}"

    def __str__(self) -> str:
        era_suffix = " (ዓ/ም)" if self.era == EthiopicEra.AMETE_MIHRET else " (ዓ/ዓ)"
        return f"{self.isoformat()}{era_suffix}"

    def __repr__(self) -> str:
        return f"EthiopicDate({self.year}, {self.month}, {self.day}, era={self.era.value!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, EthiopicDate):
            return False
        return (self.year, self.month, self.day, self.era) == (
            other.year,
            other.month,
            other.day,
            other.era,
        )


def ethiopic_to_gregorian(eth: EthiopicDate) -> GregorianDate:
    """Bidirectional conversion: EthiopicDate -> GregorianDate."""
    return eth.to_gregorian()


def gregorian_to_ethiopic(
    greg: GregorianDate,
    era: Union[EthiopicEra, str] = EthiopicEra.AMETE_MIHRET,
) -> EthiopicDate:
    """Bidirectional conversion: GregorianDate -> EthiopicDate."""
    return greg.to_ethiopic(era=era)


def parse_date_explicit(
    date_str: str,
    calendar: Union[CalendarType, str],
    era: Optional[Union[EthiopicEra, str]] = None,
) -> Union[GregorianDate, EthiopicDate]:
    """Parse date string strictly requiring an explicit calendar identifier.

    Rejects ambiguous or unlabeled dates. A separator (slash or hyphen)
    does NOT identify a calendar by itself.
    """
    if not calendar:
        raise AmbiguousDateError(
            "Calendar source must be explicit. Date string alone does not identify a calendar."
        )

    cal_str = str(calendar).lower().strip()
    if cal_str not in ("gregorian", "ethiopic", "gc", "ec"):
        raise CalendarError(f"Unknown or unsupported calendar '{calendar}'")

    if not isinstance(date_str, str) or not date_str.strip():
        raise InvalidDateError("Date string cannot be empty")

    cleaned = date_str.strip()

    # Match YYYY-MM-DD or YYYY/MM/DD
    m = re.match(r"^(\d{1,4})[-/](\d{1,2})[-/](\d{1,2})$", cleaned)
    if not m:
        raise InvalidDateError(
            f"Unrecognized date pattern '{date_str}'. Expected YYYY-MM-DD or YYYY/MM/DD."
        )

    year = int(m.group(1))
    month = int(m.group(2))
    day = int(m.group(3))

    if cal_str in ("gregorian", "gc"):
        return GregorianDate(year, month, day)
    else:
        resolved_era = era or EthiopicEra.AMETE_MIHRET
        return EthiopicDate(year, month, day, era=resolved_era)


def validate_birthdate(
    d: Union[GregorianDate, EthiopicDate],
    reference_date: Optional[datetime.date] = None,
) -> None:
    """Strictly validate birthdate against future dates.

    Birthdates cannot be in the future.
    """
    ref = reference_date or datetime.datetime.now(datetime.timezone.utc).date()
    if isinstance(d, EthiopicDate):
        greg = d.to_gregorian().to_date()
    else:
        greg = d.to_date()

    if greg > ref:
        raise FutureDateError(
            f"Birthdate {greg.isoformat()} cannot be in the future (reference date: {ref.isoformat()})"
        )


def normalize_dob_with_source(
    raw_dob: str,
    source_calendar: Optional[str] = None,
    era: Optional[str] = None,
    allow_partial: bool = True,
    reference_date: Optional[datetime.date] = None,
) -> Optional[str]:
    """Normalize birthdate according to explicit source calendar semantics.

    OIDC standard birthdate uses Gregorian YYYY-MM-DD, including partial dates:
    - YYYY-MM
    - 0000-MM-DD (partial date where year is omitted per OpenID Connect spec)

    CRITICAL RULES:
    1. Standard OIDC birthdate is Gregorian. Do NOT reinterpret a compliant Gregorian
       date as Ethiopian based on a low year, separator, country, or language.
    2. Support Ethiopic (EC) ONLY when source_calendar is explicitly configured
       (e.g. via provider extension, metadata, or host configuration).
    3. Never approximate conversion by adding 7 or 8 years.
    """
    if not raw_dob or not isinstance(raw_dob, str):
        return None

    cleaned = raw_dob.strip()

    # Check for OIDC standard partial dates: YYYY-MM or 0000-MM-DD
    if allow_partial:
        # 0000-MM-DD (year unknown)
        m_no_year = re.match(r"^0000[-/](\d{1,2})[-/](\d{1,2})$", cleaned)
        if m_no_year:
            m, d = int(m_no_year.group(1)), int(m_no_year.group(2))
            if 1 <= m <= 12 and 1 <= d <= 31:
                return f"0000-{m:02d}-{d:02d}"

        # YYYY-MM (day unknown)
        m_partial_year_month = re.match(r"^(\d{4})[-/](\d{1,2})$", cleaned)
        if m_partial_year_month:
            y, m = int(m_partial_year_month.group(1)), int(m_partial_year_month.group(2))
            if 1900 <= y <= 2100 and 1 <= m <= 12:
                return f"{y:04d}-{m:02d}"

    # Default source calendar is Gregorian unless explicitly configured as ethiopic
    cal = (source_calendar or "gregorian").lower().strip()

    try:
        parsed = parse_date_explicit(cleaned, calendar=cal, era=era)
        validate_birthdate(parsed, reference_date=reference_date)

        if isinstance(parsed, EthiopicDate):
            # Convert to Gregorian ISO YYYY-MM-DD
            greg = parsed.to_gregorian()
            if not 1900 <= greg.year <= 2100:
                return None
            return greg.isoformat()
        else:
            if not 1900 <= parsed.year <= 2100:
                return None
            return parsed.isoformat()
    except Exception:
        return None
