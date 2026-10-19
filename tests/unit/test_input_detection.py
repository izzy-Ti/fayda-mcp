"""Unit tests for Task 03: Detect supported input.

Verifies:
- Identification of Ethiopic, Latin, and mixed script text.
- Flagging unsupported characters (digits, emojis, foreign scripts).
- Flagging invisible and control characters (zero-width spaces, joiners, BOM, C0/C1 codes).
- Preserving permitted punctuation without false flags (apostrophes, hyphens, Ethiopic word separators).
- Integration with normalize_name_safely and NormalizedName.
"""

import pytest

from fayda_mcp.matching.detection import (
    DETECTED_SCRIPT_ETHIOPIC,
    DETECTED_SCRIPT_LATIN,
    DETECTED_SCRIPT_MIXED,
    DETECTED_SCRIPT_UNKNOWN,
    REVIEW_REASON_DIGITS_IN_NAME,
    REVIEW_REASON_EMPTY_INPUT,
    REVIEW_REASON_INVISIBLE_OR_CONTROL_CHARACTERS,
    REVIEW_REASON_MIXED_SCRIPT,
    REVIEW_REASON_UNKNOWN_SCRIPT,
    REVIEW_REASON_UNSUPPORTED_CHARACTERS,
    detect_input_script,
    is_control_or_invisible,
    is_ethiopic_char,
    is_latin_char,
    is_permitted_punctuation,
)
from fayda_mcp.matching.normalization import normalize_name_safely


class TestScriptIdentification:
    """Verifies identification of Ethiopic, Latin, and mixed script names."""

    def test_identify_ethiopic_script(self):
        """Names written in Ge'ez/Ethiopic script are classified as ethiopic."""
        res = detect_input_script("አበበ ቢቂላ")
        assert res.script == DETECTED_SCRIPT_ETHIOPIC
        assert res.has_ethiopic is True
        assert res.has_latin is False
        assert res.is_supported is True
        assert res.requires_review is False
        assert res.review_reasons == []

    def test_identify_latin_script(self):
        """Names written in Latin alphabet are classified as latin."""
        res = detect_input_script("Abebe Bikila")
        assert res.script == DETECTED_SCRIPT_LATIN
        assert res.has_latin is True
        assert res.has_ethiopic is False
        assert res.is_supported is True
        assert res.requires_review is False
        assert res.review_reasons == []

    def test_identify_mixed_script(self):
        """Names containing both Ethiopic and Latin are classified as mixed and flagged for review."""
        res = detect_input_script("Abebe አበበ")
        assert res.script == DETECTED_SCRIPT_MIXED
        assert res.has_latin is True
        assert res.has_ethiopic is True
        assert res.requires_review is True
        assert REVIEW_REASON_MIXED_SCRIPT in res.review_reasons

    def test_empty_and_none_input(self):
        """Empty or None inputs return unknown script and require review."""
        res_none = detect_input_script(None)
        assert res_none.script == DETECTED_SCRIPT_UNKNOWN
        assert res_none.is_supported is False
        assert res_none.requires_review is True
        assert REVIEW_REASON_EMPTY_INPUT in res_none.review_reasons

        res_empty = detect_input_script("   \t  ")
        assert res_empty.script == DETECTED_SCRIPT_UNKNOWN
        assert res_empty.is_supported is False
        assert res_empty.requires_review is True
        assert REVIEW_REASON_EMPTY_INPUT in res_empty.review_reasons


class TestInvisibleAndControlCharacters:
    """Verifies detection and flagging of invisible, zero-width, formatting, and control characters."""

    def test_flag_zero_width_space(self):
        """Zero-width space (U+200B) is detected and flagged for review."""
        res = detect_input_script("Abebe\u200b Bikila")
        assert res.has_control_or_invisible_chars is True
        assert res.requires_review is True
        assert res.is_supported is False
        assert REVIEW_REASON_INVISIBLE_OR_CONTROL_CHARACTERS in res.review_reasons
        assert "U+200B" in res.control_or_invisible_chars

    def test_flag_zero_width_joiner_and_non_joiner(self):
        """Zero-width non-joiner (U+200C) and joiner (U+200D) are flagged."""
        res_zwnj = detect_input_script("አበበ\u200c ቢቂላ")
        assert res_zwnj.has_control_or_invisible_chars is True
        assert "U+200C" in res_zwnj.control_or_invisible_chars

        res_zwj = detect_input_script("አበበ\u200d ቢቂላ")
        assert res_zwj.has_control_or_invisible_chars is True
        assert "U+200D" in res_zwj.control_or_invisible_chars

    def test_flag_bom_character(self):
        """BOM character (U+FEFF) is flagged."""
        res = detect_input_script("\ufeffAbebe Bikila")
        assert res.has_control_or_invisible_chars is True
        assert "U+FEFF" in res.control_or_invisible_chars

    def test_flag_c0_c1_control_codes(self):
        """ASCII control characters (e.g. NUL byte, BEL) are flagged."""
        res = detect_input_script("Abebe\x00Bikila")
        assert res.has_control_or_invisible_chars is True
        assert "U+0000" in res.control_or_invisible_chars

        res_bel = detect_input_script("Abebe\x07Bikila")
        assert res_bel.has_control_or_invisible_chars is True
        assert "U+0007" in res_bel.control_or_invisible_chars

    def test_flag_directional_formatting_marks(self):
        """Directional formatting characters (e.g. LTR/RTL marks) are flagged."""
        res = detect_input_script("Abebe\u200e Bikila")
        assert res.has_control_or_invisible_chars is True
        assert "U+200E" in res.control_or_invisible_chars


class TestUnsupportedCharacters:
    """Verifies flagging of characters outside supported Latin, Ethiopic, and approved punctuation."""

    def test_flag_digits_in_names(self):
        """Numeric digits in citizen names are flagged for review."""
        res = detect_input_script("Abebe 123")
        assert res.has_unsupported_chars is True
        assert res.requires_review is True
        assert res.is_supported is False
        assert REVIEW_REASON_DIGITS_IN_NAME in res.review_reasons
        assert "1" in res.unsupported_chars

    def test_flag_foreign_scripts(self):
        """Non-Ethiopic / non-Latin scripts (Arabic, Cyrillic, Chinese) are flagged."""
        # Arabic
        res_ar = detect_input_script("محمد علي")
        assert res_ar.script == DETECTED_SCRIPT_UNKNOWN
        assert res_ar.has_unsupported_chars is True
        assert res_ar.requires_review is True
        assert REVIEW_REASON_UNSUPPORTED_CHARACTERS in res_ar.review_reasons

        # Cyrillic
        res_cyr = detect_input_script("Абебе Бикила")
        assert res_cyr.script == DETECTED_SCRIPT_UNKNOWN
        assert res_cyr.has_unsupported_chars is True
        assert res_cyr.requires_review is True

        # Chinese
        res_cjk = detect_input_script("李小龙")
        assert res_cjk.script == DETECTED_SCRIPT_UNKNOWN
        assert res_cjk.has_unsupported_chars is True
        assert res_cjk.requires_review is True

    def test_flag_emojis_and_symbols(self):
        """Emojis and unexpected symbols are flagged."""
        res = detect_input_script("Abebe 😊 Bikila")
        assert res.has_unsupported_chars is True
        assert res.requires_review is True
        assert "😊" in res.unsupported_chars

        res_sym = detect_input_script("Abebe @ Bikila #1")
        assert res_sym.has_unsupported_chars is True
        assert "@" in res_sym.unsupported_chars


class TestPermittedPunctuation:
    """Verifies that standard transliteration and Ethiopic punctuation are permitted."""

    def test_permitted_apostrophes_and_hyphens(self):
        """Apostrophes (ejectives/glottals) and hyphens are permitted without false flags."""
        res_apostrophe = detect_input_script("T'esfaye D'esta")
        assert res_apostrophe.script == DETECTED_SCRIPT_LATIN
        assert res_apostrophe.is_supported is True
        assert res_apostrophe.requires_review is False

        res_curly = detect_input_script("T’esfaye D’esta")
        assert res_curly.script == DETECTED_SCRIPT_LATIN
        assert res_curly.is_supported is True
        assert res_curly.requires_review is False

        res_hyphen = detect_input_script("Haile-Selassie")
        assert res_hyphen.script == DETECTED_SCRIPT_LATIN
        assert res_hyphen.is_supported is True
        assert res_hyphen.requires_review is False

    def test_permitted_ethiopic_wordspace(self):
        """Ethiopic wordspace (U+1361 '፡') is permitted without flagging as unsupported."""
        res = detect_input_script("አበበ፡ቢቂላ")
        assert res.script == DETECTED_SCRIPT_ETHIOPIC
        assert res.is_supported is True
        assert res.requires_review is False


class TestNormalizedNameIntegration:
    """Verifies detection attaches automatically to NormalizedName."""

    def test_normalization_includes_detection(self):
        """normalize_name_safely automatically attaches InputDetectionResult."""
        norm_clean = normalize_name_safely("  Abebe Bikila  ")
        assert norm_clean is not None
        assert norm_clean.detection is not None
        assert norm_clean.detection.script == DETECTED_SCRIPT_LATIN
        assert norm_clean.detection.is_supported is True
        assert norm_clean.detection.requires_review is False

        norm_dirty = normalize_name_safely("Abebe\u200b Bikila 2")
        assert norm_dirty is not None
        assert norm_dirty.detection is not None
        assert norm_dirty.detection.has_control_or_invisible_chars is True
        assert norm_dirty.detection.has_unsupported_chars is True
        assert norm_dirty.detection.requires_review is True
        assert REVIEW_REASON_INVISIBLE_OR_CONTROL_CHARACTERS in norm_dirty.detection.review_reasons
        assert REVIEW_REASON_DIGITS_IN_NAME in norm_dirty.detection.review_reasons
