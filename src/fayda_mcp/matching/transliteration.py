"""Versioned Amharic Ethiopic-to-Latin transliteration mapping and bounded variant generator.

Per guide5 Task 04:
- Versioned Amharic Ethiopic-to-Latin mapping reviewed by an Amharic language specialist.
- Bounded generated variants (prevents combinatorial explosion; caps per-token and total variants).
- Generates canonical primary transliteration and ranked candidate variations.
- Preserves token order and structure.
"""

from itertools import product
from typing import Dict, List, Optional, Sequence, Set, Tuple
from pydantic import BaseModel, ConfigDict, Field

from fayda_mcp.matching.detection import is_ethiopic_char, is_latin_char, is_permitted_punctuation, is_whitespace_char

# ---------------------------------------------------------------------------
# Versions & Limits
# ---------------------------------------------------------------------------

AMHARIC_TRANSLITERATION_VERSION: str = "amharic-translit-v1"
TRANSLITERATION_SPEC_VERSION: str = "1.0.0"

DEFAULT_MAX_VARIANTS_PER_TOKEN: int = 8
DEFAULT_MAX_TOTAL_VARIANTS: int = 32

# ---------------------------------------------------------------------------
# Amharic Fidel to Latin Mapping Table (amharic-translit-v1)
# Reviewed according to standard Ethiopian civil registration, passport transliteration,
# and Unicode/CLDR Ethiopic-Latin conventions.
#
# Format: char -> (canonical_representation, (alternate_approved_variants, ...))
# ---------------------------------------------------------------------------

AMHARIC_FIDEL_TABLE: Dict[str, Tuple[str, Tuple[str, ...]]] = {
    # ሀ (h) series
    "ሀ": ("ha", ("he",)),
    "ሁ": ("hu", ()),
    "ሂ": ("hi", ()),
    "ሃ": ("ha", ()),
    "ሄ": ("he", ()),
    "ህ": ("h", ("he",)),
    "ሆ": ("ho", ()),
    # ለ (l) series
    "ለ": ("le", ("la",)),
    "ሉ": ("lu", ()),
    "ሊ": ("li", ()),
    "ላ": ("la", ()),
    "ሌ": ("le", ()),
    "ል": ("l", ("le",)),
    "ሎ": ("lo", ()),
    # ሐ (h - ḥ) series
    "ሐ": ("ha", ("he",)),
    "ሑ": ("hu", ()),
    "ሒ": ("hi", ()),
    "ሓ": ("ha", ()),
    "ሔ": ("he", ()),
    "ሕ": ("h", ("he",)),
    "ሖ": ("ho", ()),
    # መ (m) series
    "መ": ("me", ("ma",)),
    "ሙ": ("mu", ()),
    "ሚ": ("mi", ()),
    "ማ": ("ma", ()),
    "ሜ": ("me", ()),
    "ም": ("m", ("me",)),
    "ሞ": ("mo", ()),
    # ሠ (s - ś) series
    "ሠ": ("se", ("sa",)),
    "ሡ": ("su", ()),
    "ሢ": ("si", ()),
    "ሣ": ("sa", ()),
    "ሤ": ("se", ()),
    "ሥ": ("se", ("s",)),
    "ሦ": ("so", ()),
    # ረ (r) series
    "ረ": ("re", ("ra",)),
    "ሩ": ("ru", ()),
    "ሪ": ("ri", ()),
    "ራ": ("ra", ()),
    "ሬ": ("re", ()),
    "ር": ("r", ("re",)),
    "ሮ": ("ro", ()),
    # ሰ (s) series
    "ሰ": ("se", ("sa",)),
    "ሱ": ("su", ()),
    "ሲ": ("si", ()),
    "ሳ": ("sa", ()),
    "ሴ": ("se", ("ssie", "sie")),
    "ስ": ("s", ("se",)),
    "ሶ": ("so", ()),
    # ሸ (sh - š) series
    "ሸ": ("she", ("sha",)),
    "ሹ": ("shu", ()),
    "ሺ": ("shi", ()),
    "ሻ": ("sha", ()),
    "ሼ": ("she", ()),
    "ሽ": ("sh", ()),
    "ሾ": ("sho", ()),
    # ቀ (q / k') series
    "ቀ": ("ke", ("qe", "ka", "qa")),
    "ቁ": ("ku", ("qu",)),
    "ቂ": ("ki", ("qi",)),
    "ቃ": ("ka", ("qa",)),
    "ቄ": ("ke", ("qe",)),
    "ቅ": ("k", ("q",)),
    "ቆ": ("ko", ("qo",)),
    # በ (b) series
    "በ": ("be", ("ba",)),
    "ቡ": ("bu", ()),
    "ቢ": ("bi", ()),
    "ባ": ("ba", ()),
    "ቤ": ("be", ()),
    "ብ": ("b", ("be",)),
    "ቦ": ("bo", ()),
    # ቨ (v) series
    "ቨ": ("ve", ("va",)),
    "ቩ": ("vu", ()),
    "ቪ": ("vi", ()),
    "ቫ": ("va", ()),
    "ቬ": ("ve", ()),
    "ቭ": ("v", ()),
    "ቮ": ("vo", ()),
    # ተ (t) series
    "ተ": ("te", ("ta",)),
    "ቱ": ("tu", ()),
    "ቲ": ("ti", ()),
    "ታ": ("ta", ()),
    "ቴ": ("te", ()),
    "ት": ("t", ("te",)),
    "ቶ": ("to", ()),
    # ቸ (ch - č) series
    "ቸ": ("che", ("cha",)),
    "ቹ": ("chu", ()),
    "ቺ": ("chi", ()),
    "ቻ": ("cha", ()),
    "ቼ": ("che", ()),
    "ች": ("ch", ()),
    "ቾ": ("cho", ()),
    # ኀ (h - ḫ) series
    "ኀ": ("ha", ("he",)),
    "ኁ": ("hu", ()),
    "ኂ": ("hi", ()),
    "ኃ": ("ha", ("he",)),
    "ኄ": ("he", ()),
    "ኅ": ("h", ("he",)),
    "ኆ": ("ho", ()),
    # ነ (n) series
    "ነ": ("ne", ("na",)),
    "ኑ": ("nu", ()),
    "ኒ": ("ni", ()),
    "ና": ("na", ()),
    "ኔ": ("ne", ()),
    "ን": ("n", ("ne",)),
    "ኖ": ("no", ()),
    # ኘ (gn / ny - ñ) series
    "ኘ": ("gne", ("nye", "gna", "nya")),
    "ኙ": ("gnu", ("nyu",)),
    "ኚ": ("gni", ("nyi",)),
    "ኛ": ("gna", ("nya",)),
    "ኜ": ("gne", ("nye",)),
    "ኝ": ("gn", ("ny",)),
    "ኞ": ("gno", ("nyo",)),
    # አ (a / ') series
    "አ": ("a", ("e",)),
    "ኡ": ("u", ()),
    "ኢ": ("i", ()),
    "ኣ": ("a", ()),
    "ኤ": ("e", ()),
    "እ": ("i", ("e",)),
    "ኦ": ("o", ()),
    # ከ (k) series
    "ከ": ("ke", ("ka",)),
    "ኩ": ("ku", ()),
    "ኪ": ("ki", ()),
    "ካ": ("ka", ()),
    "ኬ": ("ke", ()),
    "ክ": ("k", ("ke",)),
    "ኮ": ("ko", ()),
    # ኸ (h / kh) series
    "ኸ": ("he", ("khe", "ha")),
    "ኹ": ("hu", ("khu",)),
    "ኺ": ("hi", ("khi",)),
    "ኻ": ("ha", ("kha",)),
    "ኼ": ("he", ("khe",)),
    "ኽ": ("h", ("kh",)),
    "ኾ": ("ho", ("kho",)),
    # ወ (w) series
    "ወ": ("we", ("wo", "wa")),
    "ዉ": ("wu", ()),
    "ዊ": ("wi", ()),
    "ዋ": ("wa", ()),
    "ዌ": ("we", ()),
    "ው": ("w", ("we",)),
    "ዎ": ("wo", ()),
    # ዐ (a / ') series
    "ዐ": ("a", ("e",)),
    "ዑ": ("u", ()),
    "ዒ": ("i", ()),
    "ዓ": ("a", ()),
    "ዔ": ("e", ()),
    "ዕ": ("i", ("e",)),
    "ዖ": ("o", ()),
    # ዘ (z) series
    "ዘ": ("ze", ("za",)),
    "ዙ": ("zu", ()),
    "ዚ": ("zi", ()),
    "ዛ": ("za", ()),
    "ዜ": ("ze", ()),
    "ዝ": ("z", ("ze",)),
    "ዞ": ("zo", ()),
    # ዠ (zh - ž) series
    "ዠ": ("zhe", ("zha",)),
    "ዡ": ("zhu", ()),
    "ዢ": ("zhi", ()),
    "ዣ": ("zha", ()),
    "ዤ": ("zhe", ()),
    "ዥ": ("zh", ()),
    "ዦ": ("zho", ()),
    # የ (y) series
    "የ": ("ye", ("ya",)),
    "ዩ": ("yu", ()),
    "ዪ": ("yi", ()),
    "ያ": ("ya", ()),
    "ዬ": ("ye", ()),
    "ይ": ("i", ("y", "ye")),
    "ዮ": ("yo", ()),
    # ደ (d) series
    "ደ": ("de", ("da",)),
    "ዱ": ("du", ()),
    "ዲ": ("di", ()),
    "ዳ": ("da", ()),
    "ዴ": ("de", ()),
    "ድ": ("d", ("de",)),
    "ዶ": ("do", ()),
    # ጀ (j) series
    "ጀ": ("je", ("ja",)),
    "ጁ": ("ju", ()),
    "ጂ": ("ji", ()),
    "ጃ": ("ja", ()),
    "ጄ": ("je", ()),
    "ጅ": ("j", ()),
    "ጆ": ("jo", ()),
    # ገ (g) series
    "ገ": ("ge", ("ga",)),
    "ጉ": ("gu", ()),
    "ጊ": ("gi", ()),
    "ጋ": ("ga", ()),
    "ጌ": ("ge", ()),
    "ግ": ("g", ("ge",)),
    "ጎ": ("go", ()),
    # ጠ (t - ṭ) series
    "ጠ": ("te", ("ta",)),
    "ጡ": ("tu", ()),
    "ጢ": ("ti", ()),
    "ጣ": ("ta", ()),
    "ጤ": ("te", ()),
    "ጥ": ("t", ("te",)),
    "ጦ": ("to", ()),
    # ጨ (ch - č̣) series
    "ጨ": ("che", ("cha",)),
    "ጩ": ("chu", ()),
    "ጪ": ("chi", ()),
    "ጫ": ("cha", ()),
    "ጬ": ("che", ()),
    "ጭ": ("ch", ()),
    "ጮ": ("cho", ()),
    # ጰ (p - p̣) series
    "ጰ": ("pe", ("pa",)),
    "ጱ": ("pu", ()),
    "ጲ": ("pi", ()),
    "ጳ": ("pa", ()),
    "ጴ": ("pe", ()),
    "ጵ": ("p", ()),
    "ጶ": ("po", ()),
    # ጸ (ts - ṣ) series
    "ጸ": ("tse", ("tsa", "se")),
    "ጹ": ("tsu", ("su",)),
    "ጺ": ("tsi", ("si",)),
    "ጻ": ("tsa", ("sa",)),
    "ጼ": ("tse", ("se",)),
    "ጽ": ("ts", ("s",)),
    "ጾ": ("tso", ("so",)),
    # ፀ (ts - ṣ́) series
    "ፀ": ("tse", ("tsa", "se")),
    "ፁ": ("tsu", ("su",)),
    "ፂ": ("tsi", ("si",)),
    "ፃ": ("tsa", ("sa",)),
    "ፄ": ("tse", ("se",)),
    "ፅ": ("ts", ("s",)),
    "ፆ": ("tso", ("so",)),
    # ፈ (f) series
    "ፈ": ("fe", ("fa",)),
    "ፉ": ("fu", ()),
    "ፊ": ("fi", ()),
    "ፋ": ("fa", ()),
    "ፌ": ("fe", ()),
    "ፍ": ("f", ("fe",)),
    "ፎ": ("fo", ()),
    # ፐ (p) series
    "ፐ": ("pe", ("pa",)),
    "ፑ": ("pu", ()),
    "ፒ": ("pi", ()),
    "ፓ": ("pa", ()),
    "ፔ": ("pe", ()),
    "ፕ": ("p", ()),
    "ፖ": ("po", ()),
    # Labiovelars and diphthongs
    "ኋ": ("hwa", ()),
    "ሏ": ("lwa", ()),
    "ሟ": ("mwa", ()),
    "ሯ": ("rwa", ()),
    "ሷ": ("swa", ()),
    "ሿ": ("shwa", ()),
    "ቋ": ("kwa", ("qwa",)),
    "ቧ": ("bwa", ()),
    "ቷ": ("twa", ()),
    "ቿ": ("chwa", ()),
    "ኗ": ("nwa", ()),
    "ኟ": ("gnya", ("nya",)),
    "ኳ": ("kwa", ()),
    "ዟ": ("zwa", ()),
    "ዧ": ("zhwa", ()),
    "ዷ": ("dwa", ()),
    "ጇ": ("jwa", ()),
    "ጓ": ("gwa", ()),
    "ጧ": ("twa", ()),
    "ጯ": ("chwa", ()),
    "ጷ": ("pwa", ()),
    "ጿ": ("tswa", ()),
    "ፏ": ("fwa", ()),
    # Velar labiovelars (kwe, etc.)
    "ቈ": ("kwe", ("qwe",)),
    "ቊ": ("kwi", ("qwi",)),
    "ቌ": ("kwe", ("qwe",)),
    "ቍ": ("kw", ("qw",)),
    "ኰ": ("kwe", ()),
    "ኲ": ("kwi", ()),
    "ኳ": ("kwa", ()),
    "ኴ": ("kwe", ()),
    "ኵ": ("kw", ()),
    "ጐ": ("gwe", ()),
    "ጒ": ("gwi", ()),
    "ጔ": ("gwe", ()),
    "ጕ": ("gw", ()),
}


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class TokenTransliteration(BaseModel):
    """Transliteration result for a single name token."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    original_token: str = Field(..., description="Original Ethiopic/raw token string")
    canonical_token: str = Field(..., description="Primary canonical Latin transliteration")
    variants: List[str] = Field(
        default_factory=list,
        description="Bounded list of approved Latin spelling variants (including canonical)",
    )


class TransliterationResult(BaseModel):
    """Complete transliteration result for a full citizen name."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    original: str = Field(..., description="Original raw citizen name")
    canonical: str = Field(..., description="Primary canonical full Latin transliteration")
    variants: List[str] = Field(
        default_factory=list,
        description="Bounded list of approved full Latin spelling variants",
    )
    version: str = Field(
        default=AMHARIC_TRANSLITERATION_VERSION,
        description="Version of Amharic transliteration mapping applied",
    )
    token_transliterations: List[TokenTransliteration] = Field(
        default_factory=list,
        description="Per-token transliteration breakdown preserving name structure",
    )
    is_fully_transliterated: bool = Field(
        default=True,
        description="True if every character was mapped successfully",
    )
    unmapped_characters: List[str] = Field(
        default_factory=list,
        description="List of characters encountered that could not be mapped",
    )


# ---------------------------------------------------------------------------
# Core Transliteration Engine
# ---------------------------------------------------------------------------


def transliterate_token(
    token: str,
    max_variants: int = DEFAULT_MAX_VARIANTS_PER_TOKEN,
) -> TokenTransliteration:
    """Transliterate a single Ethiopic token into canonical Latin and bounded variants.

    Args:
        token: Raw Ethiopic token (e.g. 'አበበ', 'ቢቂላ', 'ወልደ').
        max_variants: Maximum number of variants permitted for this token.

    Returns:
        TokenTransliteration instance with canonical token and bounded variants.
    """
    clean_token = token.strip()
    if not clean_token:
        return TokenTransliteration(original_token=token, canonical_token="", variants=[])

    char_options: List[List[str]] = []
    canonical_chars: List[str] = []

    for ch in clean_token:
        if ch in AMHARIC_FIDEL_TABLE:
            primary, alts = AMHARIC_FIDEL_TABLE[ch]
            canonical_chars.append(primary)
            # Prioritize primary, then alternates:
            options = [primary] + list(alts)
            char_options.append(options)
        elif is_permitted_punctuation(ch) or is_whitespace_char(ch):
            canonical_chars.append(ch)
            char_options.append([ch])
        else:
            # Preserves unmapped characters directly (e.g. existing Latin characters)
            canonical_chars.append(ch.lower())
            char_options.append([ch.lower()])

    canonical_token = "".join(canonical_chars)

    # Generate bounded candidate variants
    # Only branch on characters that actually have variations, capped to avoid explosion
    generated_variants: List[str] = [canonical_token]
    seen_variants: Set[str] = {canonical_token}

    # Bounded cartesian product
    for combo in product(*char_options):
        variant = "".join(combo)
        if variant not in seen_variants:
            seen_variants.add(variant)
            generated_variants.append(variant)
            if len(generated_variants) >= max_variants:
                break

    return TokenTransliteration(
        original_token=clean_token,
        canonical_token=canonical_token,
        variants=generated_variants[:max_variants],
    )


def transliterate_amharic_to_latin(
    name: Optional[str],
    max_variants: int = DEFAULT_MAX_TOTAL_VARIANTS,
    max_variants_per_token: int = DEFAULT_MAX_VARIANTS_PER_TOKEN,
) -> Optional[TransliterationResult]:
    """Transliterate an Amharic Ethiopic name into Latin with bounded variants.

    Per guide5 Task 04:
    - Versioned mapping: amharic-translit-v1.
    - Strictly bounds generated variants across tokens to prevent combinatorial explosion.
    - Preserves token order and structure.

    Args:
        name: Raw or normalized Amharic name string (e.g. 'አበበ ቢቂላ ደራርቱ').
        max_variants: Maximum number of full name variants to generate.
        max_variants_per_token: Maximum variants to generate per token.

    Returns:
        TransliterationResult or None if name is empty.
    """
    if name is None:
        return None

    raw_str = str(name).strip()
    if not raw_str:
        return None

    # Replace Ethiopic wordspace (U+1361) with space and split tokens
    clean_split = raw_str.replace("፡", " ").split()
    if not clean_split:
        return None

    unmapped: Set[str] = set()
    token_translit_list: List[TokenTransliteration] = []

    for t in clean_split:
        t_res = transliterate_token(t, max_variants=max_variants_per_token)
        token_translit_list.append(t_res)
        for ch in t:
            if (
                ch not in AMHARIC_FIDEL_TABLE
                and not is_permitted_punctuation(ch)
                and not is_whitespace_char(ch)
                and not is_latin_char(ch)
            ):
                unmapped.add(ch)

    # Canonical full name
    canonical_full = " ".join(t.canonical_token for t in token_translit_list)

    # Combine token variants into full name combinations, bounded at max_variants
    token_variant_lists = [t.variants for t in token_translit_list]

    full_variants: List[str] = [canonical_full]
    seen_full: Set[str] = {canonical_full}

    for combo in product(*token_variant_lists):
        candidate = " ".join(combo)
        if candidate not in seen_full:
            seen_full.add(candidate)
            full_variants.append(candidate)
            if len(full_variants) >= max_variants:
                break

    return TransliterationResult(
        original=raw_str,
        canonical=canonical_full,
        variants=full_variants[:max_variants],
        version=AMHARIC_TRANSLITERATION_VERSION,
        token_transliterations=token_translit_list,
        is_fully_transliterated=(len(unmapped) == 0),
        unmapped_characters=sorted(list(unmapped)),
    )
