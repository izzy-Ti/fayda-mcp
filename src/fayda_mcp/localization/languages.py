"""Regional language normalization and localization module for Fayda MCP.

Supports selection targets:
- en: English
- am: Amharic (አማርኛ)
- om: Afaan Oromoo
- so: Somali (Soomaali)
- ti: Tigrinya (ትግርኛ)
- sid: Sidaamu Afoo
- wal: Wolaytta

Accepts:
- Localized claim keys (e.g. name#om, family_name#am)
- Documented language/value dictionaries (e.g. {"@value": "...", "@language": "..."})
- Language code mappings (e.g. ISO 639-2 amh -> am, eng -> en, orm -> om)
- Preserves original Unicode text and never transliterates without explicit request.
- Never stringifies a raw dict/object as a string name.
"""

from typing import Any, Dict, List, Optional, Set, Tuple


# Supported selection targets in Fayda normalization
SUPPORTED_LOCALES: Set[str] = {"en", "am", "om", "so", "ti", "sid", "wal"}

# Catalog mapping provider-specific or ISO 639-2/3 language codes to canonical BCP 47 targets
PROVIDER_LANGUAGE_CATALOG: Dict[str, str] = {
    # English
    "en": "en",
    "eng": "en",
    "en-us": "en",
    "en-gb": "en",
    # Amharic
    "am": "am",
    "amh": "am",
    "am-et": "am",
    # Afaan Oromoo
    "om": "om",
    "orm": "om",
    "oro": "om",
    "om-et": "om",
    # Somali
    "so": "so",
    "som": "so",
    "so-et": "so",
    # Tigrinya
    "ti": "ti",
    "tir": "ti",
    "tig": "ti",
    "ti-et": "ti",
    # Sidama
    "sid": "sid",
    "sid-et": "sid",
    # Wolaytta
    "wal": "wal",
    "wol": "wal",
    "wal-et": "wal",
}


def normalize_language_tag(tag: Optional[str]) -> Optional[str]:
    """Normalize language tag case-insensitively and map provider codes to canonical target."""
    if not tag or not isinstance(tag, str):
        return None

    cleaned = tag.strip().lower()
    if not cleaned:
        return None

    # Direct catalog lookup
    if cleaned in PROVIDER_LANGUAGE_CATALOG:
        return PROVIDER_LANGUAGE_CATALOG[cleaned]

    # Split subtag (e.g. "en-us" -> primary "en")
    parts = cleaned.replace("_", "-").split("-")
    primary = parts[0]
    if primary in PROVIDER_LANGUAGE_CATALOG:
        return PROVIDER_LANGUAGE_CATALOG[primary]
    if primary in SUPPORTED_LOCALES:
        return primary

    return None


def select_localized_value(
    val: Any,
    preferred_locales: Optional[List[str]] = None,
    fallback_locale: str = "en",
) -> Optional[str]:
    """Select appropriate localized string from string, dictionary, or list of localized dicts.

    Selection priority:
    1. Exact preference match in order of preferred_locales
    2. Primary language match
    3. Configured fallback locale
    4. First available plain string

    Preserves original Unicode text without transliteration.
    Never stringifies a raw dict or object as a name.
    """
    if val is None:
        return None

    if isinstance(val, str):
        s = val.strip()
        return s if s else None

    # Handle dictionary of languages, e.g. {"en": "Abebe", "am": "አበበ"}
    # or eSignet {"@value": "Abebe", "@language": "en"}
    if isinstance(val, dict):
        # Case A: {"@value": "...", "@language": "..."}
        if "@value" in val:
            content = val.get("@value")
            if not isinstance(content, str):
                return None
            return content.strip()

        # Build map of canonical_lang -> text
        lang_map: Dict[str, str] = {}
        untagged: Optional[str] = None

        for k, v in val.items():
            if not isinstance(v, str):
                continue
            text = v.strip()
            if not text:
                continue

            k_norm = normalize_language_tag(k)
            if k_norm:
                lang_map[k_norm] = text
            elif k.lower() in ("default", "val", "value"):
                untagged = text

        return _pick_from_map(lang_map, preferred_locales, fallback_locale, untagged)

    # Handle list of localized dicts, e.g. [{"@value": "አበበ", "@language": "am"}, ...]
    if isinstance(val, list):
        lang_map = {}
        untagged = None

        for item in val:
            if isinstance(item, str):
                if untagged is None:
                    untagged = item.strip()
            elif isinstance(item, dict):
                content = item.get("@value") or item.get("value")
                if not isinstance(content, str) or not content.strip():
                    continue
                lang_tag = item.get("@language") or item.get("language") or item.get("lang")
                norm_tag = normalize_language_tag(str(lang_tag)) if lang_tag else None
                if norm_tag:
                    lang_map[norm_tag] = content.strip()
                elif untagged is None:
                    untagged = content.strip()

        return _pick_from_map(lang_map, preferred_locales, fallback_locale, untagged)

    return None


def _pick_from_map(
    lang_map: Dict[str, str],
    preferred_locales: Optional[List[str]],
    fallback_locale: str,
    untagged: Optional[str],
) -> Optional[str]:
    # 1. Preferred locales in priority order
    if preferred_locales:
        for pref in preferred_locales:
            norm_pref = normalize_language_tag(pref)
            if norm_pref and norm_pref in lang_map:
                return lang_map[norm_pref]

    # 2. Configured fallback locale
    norm_fallback = normalize_language_tag(fallback_locale)
    if norm_fallback and norm_fallback in lang_map:
        return lang_map[norm_fallback]

    # 3. Untagged field
    if untagged:
        return untagged

    # 4. Any available language in the map
    if lang_map:
        return next(iter(lang_map.values()))

    return None


def extract_localized_claim(
    claims: Dict[str, Any],
    base_claim_name: str,
    preferred_locales: Optional[List[str]] = None,
    fallback_locale: str = "en",
) -> Optional[str]:
    """Extract localized claim supporting localized claim keys (e.g. name#om, name#am).

    Looks for keys with format `{base_claim_name}#{locale}` or direct `{base_claim_name}`.
    """
    # 1. Check for localized keys in claims dictionary: e.g. name#om, name#am
    key_lang_map: Dict[str, str] = {}
    for k, v in claims.items():
        if not isinstance(v, str) or not v.strip():
            continue
        if "#" in k:
            parts = k.split("#", 1)
            if parts[0].lower() == base_claim_name.lower():
                norm_tag = normalize_language_tag(parts[1])
                if norm_tag:
                    key_lang_map[norm_tag] = v.strip()

    # If localized keys were present, pick according to preference
    if key_lang_map:
        picked = _pick_from_map(key_lang_map, preferred_locales, fallback_locale, untagged=None)
        if picked:
            return picked

    # 2. Check base claim name directly
    direct_val = claims.get(base_claim_name)
    if direct_val is not None:
        return select_localized_value(direct_val, preferred_locales, fallback_locale)

    return None
