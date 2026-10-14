# Citizen Details Matching (`details-v1`)

**Document Version:** 1.0.0  
**Status:** Canonical Security Architecture & Specification  
**Reference:** Fayda MCP Citizen Details Matching Addendum

---

## 1. Executive Summary

The **Citizen Details Matching** system enables relying parties (banks, telecom providers, government portals) to compare citizen-submitted identity claims (such as applicant name and date of birth) against authoritative National ID (Fayda eSignet) records **without exposing or retaining raw citizen demographics, biometrics, or tokens**.

```
+-----------------------------------------------------------------------------------------+
|                         DETAILS MATCHING ARCHITECTURE FLOW                              |
+-----------------------------------------------------------------------------------------+
|                                                                                         |
| 1. Backend Expected Submission       POST /verification/details/expected                |
|    Relying Backend ----------------> [ DetailsMatchingService ]                         |
|                                      • Validates inputs & bounds TTL (60s-3600s)        |
|                                      • Encrypts details at rest with AES-256-GCM        |
|                                      • Generates opaque reference (ed_...)              |
|                                                                                         |
| 2. Agent Verification Launch         start_details_verification(ref, purpose, user, ...) |
|    MCP Agent / Client -------------> [ FastMCP Tool ]                                   |
|                                      • Enforces tenant & principal caller ownership     |
|                                      • Single-use binding (prevents replay)             |
|                                      • Reuses eSignet OIDC flow with scopes & claims    |
|                                      • Returns auth URL + request_id (vr_...)           |
|                                                                                         |
| 3. Citizen Auth & Callback           GET /callback?code=...&state=...                   |
|    Citizen -> eSignet -------------> [ FaydaVerificationService.complete_verification ] |
|                                      • Exchanges code for tokens via private_key_jwt    |
|                                      • Validates ID Token & UserInfo claims             |
|                                      • Runs deterministic matching (NFC, casefold, cal) |
|                                      • Discards raw claims from memory immediately      |
|                                      • Purges expected details ciphertext               |
|                                      • Persists minimal tri-state match flags           |
|                                                                                         |
| 4. Agent Result Retrieval            get_details_match_result(request_id)               |
|    MCP Agent / Client -------------> [ FastMCP Tool ]                                   |
|                                      • Checks caller ownership & TTL expiry             |
|                                      • Returns tri-state flags, timestamps, reasons     |
|                                      • ZERO names, DOBs, FANs, or tokens returned       |
|                                                                                         |
+-----------------------------------------------------------------------------------------+
```

---

## 2. Core Security Invariants

1. **Zero Raw Demographic / Token Leakage**:
   The MCP tool surface never returns citizen names, dates of birth, National ID Numbers (FAN/FIN), id tokens, or access tokens. Only opaque request IDs, tri-state match flags, safe reason codes, and comparison policy versions are returned.
2. **Short TTL & Ephemeral Retention**:
   Expected details records are held strictly in temporary storage with an explicit time-to-live (`expected_details_ttl_seconds`, default 900s, bounds 60s–3600s). Once the verification callback executes, expected details are automatically and permanently purged.
3. **AES-256-GCM Encryption at Rest**:
   Temporary retained details are encrypted before persistence using authenticated AES-256-GCM encryption with randomized 96-bit nonces. Keys are derived per tenant/deployment using PBKDF2/HMAC-SHA256.
4. **Single-Use Binding & Replay Prevention**:
   An `expected_details_ref` can be bound to exactly one verification request. Once bound, subsequent attempts to start verification with the same reference are rejected (`details_already_bound`).
5. **Multi-Tenant & Principal Isolation**:
   Every expected details submission and verification request is tagged with the caller's `tenant_id` and `principal_id`. Cross-caller access is strictly rejected at all tool and API endpoints.

---

## 3. Tri-State Match Semantics

Every compared field evaluates to a tri-state outcome:

| Match Flag | JSON Representation | Meaning |
| :--- | :--- | :--- |
| `True` | `true` | The normalized expected detail matches the normalized provider claim exactly. |
| `False` | `false` | Both values were available and valid, but their normalized forms differ. |
| `None` | `null` | The field could not be compared (e.g., missing claim, partial DOB, ungranted scope). |

### Overall `matching_status`

The overall matching status is derived deterministically from the tri-state field flags:

- `"matched"`: Every evaluated field matched (`True`).
- `"mismatched"`: At least one evaluated field failed to match (`False`).
- `"unavailable"`: No field failed, but one or more fields were unresolvable (`None`).
- `"pending"`: Verification journey has been launched but citizen has not yet authenticated via callback.

---

## 4. Deterministic Comparison Rules

Matching adheres to comparison policy version `details-v1`:

### Name Comparison (`compare_names`)
1. **Unicode NFC Normalization**: Decomposed Unicode characters (e.g., `'e'` + combining acute accent) are converted to precomposed form (`unicodedata.normalize("NFC", name)`).
2. **Full Unicode Case-Folding**: Applied via `str.casefold()` (handling uppercase, lowercase, and complex mappings like German `ß` to `ss`).
3. **Whitespace Collapsing**: Leading, trailing, and internal whitespace runs (tabs, spaces, newlines) are collapsed to a single ASCII space.
4. **Script & Token Order Preservation**:
   - Ge'ez / Amharic script is preserved without automatic transliteration.
   - Word token order is strictly preserved (`"Abebe Bikila"` does NOT match `"Bikila Abebe"`).

### Date of Birth Comparison (`compare_dates`)
1. **Explicit Calendar Normalization**:
   - Both expected and provider birthdates require explicit calendar identification (`"gregorian"` or `"ethiopic"`).
   - Ethiopic dates (Amete Mihret) are explicitly converted to astronomical Gregorian equivalents.
2. **Rejection of Partial or Ambiguous Dates**:
   - Partial dates (`"1990"`, `"1990-05"`, wildcard zeros `"0000-05-12"`) strictly evaluate to `None` with reason `"partial_dob_unavailable"`.
   - Two-digit years (`"95-04-12"`) evaluate deterministically against full calendar years, preventing false positives.
   - Unparseable or non-existent dates (`"1990-02-30"`) evaluate to `None` with reason `"invalid_date_format"`.
3. **Format Agnosticism**: Hyphens (`YYYY-MM-DD`) and slashes (`YYYY/MM/DD`) are normalized equivalently.

---

## 5. MCP Tool Reference

### `start_details_verification`
Launches citizen details verification by binding an authenticated expected details reference to an eSignet authorization journey.

- **Parameters**:
  - `expected_details_ref` (string, required): Opaque reference token starting with `ed_`.
  - `purpose` (string, required): Stated purpose (e.g., `"onboarding"`, `"kyc"`).
  - `application_user_ref` (string, required): Scoped user identifier matching the registered expectation.
  - `idempotency_key` (string, optional): Idempotency key for safe client retries.
- **Returns**: `StartDetailsVerificationResponse` with `request_id`, `authorization_url`, and `expires_at`.

### `get_details_match_result`
Retrieves minimal citizen details match outcome by opaque request identifier.

- **Parameters**:
  - `request_id` (string, required): Unique verification request identifier (`vr_...`).
- **Returns**: `DetailsMatchResult`:
  - `request_id` (str)
  - `matching_status` (`"matched" | "mismatched" | "unavailable" | "pending"`)
  - `matches` (dict mapping field names to `true | false | null`)
  - `reasons` (dict mapping field names to safe machine-readable reason codes)
  - `comparison_policy_version` (`"details-v1"`)
  - `checked_at` (ISO 8601 UTC timestamp or `None`)
  - `expires_at` (ISO 8601 UTC timestamp)
  - `evidence_ref` (string reference or `None`)
  - `identity_authenticated` (boolean indicating whether citizen authenticated with Fayda)

---

## 6. Backend Expected Submission API

Relying parties register citizen expected details through an authenticated backend endpoint before directing the MCP agent or citizen:

```http
POST /verification/details/expected HTTP/1.1
Host: api.partner.bank.et
Authorization: Bearer <service_token>
Content-Type: application/json

{
  "application_user_ref": "cust_98765",
  "purpose": "onboarding",
  "expected_details": {
    "full_name": "Abebe Bikila",
    "date_of_birth": "1995/04/12",
    "dob_calendar": "gregorian"
  },
  "ttl_seconds": 900
}
```

**Response (`201 Created`)**:
```json
{
  "expected_details_ref": "ed_4f8a9b1c2d3e4f5a6b7c8d9e",
  "expires_at": "2026-10-14T07:35:00Z",
  "application_user_ref": "cust_98765",
  "purpose": "onboarding"
}
```

---

## 7. Retries & Error Handling

- **Typo / Changed Input Retries**: If matching fails (`"mismatched"`), the applicant can correct their input. The relying party submits a new expected details payload (generating a new `ed_...` reference) and launches a fresh verification with a new idempotency key.
- **Reference Expiration**: Expired references return `DetailsReferenceExpiredError` (or `VerificationNotFoundError` on result retrieval).
- **Cross-Tenant Access**: Access attempts across tenant or principal boundaries are logged to audit trails and rejected with HTTP 403 / `AuthorizationError`.
