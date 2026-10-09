# Fayda QR Signed Content, Byte Rules, and Calendar Specification

This document details the signed-byte rules, cryptographic envelope, field coverage, and date-of-birth (DOB) calendar interpretation for Fayda National ID QR code credentials (Version 4), per the Fayda MCP QR addendum and Ethiopian National ID standards.

---

## 1. Exact Signed-Byte Rules

Fayda National ID Version-4 QR codes secure credential integrity using a **Detached JSON Web Signature (JWS)** per RFC 7515 Appendix F and RFC 7518 Section 3.3.

### 1.1 Detached JWS Structure
The signature segment appears at the end of the QR payload following the `:SIGN:` delimiter:
```text
:SIGN:<base64url_header>..<base64url_signature>
```
- **Protected Header**: `eyJhbGciOiJSUzI1NiJ9` which decodes to `{"alg": "RS256"}`.
- **Empty In-Line Payload**: Represented by the two consecutive dots (`..`), signaling detached payload content per RFC 7515 Appendix F.
- **Signature**: 256-byte (2048-bit) RSA signature using SHA-256 (`RS256`), base64url-encoded.
- **Key Identifier (`kid`)**: Absent from the protected header. Keys must be resolved from the trusted Fayda QR public key bundle.

### 1.2 Signed Byte Envelope (Payload)
The exact signed payload consists of the verbatim UTF-8 encoded text preceding the `:SIGN:` delimiter:
```python
payload_text = qr_text[:qr_text.rfind(":SIGN:")]
payload_bytes = payload_text.encode("utf-8")
```

Per RFC 7515 Section 5.1 and Appendix F, the cryptographic **JWS Signing Input** presented to RSA-SHA256 signature verification is:
```text
ASCII(BASE64URL(UTF8(JWS Protected Header))) || '.' || BASE64URL(JWS Payload Bytes)
```
Where:
- `BASE64URL(UTF8(JWS Protected Header))` is `eyJhbGciOiJSUzI1NiJ9`.
- `BASE64URL(JWS Payload Bytes)` is the URL-safe base64 encoding (without padding) of the exact raw text preceding `:SIGN:`.

---

## 2. Field Coverage & Tamper Evidence

The signature covers the entire credential payload preceding `:SIGN:`, including:

| Field | Tag | In Signature Envelope? | Description |
| :--- | :--- | :---: | :--- |
| **Facial Photo** | *(Initial)* | **Yes** | Base64url-encoded binary WebP image. |
| **Full Name** | `:DLT:` | **Yes** | Full name string (including any trailing whitespace). |
| **Format Version** | `:V:` | **Yes** | Specification format integer (e.g. `4`). |
| **Gender** | `:G:` | **Yes** | Gender code (`M` or `F`). |
| **Fayda Access Number** | `:A:` | **Yes** | 16-digit FAN / Individual ID with formatting spaces. |
| **Date of Birth** | `:D:` | **Yes** | Birthdate text (`YYYY/MM/DD`). |
| **Signature Segment** | `:SIGN:` | **No** | The `:SIGN:` delimiter and JWS token itself are excluded from the payload. |

### Tamper Evidence Invariant
Because the digital signature covers the exact concatenation of all demographic fields and the embedded face photo:
- Modifying the citizen's name, gender, FAN, or date of birth invalidates the signature.
- Swapping or altering the face photo invalidates the signature.
- Changing spaces, delimiters, or casing in the demographic segment invalidates the signature.

---

## 3. Date of Birth Calendar Interpretation

### 3.1 Observed Format
In Version-4 Fayda card QR codes, the date of birth is formatted as:
```text
YYYY/MM/DD
```
For example: `2004/12/28`.

### 3.2 Gregorian Default Convention
- By default, the DOB is treated as **Gregorian** (`YYYY-MM-DD` normalized to ISO 8601).
- In the sample credential `Israel Ashenafi Bekele`, the date `2004/12/28` corresponds to December 28, 2004 Gregorian (producing an adult age of ~20-21 years as of 2024-2026), consistent with Ethiopian national ID issuance to adults.

### 3.3 Ethiopic Calendar Handling
- If Fayda or the host configuration explicitly declares `source_calendar="ethiopic"` (or `EC`), the date `2004/12/28` is interpreted as 28 Tahsas 2004 E.C. (or 28 Hidar/Tahsas depending on month indexing), and converted via the existing Ethiopian calendar conversion library (`fayda_mcp.localization.calendars`).
- **Release Blocker Guarantee ("No ambiguous-calendar age")**:
  If the issuer calendar is unconfirmed, ambiguous, or contested, age predicates must evaluate to `unavailable` rather than guessing or silently assuming an unconfirmed calendar.
