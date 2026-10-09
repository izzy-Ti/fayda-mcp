# Fayda QR Code Credential Profile Specification

This document specifies the structure, delimiters, field definitions, encoding rules, and cryptographic conventions for the physical Fayda National ID QR code credential profile (Format Version 4), per the Fayda MCP QR addendum and Ethiopian National ID standards.

---

## 1. Scope & System Overview

A Fayda National ID card carries a high-density 2D QR code printed on the physical credential. When scanned by an optical barcode reader, camera, or mobile device, the scanner produces an unchanged raw ASCII/UTF-8 text payload.

The QR verification workflow establishes:
- **Credential Origin & Integrity**: Digital signature validation confirms that the credential payload was issued by the authorized National ID Authority (Fayda) and has not been tampered with.
- **Offline / Edge Verification**: Allows verification without an active Internet connection or live OIDC authorization redirect to eSignet.
- **Strict Boundary**: A scanned QR code proves credential integrity, but does **not** authenticate physical cardholder possession or live human presence. Offline QR verification does not check real-time registry revocation status.

---

## 2. Supported Versions

| Version Identifier | Status | Description |
| :--- | :--- | :--- |
| **`4`** | **Supported (Current Standard)** | Active format deployed on printed Fayda National ID cards. |
| Other / Unknown | **Rejected** | Future or legacy versions are rejected until explicit parsing profiles are configured to prevent parser confusion or signature bypass. |

---

## 3. Delimiter Structure & Segment Layout

A Version-4 Fayda QR text payload consists of sequential tagged segments:

```
<PhotoBase64Url>DLT<FullName>V<Version>G<Gender>A<FAN>D<DateOfBirth>SIGN<DetachedJWS>
```

### Segment Breakdown

| Delimiter / Tag | Name | Description |
| :--- | :--- | :--- |
| *(Initial)* | **Photo Segment** | Raw base64url-encoded string at the start of the payload, preceding `DLT`. Contains the compressed WebP photo. |
| `DLT` | **Name Delimiter** | Introduces the citizen's full name. Acts as the boundary between the initial photo segment and demographic fields. |
| `V` | **Version Tag** | Format version indicator. For Version-4 credentials, the value is `4`. |
| `G` | **Gender Tag** | Citizen gender code. Expected value is `M` (Male) or `F` (Female). |
| `A` | **Access Number Tag** | Introduces the 16-digit Fayda Access Number (FAN) / Individual ID. |
| `D` | **Date of Birth Tag** | Introduces the birthdate text formatted as `YYYY/MM/DD`. |
| `SIGN` | **Signature Tag** | Introduces the detached JWS digital signature string. |

---

## 4. Field Meanings and Data Formats

### 1. Photo (`photo_base64url`)
- **Meaning**: Facial photograph of the citizen captured during National ID enrollment.
- **Image Format**: Embedded binary image compressed in WebP format (`image/webp`).
- **Encoding**: URL-safe Base64 (`base64url`, RFC 4648 Section 5) without padding characters.
- **Security Note**: The embedded photo is not a QR image and does not prove live person presence without independent facial comparison/liveness verification.

### 2. Full Name (`name`)
- **Meaning**: Official full name of the citizen as recorded in the Fayda registry (introduced by `DLT`).
- **Format**: UTF-8 string (typically English / Latin script and/or localized Amharic script).

### 3. QR Format Version (`version`)
- **Meaning**: Specification schema version of the QR data format.
- **Value**: Integer `4` for version-4 credentials.

### 4. Gender (`gender`)
- **Meaning**: Recorded administrative sex/gender of the cardholder.
- **Values**: `M` (Male) or `F` (Female).

### 5. Fayda Access Number (`fan`)
- **Meaning**: 16-digit individual credential identification number (FAN).
- **Format**: 16 alphanumeric / numeric characters (e.g. `1234567890123456`).

### 6. Date of Birth (`birthdate`)
- **Meaning**: Cardholder date of birth.
- **Format**: Text string formatted as `YYYY/MM/DD` (e.g., `1995/04/12`).
- **Calendar Convention**: Gregorian date format by default. Ethiopic calendar calculations require explicit configuration and confirmed issuer metadata.

### 7. Digital Signature (`signature`)
- **Meaning**: Detached JSON Web Signature (JWS) sealing the credential content.
- **Format**: Detached JWS format per RFC 7515 Appendix F: `<base64url_header>..<base64url_signature>` with an empty payload between the period separators.
- **Header**: Compact JSON object containing `{"alg": "RS256"}` (RSA signature with SHA-256). Observed headers contain no `kid` (Key ID), requiring resolution via the trusted QR public key bundle.

---

## 5. Excluded and Absent Fields

The Version-4 QR profile is strictly minimal:
- **No Contact Data**: The QR payload contains **no** phone number (`phone_number`) and **no** email address (`email`).
- **No Address Fields**: Contains **no** postal, region, zone, or residential address data.
- **No Biometric Minutiae**: Contains **no** fingerprint templates or iris codes.

---

## 6. Verification and Security Semantics

1. **Origin Integrity**:
   A mathematically valid detached signature establishes that the content was generated by the National ID authority holding the corresponding private signing key.
2. **Replay & Copied Credentials**:
   A photocopied, cloned, or screenshotted QR code retains the identical cryptographic signature. Verifying the signature confirms that the *data* is authentic, but does **not** prove that the presenter is the legitimate cardholder.
3. **Disjoint Outcomes**:
   - `credential_signature_valid`: Set to `true` when the signature matches the configured public key.
   - `holder_authenticated`: Remains `false` for QR-only evidence because scanning alone does not authenticate the live holder.
   - `identity_verified`: Must **not** be asserted from QR-only evidence without live holder authentication (e.g., eSignet OIDC or matched biometric verification).
