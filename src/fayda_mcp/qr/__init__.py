"""Fayda National ID QR code credential verification package.

Implements offline/edge parsing, signature verification, and privacy-filtered
result evaluation for printed Fayda National ID QR credentials.
"""

# Supported QR specification versions
SUPPORTED_QR_VERSIONS = (4,)
DEFAULT_QR_VERSION = 4

# Delimiter tags in Version-4 QR layout
TAG_NAME_INTRO = "DLT"
TAG_VERSION = "V"
TAG_GENDER = "G"
TAG_FAN = "A"
TAG_DOB = "D"
TAG_SIGNATURE = "SIGN"

QR_DELIMITERS = (
    TAG_NAME_INTRO,
    TAG_VERSION,
    TAG_GENDER,
    TAG_FAN,
    TAG_DOB,
    TAG_SIGNATURE,
)

__all__ = [
    "SUPPORTED_QR_VERSIONS",
    "DEFAULT_QR_VERSION",
    "TAG_NAME_INTRO",
    "TAG_VERSION",
    "TAG_GENDER",
    "TAG_FAN",
    "TAG_DOB",
    "TAG_SIGNATURE",
    "QR_DELIMITERS",
]
