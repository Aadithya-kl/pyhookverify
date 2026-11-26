"""Strict decoders and constant-time comparison helpers.

Every decoder here is canonical: malformed or ambiguous encodings are rejected
instead of being silently repaired. Decoded values are compared only after
length equality is established, using ``hmac.compare_digest`` on ``bytes``.
"""

import base64
import binascii
import hmac
import re
import time

from .errors import HookVerifyError

_HEX_RE = re.compile(r"\A[0-9a-fA-F]*\Z")
_INT_RE = re.compile(r"\A-?[0-9]+\Z")
# RFC 4648 canonical base64: padded, no whitespace, no URL-safe alphabet.
_B64_RE = re.compile(r"\A[A-Za-z0-9+/]*(?:==|=)?\Z")

__all__ = [
    "decode_hex",
    "decode_base64",
    "parse_timestamp",
    "ct_equal",
    "current_time",
    "is_blank",
    "is_safe_header_name",
]

HEADER_NAME_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_-]*\Z")


def is_blank(value: str) -> bool:
    """True when a string is empty or contains only whitespace."""
    return not value.strip()


def decode_hex(value: str, field: str = "signature") -> bytes:
    """Decode a strict, even-length hexadecimal string.

    Rejects whitespace, ``0x`` prefixes, odd length, and non-hex characters.
    """
    if not isinstance(value, str) or not value or len(value) % 2 != 0:
        raise HookVerifyError("invalid_encoding", "%s must be non-empty even-length hex" % field)
    if not _HEX_RE.match(value):
        raise HookVerifyError("invalid_encoding", "%s contains non-hex characters" % field)
    try:
        return bytes.fromhex(value)
    except ValueError:
        # Defensive: the regex above already guarantees validity.
        raise HookVerifyError("invalid_encoding", "%s is not valid hex" % field)


def decode_base64(value: str, field: str = "signature") -> bytes:
    """Decode canonical RFC 4648 base64 with strict padding and zero slack bits.

    Rejects whitespace, URL-safe characters, missing/extra padding, and
    non-canonical final padding bits (e.g. ``Zh==`` where ``Zg==`` is proper).
    """
    if not isinstance(value, str) or not value:
        raise HookVerifyError("invalid_encoding", "%s must be non-empty base64" % field)
    if not _B64_RE.match(value):
        raise HookVerifyError(
            "invalid_encoding", "%s contains non-canonical base64 characters" % field
        )
    if len(value) % 4 != 0:
        raise HookVerifyError("invalid_encoding", "%s has invalid base64 padding" % field)
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, ValueError):
        raise HookVerifyError("invalid_encoding", "%s is not valid base64" % field)
    # Re-encoding is the cheapest exact check that padding bits are zero.
    if base64.b64encode(decoded).decode("ascii") != value:
        raise HookVerifyError(
            "invalid_encoding", "%s has non-canonical base64 padding bits" % field
        )
    return decoded


def parse_timestamp(value: str, field: str = "timestamp") -> int:
    """Parse a strict base-10 integer timestamp (no signs, spaces, or suffixes)."""
    text = value.strip() if isinstance(value, str) else ""
    if not text or not text.isascii() or not text.isdecimal():
        raise HookVerifyError("invalid_timestamp", "%s must be a positive decimal integer" % field)
    # 2 ** 63 - 1 has 19 digits. Reject longer strings before calling int():
    # CPython 3.11+ raises ValueError past 4300 digits, which would escape as
    # an uncaught error, and older builds spend quadratic time converting a
    # multi-megabyte decimal.
    if len(text) > 19:
        raise HookVerifyError("invalid_timestamp", "%s is out of range" % field)
    parsed = int(text)
    if parsed > 2 ** 63 - 1:
        raise HookVerifyError("invalid_timestamp", "%s is out of range" % field)
    return parsed


def ct_equal(left: bytes, right: bytes) -> bool:
    """Constant-time byte equality; unequal lengths never reach compare_digest."""
    if not isinstance(left, bytes) or not isinstance(right, bytes):
        return False
    if len(left) != len(right):
        return False
    return hmac.compare_digest(left, right)


def current_time() -> float:
    """Injectable clock default: POSIX seconds as a float."""
    return time.time()


def is_safe_header_name(name: str) -> bool:
    """Header names accepted by the registry are plain ASCII tokens."""
    return bool(isinstance(name, str) and HEADER_NAME_RE.match(name))
