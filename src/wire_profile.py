"""Shared text and canonical-JSON boundary for the executable reference profile.

The accepted object domain is deliberately narrower than Python's ``str`` domain.
Identifiers are nonempty printable US-ASCII.  The application message may contain
Unicode scalar values, but explicit UTF-16 surrogate code points are rejected.
Rejecting surrogates is necessary because ``json.dumps(..., ensure_ascii=True)``
encodes one supplementary scalar and an explicitly supplied surrogate pair to the
same escape sequence.
"""
from __future__ import annotations

import json
from typing import Any

MAX_IDENTIFIER = 128
MAX_MESSAGE = 4096
MAX_KEY_TEXT = 256


def _has_surrogate(value: str) -> bool:
    return any(0xD800 <= ord(ch) <= 0xDFFF for ch in value)


def scalar_text(
    value: Any,
    field: str,
    *,
    allow_empty: bool = False,
    limit: int,
) -> str:
    """Validate bounded Unicode scalar text and return it unchanged."""
    if not isinstance(value, str):
        raise ValueError(f"{field} must be text")
    if (not allow_empty and not value) or len(value) > limit:
        raise ValueError(f"{field} has invalid length")
    if _has_surrogate(value):
        raise ValueError(f"{field} contains a UTF-16 surrogate code point")
    return value


def ascii_identifier(
    value: Any,
    field: str,
    *,
    allow_empty: bool = False,
    limit: int = MAX_IDENTIFIER,
) -> str:
    """Validate a bounded identifier in printable US-ASCII (U+0021..U+007E)."""
    text = scalar_text(value, field, allow_empty=allow_empty, limit=limit)
    if any(ord(ch) < 0x21 or ord(ch) > 0x7E for ch in text):
        raise ValueError(f"{field} must use printable US-ASCII without whitespace")
    return text


def _validate_json_tree(value: Any, path: str = "value") -> None:
    """Reject strings outside the Unicode-scalar domain before JSON escaping."""
    if isinstance(value, str):
        if _has_surrogate(value):
            raise ValueError(f"{path} contains a UTF-16 surrogate code point")
        return
    if value is None or type(value) in (bool, int):
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            _validate_json_tree(child, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{path} has a non-text object key")
            if _has_surrogate(key):
                raise ValueError(f"{path} has a surrogate-containing object key")
            _validate_json_tree(child, f"{path}.{key}")
        return
    raise ValueError(f"{path} contains a value outside the canonical JSON profile")


def canonical_json(value: Any) -> bytes:
    """Return the sole deterministic JSON encoding for accepted profile objects."""
    _validate_json_tree(value)
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")
