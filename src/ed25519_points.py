"""Minimal strict validation of raw Ed25519 public-key encodings.

This module validates the 32-byte RFC 8032 compressed point, rejects the identity,
and requires membership in the prime-order subgroup.  It is intentionally limited
to public-key admission for the executable reference profile; signature arithmetic
remains delegated to ``cryptography``.
"""
from __future__ import annotations

_P = 2**255 - 19
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)
_L = 2**252 + 27742317777372353535851937790883648493

# Extended Edwards coordinates (X:Y:Z:T), with x=X/Z, y=Y/Z, XY=ZT.
_IDENTITY = (0, 1, 1, 0)


def _recover_affine(raw: bytes) -> tuple[int, int]:
    if not isinstance(raw, bytes) or len(raw) != 32:
        raise ValueError("Ed25519 public key must be exactly 32 bytes")
    encoded = int.from_bytes(raw, "little")
    sign = encoded >> 255
    y = encoded & ((1 << 255) - 1)
    if y >= _P:
        raise ValueError("Ed25519 public key has a noncanonical y-coordinate")

    y2 = y * y % _P
    denominator = (_D * y2 + 1) % _P
    if denominator == 0:
        raise ValueError("Ed25519 public key does not decode to a curve point")
    x2 = (y2 - 1) * pow(denominator, _P - 2, _P) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        raise ValueError("Ed25519 public key does not decode to a curve point")
    if x == 0 and sign == 1:
        raise ValueError("Ed25519 public key uses the forbidden x=0 sign encoding")
    if (x & 1) != sign:
        x = (-x) % _P
    return x, y


def _add(p: tuple[int, int, int, int], q: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = (2 * _D * t1 * t2) % _P
    d = (2 * z1 * z2) % _P
    e = (b - a) % _P
    f = (d - c) % _P
    g = (d + c) % _P
    h = (b + a) % _P
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _double(p: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x, y, z, _t = p
    a = x * x % _P
    b = y * y % _P
    c = 2 * z * z % _P
    d = (-a) % _P
    e = ((x + y) * (x + y) - a - b) % _P
    g = (d + b) % _P
    f = (g - c) % _P
    h = (d - b) % _P
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _scalar_multiply(point: tuple[int, int, int, int], scalar: int) -> tuple[int, int, int, int]:
    result = _IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = _add(result, addend)
        addend = _double(addend)
        scalar >>= 1
    return result


def _is_identity(point: tuple[int, int, int, int]) -> bool:
    x, y, z, _t = point
    return x % _P == 0 and (y - z) % _P == 0


def validate_public_key_bytes(raw: bytes) -> None:
    """Raise ``ValueError`` unless ``raw`` is a nonidentity prime-order point."""
    x, y = _recover_affine(raw)
    point = (x, y, 1, x * y % _P)
    if _is_identity(point):
        raise ValueError("Ed25519 public key is the identity point")
    if not _is_identity(_scalar_multiply(point, _L)):
        raise ValueError("Ed25519 public key is not in the prime-order subgroup")
