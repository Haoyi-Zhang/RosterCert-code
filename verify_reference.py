#!/usr/bin/env python3
"""Verify a canonical causal-roster Ed25519 reference-certificate file."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
from reference_profile import (  # noqa: E402
    certificate_bytes,
    verify_reference_certificate,
)

# The semantic model permits at most 64 events and bounded strings.  Two MiB is far
# above any valid profile produced by this repository while avoiding an unbounded
# read of attacker-selected input.  This is a reference-tool guard, not a protocol
# transport limit.
MAX_CERTIFICATE_BYTES = 2 * 1024 * 1024
MAX_TRUST_ANCHOR_BYTES = 256


def _bounded_read(path: Path, limit: int, label: str) -> bytes:
    """Read at most ``limit + 1`` bytes from one already-opened file handle."""
    if type(limit) is not int or limit < 0:
        raise ValueError("read limit must be a nonnegative integer")
    try:
        with path.open("rb") as handle:
            raw = handle.read(limit + 1)
    except OSError as exc:
        raise ValueError(f"cannot read {label}: {exc}") from exc
    if len(raw) > limit:
        raise ValueError(f"{label} exceeds {limit} bytes")
    return raw


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("certificate", type=Path)
    parser.add_argument("history_public_key", type=Path)
    args = parser.parse_args()
    try:
        raw = _bounded_read(args.certificate, MAX_CERTIFICATE_BYTES, "certificate")
        anchor_raw = _bounded_read(
            args.history_public_key, MAX_TRUST_ANCHOR_BYTES, "history public key"
        )
        certificate = json.loads(raw.decode("ascii"))
        authority = anchor_raw.decode("ascii").strip()
    except (ValueError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        print(f"INVALID: cannot read input: {exc}", file=sys.stderr)
        return 2
    if not verify_reference_certificate(certificate, authority):
        print("INVALID", file=sys.stderr)
        return 1
    try:
        canonical = certificate_bytes(certificate, authority)
    except (ValueError, RecursionError):
        print("INVALID", file=sys.stderr)
        return 1
    if raw != canonical:
        print("INVALID: certificate file is not canonical ASCII JSON", file=sys.stderr)
        return 1
    print("VALID")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
