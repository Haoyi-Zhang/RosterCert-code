#!/usr/bin/env python3
"""Explain why the archived finite campaign cannot be reproduced here.

The campaign is permanently noncompliant because its cumulative obligation count
exceeded the declared ceiling.  Independently, the supplied archive lacks the exact
pre-V3 session-codec source that produced the retained 12 session-control labels:
those labels came from a two-column ``[identity, ephemeral_key]`` table, while the
current V3 contract requires ``[identity, event, ephemeral_key]`` triples.

Adapting the archived calls to V3 would create a new post-hoc program, not recover
historical provenance.  This command therefore exits before importing generators,
creating inputs, reserving a ledger entry, or enumerating any case.
"""
from __future__ import annotations

import argparse
import sys


LIMITATION = (
    "DISABLED: the finite campaign is terminally noncompliant and the exact "
    "pre-V3 two-column session-codec source used for the archived 12 controls "
    "is not present. The current three-column V3 codec is not a historical "
    "replacement; no enumeration or ledger reservation was started."
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--explain",
        action="store_true",
        help="print the archival limitation (the runner is always disabled)",
    )
    parser.parse_args()
    print(LIMITATION, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
