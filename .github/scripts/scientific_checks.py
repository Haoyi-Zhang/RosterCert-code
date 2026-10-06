"""Check the deterministic owned fixture without rewriting it or running campaigns."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
from generate_reference_example import build
from reference_profile import certificate_bytes


def main() -> int:
    certificate, anchor = build()
    expected = (ROOT / "examples/reference-certificate.json").read_bytes()
    actual = certificate_bytes(certificate, anchor)
    expected_anchor = (ROOT / "examples/reference-history-public-key.txt").read_bytes()
    matches = actual == expected and (anchor + "\n").encode("ascii") == expected_anchor
    print(json.dumps({"check": "deterministic public fixture regeneration",
                      "matches_supplied_bytes": matches, "certificate_bytes": len(actual),
                      "selected_entries": len(certificate["context"]["profile"]),
                      "scope": "one owned synthetic certificate; no historical enumeration, "
                               "primitive-security proof, or deployment test"}, indent=2))
    return 0 if matches else 1


if __name__ == "__main__":
    raise SystemExit(main())
