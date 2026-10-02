#!/usr/bin/env python3
"""Static delivery audit for the standalone causal-roster artifact.

This command does not rerun the permanently noncompliant finite scientific
campaign.  It checks only package structure, ledgers, the public Ed25519 fixture,
and synchronization of the self-contained article source.
"""
from __future__ import annotations

import csv
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from reference_profile import certificate_bytes, verify_reference_certificate  # noqa: E402


class AuditError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AuditError(message)


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def main() -> int:
    required = [
        "README.md", "LICENSE", "requirements.txt", "verify_reference.py",
        "generate_reference_example.py", "BOUNDARY-VALIDATION.md",
        "claim_evidence_ledger.csv",
        "literature.csv", "bibliography_audit.csv", "external_resources.csv",
        "proofs/analysis.tex", "proofs/analysis.pdf",
        "src/wire_profile.py", "src/ed25519_points.py",
        "tests/test_boundaries.py",
        "examples/reference-certificate.json",
        "examples/reference-history-public-key.txt",
        "results/campaign-status.json",
        "results/HISTORICAL-SOURCE-LIMITATION.md",
    ]
    missing = [name for name in required if not (ROOT / name).is_file()]
    require(not missing, f"missing required files: {missing}")

    certificate_path = ROOT / "examples/reference-certificate.json"
    anchor_path = ROOT / "examples/reference-history-public-key.txt"
    raw = certificate_path.read_bytes()
    require(len(raw) <= 2 * 1024 * 1024, "reference certificate is unexpectedly large")
    require(raw.decode("ascii").encode("ascii") == raw, "certificate is not ASCII")
    certificate: Any = json.loads(raw)
    anchor = anchor_path.read_text(encoding="ascii").strip()
    require(verify_reference_certificate(certificate, anchor), "reference certificate fails verification")
    require(raw == certificate_bytes(certificate, anchor), "reference certificate is not canonical")

    forbidden_fixture_names = {"private", "private_key", "secret", "seed", "sk", "hsk", "esk", "dsk"}
    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                require(str(key).casefold() not in forbidden_fixture_names,
                        f"fixture contains forbidden secret-like field: {key}")
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)
    walk(certificate)

    literature = read_csv(ROOT / "literature.csv")
    bibliography = read_csv(ROOT / "bibliography_audit.csv")
    resources = read_csv(ROOT / "external_resources.csv")
    claims = read_csv(ROOT / "claim_evidence_ledger.csv")
    require(len(literature) == 80, f"expected 80 literature rows, found {len(literature)}")
    require(len(bibliography) == 80, f"expected 80 bibliography-audit rows, found {len(bibliography)}")
    lit_keys = [row["key"] for row in literature]
    bib_keys = [row["key"] for row in bibliography]
    require(len(set(lit_keys)) == len(lit_keys), "duplicate literature key")
    require(lit_keys == bib_keys, "literature and bibliography audit are not in the same key order")
    require(all(int(row["manuscript_citation_count"]) >= 1 for row in bibliography),
            "one or more retained bibliography entries are uncited")
    identifiers = [row["identifier"] for row in bibliography if row["identifier"]]
    require(len(identifiers) == len(set(identifiers)), "duplicate persistent bibliography identifier")
    require(len({row["title"].casefold() for row in bibliography}) == len(bibliography),
            "duplicate bibliography title")
    require(any(row["name"] == "Python cryptography Ed25519 API" for row in resources),
            "cryptography dependency is absent from the external-resource ledger")
    require(len({row["claim_id"] for row in claims}) == len(claims), "duplicate claim ID")
    require(all(row["maturity"] and row["fresh_recheck"] for row in claims),
            "claim ledger has an empty maturity or recheck field")

    test_methods = 0
    for test_path in sorted((ROOT / "tests").glob("test_*.py")):
        test_methods += len(re.findall(r"(?m)^    def test_[A-Za-z0-9_]+\(",
                                      test_path.read_text(encoding="utf-8")))
    require(test_methods == 47, f"expected 47 unit-test methods, found {test_methods}")

    runner = (ROOT / "reproduce.py").read_text(encoding="utf-8")
    require("from session import" not in runner,
            "disabled archival runner still imports the current session codec")
    require("no enumeration or ledger reservation was started" in runner,
            "archival runner does not state its non-execution boundary")
    require("pre-V3 two-column session-codec source" in runner,
            "archival runner does not disclose the missing source dependency")

    analysis = (ROOT / "proofs/analysis.tex").read_text(encoding="utf-8")
    require("\\input{" not in analysis, "standalone analysis.tex still has an input dependency")
    require("\\bibliography{" not in analysis, "standalone analysis.tex still needs BibTeX")
    bibitems = re.findall(r"(?m)^\\bibitem\{([^}]+)\}", analysis)
    require(len(bibitems) == 80, f"expected 80 embedded bibitems, found {len(bibitems)}")
    require(set(bibitems) == set(lit_keys), "embedded bibliography keys do not match the ledgers")

    campaign = json.loads((ROOT / "results/campaign-status.json").read_text(encoding="utf-8"))
    breach = campaign["terminal_breach"]
    require(campaign["status"] == "permanently noncompliant", "campaign status was weakened")
    require(campaign["evidence_status"] == "all computational outputs are non-evidentiary",
            "campaign evidentiary status was weakened")
    require(int(breach["charged_obligations"]) == 835446, "terminal charge changed")
    require(int(breach["limit"]) == 600000 and int(breach["charged_obligations"]) > int(breach["limit"]),
            "terminal breach is not represented correctly")

    report = {
        "status": "PASS",
        "scope": "static delivery audit only; scientific campaign not rerun",
        "reference_certificate": "valid canonical Ed25519 profile fixture",
        "literature_rows": len(literature),
        "cited_bibliography_rows": len(bibliography),
        "claim_rows": len(claims),
        "unit_test_methods": test_methods,
        "external_resource_rows": len(resources),
        "embedded_bibitems": len(bibitems),
        "campaign_status": campaign["status"],
        "terminal_charged_obligations": int(breach["charged_obligations"]),
        "terminal_limit": int(breach["limit"]),
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AuditError, OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"AUDIT FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
