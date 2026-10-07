# Accountable multisignatures under asynchronous churn

This standalone repository accompanies the internal article **Causal Roster Certificates for Session-Separated Accountable Multisignatures under Asynchronous Churn**.

## What is established

The self-contained article proves:

- an exact interval characterization of all causal cuts authorizing one fixed identity/key-version profile;
- exact historical, view-fresh, and window-robust acceptance modes;
- a session-separated compiler that binds exact long-term versions to fresh one-session keys;
- an explicit signed protocol-domain tag, with public parameters plus the certificate determining every authenticated payload;
- a generic completed-framing reduction;
- a conditional executable Ed25519 signed-checkpoint/delegation/vector profile;
- a conditional key-prefixed BGLS one-session aggregate realization;
- maximum-closure tractability for per-identity chains and NP-completeness with quarantined forks;
- information limits for hidden revocation and undeclared observation.

The Ed25519 profile is implemented and performs real public-key verification. The BGLS profile is a written random-oracle reduction only: this repository does not implement pairings, choose a production curve/hash-to-group suite, or report performance. Neither profile supplies the anchor paper's constant stored registry-key compression, and neither makes the complete causal certificate constant size.

## Permanent campaign warning

The historical finite diagnostic campaign exceeded its declared cumulative ceiling. The superseded controller charged **835,446** obligations against a **600,000** ceiling. Under the governing project rule, that breach is terminal. Later runs and ledgers cannot reset, exclude, or repair it.

Accordingly, all frozen files under `data/` and `results/` are provenance and source-inspection material only. They are not evidence for a theorem, cryptographic property, complexity result, resource claim, or scientific reproduction claim. `results/campaign-status.json` is authoritative. The exact pre-V3 two-column session helper that produced the archived 12 mutation labels is absent; `results/HISTORICAL-SOURCE-LIMITATION.md` records that gap. `reproduce.py` exits before generation, reservation, or enumeration and cannot create evidence.

## Repository map

- `proofs/analysis.tex`, `proofs/analysis.pdf`: self-contained 36-page article with embedded 80-item bibliography.
- `src/roster.py`: finite-poset roster semantics.
- `src/oracle.py`: separately structured exhaustive oracle for small source-integrity cases.
- `src/cases.py`: deterministic historical-corpus generator.
- `src/wire_profile.py`: shared printable-ASCII identifier, Unicode-scalar message, and canonical-JSON boundary.
- `src/ed25519_points.py`: strict canonical, nonidentity, prime-order Ed25519 public-key admission.
- `src/session.py`: semantic normalization and exact history, delegation, and base payload encodings.
- `src/reference_profile.py`: executable Ed25519 checkpoint, delegation, and linear one-session signature profile.
- `verify_reference.py`: single-handle bounded file verifier; requires canonical ASCII JSON bytes.
- `generate_reference_example.py`: deterministic generator for the public, non-secret fixture.
- `examples/`: canonical reference certificate and independent history trust anchor.
- `tests/test_core.py`, `tests/test_reference_profile.py`, `tests/test_boundaries.py`: 47 interface test methods; `tests/test_manuscript_sync.py` adds three scientific-source synchronization regressions.
- `audit_artifact.py`: static package/fixture/ledger/bibliography audit; never invokes the historical scientific runner.
- `BOUNDARY-VALIDATION.md`: focused evidence and non-claims for the five repaired interfaces.
- `claim_evidence_ledger.csv`: material claims mapped to proofs, source checks, and maturity.
- `literature.csv`: 80 scholarly sources with role and disclosed reading depth.
- `bibliography_audit.csv`: persistent-identifier, citation-count, and verification-depth audit for all 80 entries.
- `external_resources.csv`: scholarly/tool records, acquisition mode, license boundary, and integration role.
- `data/`, `results/`: preserved historical diagnostics and terminal campaign/source disclosure; non-evidentiary.
- `reproduce.py`: non-executing limitation reporter; the missing pre-V3 dependency is not reconstructed or replaced.

## Dependency

The executable reference profile requires Python 3 and `cryptography>=41`, as declared in `requirements.txt`. No secret, network service, GPU, private data, or external model is required.

## Source-integrity tests

From the repository root:

```sh
python3 -m unittest discover -s tests -v
```

The current package contains **50** test methods: 47 interface checks and three scientific-source synchronization regressions. They cover semantic malformed inputs, exact identity/event/key binding, all temporal modes, certificate schema strictness, wrong trust anchors, signature and context mutation, aliases across identities or roles, duplicate ephemeral keys, strict validation of every active Ed25519 key (including an unselected `ff`-repeated key), the supplementary-scalar/surrogate-pair serialization alias, printable-ASCII identifiers, Unicode-scalar messages, canonical wire encoding, one-handle `limit+1` reads, duplicate JSON members, and command-line verification. The synchronization regressions retain scientific qualifications, follow nested figure inputs, and distinguish absent sibling source from agreement. The alias test is a static object-interface regression, not evidence of an online forgery. Passing the suite shows that the package executes these checks; it does not prove Ed25519, the general theorems, or deployment security.

## Regenerate and verify the public certificate

Current-version lookup prepares immutable strict-descendant masks once per
admitted roster, then intersects them with present same-owner writes. Cross-owner
descendants do not retire a version; incomparable same-owner maxima still
quarantine, and inactive maxima remain inactive. No measured speedup is claimed.
The separate optional source-integrity regression is also an explicit CI step:

```sh
python3 -B tests/regression_current_versions.py -v
```

It uses only named tiny/admission-boundary fixtures and one existing public
certificate, with an independent graph-path reference and exact payload checks.
It does not enumerate, reopen or provide evidence for the invalidated campaign.
The original 50-method suite and all historical receipts remain unchanged.

```sh
python3 generate_reference_example.py
python3 verify_reference.py \
  examples/reference-certificate.json \
  examples/reference-history-public-key.txt
```

Expected verifier output:

```text
VALID
```

The generator derives deterministic test keys so the fixture is byte-reproducible. Those keys are public and unsafe for real authorization. The verifier rejects a file unless its raw bytes equal the profile's canonical ASCII-JSON encoding.

## Static delivery audit

```sh
python3 audit_artifact.py
```

This checks required files, the Ed25519 fixture, ledgers, 80 embedded bibliography items, citation retention, and the permanent campaign warning. When `../paper/main.tex` exists, it additionally compares the standalone abstract and scientific body with the recursively expanded manuscript; a flat artifact repository explicitly reports this comparison as unavailable. It does not run `reproduce.py`, re-enumerate the corpus, or constitute independent scientific replication.

The bounded workflow in `.github/workflows/scientific-checks.yml` runs the source checks on Ubuntu 24.04 from this flat repository root. It retains failure exit codes and uploads raw logs even on failure. Its owned fixture check can also be run locally without rewriting the supplied example:

```sh
python3 -B .github/scripts/scientific_checks.py
```

That check regenerates one deterministic public certificate in memory and requires byte equality with the supplied certificate and trust anchor. A local run does not establish that the GitHub workflow has run.

## Build the self-contained article

```sh
cd proofs
pdflatex -interaction=nonstopmode -halt-on-error analysis.tex
pdflatex -interaction=nonstopmode -halt-on-error analysis.tex
```

The source contains no `\input`, BibTeX invocation, project-tree path, repository URL, or network dependency. Successful compilation checks typesetting and references only, not mathematical correctness.

## Optional inspection of historical code

`reproduce.py` does not reproduce the campaign. It reports that the cumulative campaign is terminally invalid and that the exact pre-V3 two-column session-codec dependency is missing, then exits before importing generators or reserving work. Adapting calls to the current three-column V3 contract would be a new program and must not be described as historical provenance.

## Cryptographic boundary

The executable profile uses three independently modelled Ed25519 roles:

1. a central history-checkpoint key;
2. active long-term version/delegation keys; and
3. fresh one-session keys.

All identifiers use one printable US-ASCII boundary; messages use Unicode scalar values and reject explicit surrogate code points before canonical ASCII escaping. Issuance, object verification, and the CLI share this normalization. Every active event key, selected or not, must be a canonical nonidentity point in the prime-order Ed25519 subgroup; hexadecimal length alone is insufficient. The profile also rejects byte reuse across roles and one active long-term key assigned to two identities, while permitting same-owner reuse across event versions because every payload binds the exact event ID. It has no secure key store, randomness service, erasure guarantee, rollback protection, replay database, governance implementation, transparency consistency proof, or availability protocol.

The proof-level BGLS profile uses validated type-III public-key pairs, public-key-prefixed messages, and a complete table/message/signer-set encoding. Its aggregate is one source-group element; the table and other certificate evidence remain linear. Current BLS implementation guidance is used for validation practice only, while the cited multi-user BLS/BGLS paper supplies the security theorem.

## Trust, licensing, and external use

Event authenticity, admission, ownership, and observation completeness are explicit inputs, not inferred from signatures alone. A received authenticated upper view cannot reveal a remote update that was never delivered.

Project source and benign generated fixtures are provided under `LICENSE`. No publisher paper text, third-party implementation, credential, or private data is redistributed.
