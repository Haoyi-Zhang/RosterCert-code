# Retained input semantics

Each line of `cases.jsonl` is one JSON case. `events` contains records with exactly `id`, `owner`, `active`, `key`, `parents`, and `weight`; parent-to-child edges generate the mathematical order. `lower` and `upper` are ideal event-name sets with the former contained in the latter. `profile` maps identities to exact event IDs. Fork-reduction cases additionally contain the small input graph and its vertex count.

The public-key strings are labels, not cryptographic keys. The parser bounds histories to 64 records, strings to 128 characters, and weights to 100; the exact oracle is used only on much smaller frozen cases. These implementation limits are not the scope of the general theorems.

A cut's active version for one identity is its sole maximal visible same-owner write when that write is active. Multiple incomparable maxima quarantine the identity. A common later write can resolve the fork. Empty mathematical profiles are included as boundary cases, although completed aggregate certificates require a nonempty profile.

The seed is `20260911`. The archived corpus contains 1,200 sampled profile queries, 200 instances of each of four designed infeasible families, 150 chain-optimization cases, and 15 graph-reduction cases. The selector sorts identity names before assigning random draws. `selection-counterexample.json` shows why a fixed pseudorandom seed did not repair iteration over an unordered set. `selection-differences.json` records the affected profiles within the final 1,200-case sampled cohort; event records, bounds, IDs, and family labels are unchanged. These files document the repair without retaining the superseded full result set.

The cases are benign abstract inputs. They are not held-out operational data, real keys, a human study, attack traffic, or a sample from a deployed signing service.

These archived inputs and their outputs are non-evidentiary because the project campaign exceeded its declared cumulative obligation ceiling. They remain useful for source inspection and defect provenance only.
