# Boundary validation notes

These checks concern the executable Ed25519 reference profile. They do not alter the finite-poset theorems, instantiate the proof-level BGLS construction, or turn the invalidated historical campaign into evidence.

## Text and object encoding

`src/wire_profile.py` supplies the common boundary used by issuance, object verification, and the command-line verifier. Protocol, application, session, namespace, event, owner, parent, profile, and table identifiers are nonempty printable US-ASCII. The application message may contain Unicode scalar values but rejects code points U+D800--U+DFFF. Canonical JSON is produced only after this object-domain check.

`BoundaryTests.test_application_surrogate_alias_is_a_static_collision_but_outside_domain` signs a miniature legacy payload and confirms that `chr(0x1f600)` and the explicit pair `chr(0xd83d)+chr(0xde00)` produced the same `ensure_ascii=True` bytes before the repair. The current issuer, object verifier, and CLI reject the non-ASCII application value. This is a static object-interface regression test, not evidence of a deployed online forgery.

`BoundaryTests.test_unicode_scalar_message_is_injective_and_surrogate_object_is_rejected` confirms that a supplementary scalar is accepted in the message and survives the CLI path, while an explicitly supplied surrogate-pair object is rejected before serialization.

## Active Ed25519 keys

`src/ed25519_points.py` decodes the RFC 8032 compressed point, enforces canonical `y`, rejects the forbidden sign encoding and identity, and requires membership in the prime-order subgroup. `src/reference_profile.py` applies this check to every active history event, whether or not that event is selected, and to the history and ephemeral verification keys.

`BoundaryTests.test_unselected_ff_public_key_is_rejected_as_an_invalid_point` uses an unselected active event with `ff` repeated 32 times. It tests issuance and then re-signs a mutated checkpoint so object and CLI rejection isolate local point admission rather than a stale history signature. Generated valid keys pass; identity and small-order encodings fail.

## Historical session-control source

The retained 12 mutation labels came from an unavailable pre-V3 helper accepting `[identity, ephemeral_key]`. The current V3 contract requires `[identity, event, ephemeral_key]`. `results/HISTORICAL-SOURCE-LIMITATION.md` records that the exact dependency and immutable source identifier are absent. `reproduce.py` is a non-executing limitation reporter and exits before generator imports, input creation, ledger reservation, or enumeration. No V3 adapter is represented as historical provenance.

## Bounded CLI input

`verify_reference.py` opens each path once, reads at most `limit + 1` bytes through that handle, and rejects when the bytes actually read exceed the limit. Boundary tests cover exact-limit and limit-plus-one regular files and a controlled probe that records the single `read(limit + 1)` call. No large-load test is required.

## Protocol-domain mapping

In the article, public parameters `pp=(pp_H, enc, H, ids)` fix the history parameters and serialization algorithms. The protocol tag is an explicit certificate field, appears in the history payload `eta_H`, common session statement `chi`, and certificate `tau`, and is passed to generic history verification. Consequently `(pp,tau)` reconstructs every history, delegation, and base payload without an ambient domain variable. The executable `domain` field realizes this tag.

## Recheck command

```sh
python3 -m unittest discover -s tests -v
python3 audit_artifact.py
python3 verify_reference.py \
  examples/reference-certificate.json \
  examples/reference-history-public-key.txt
```

At delivery, the repository contains 47 unit-test methods. Passing them establishes only the stated implementation checks, not primitive security, theorem correctness, production safety, or independent replication.
