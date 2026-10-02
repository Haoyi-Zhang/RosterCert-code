# Executable reference certificate

`reference-certificate.json` is a deterministic, public, benign test fixture for the linear Ed25519 profile. `reference-history-public-key.txt` is its independent trust anchor. No private-key file is stored. The generator deliberately exposes deterministic test-key derivation, so every fixture secret is effectively public and unsafe.

Regenerate and verify it from the repository root:

```sh
python3 generate_reference_example.py
python3 verify_reference.py \
  examples/reference-certificate.json \
  examples/reference-history-public-key.txt
```

A valid packaged fixture prints `VALID`. The verifier checks a central history signature, one exact long-term delegation per selected event, and one exact-message session signature per identity/event/ephemeral-key triple. It also validates the semantic context, algorithm identifiers, active-key encodings, identity and role separation, exact table membership, and raw canonical ASCII-JSON bytes.

The fixture demonstrates only that the packaged implementation performs these checks. It is not BGLS aggregation, a pairing benchmark, proof-assistant verification, global-freshness evidence, decentralized governance, or production authorization material.
