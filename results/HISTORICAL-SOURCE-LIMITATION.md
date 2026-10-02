# Historical session-control source limitation

The retained `semantic.json` lists 12 session-control mutation labels. The corresponding archived call site in `reproduce.py` used two-column rows of the form `[identity, ephemeral_key]`. The only session codec supplied in this project archive is the later V3 interface, which requires `[identity, event, ephemeral_key]` triples.

No exact copy, immutable archive identifier, or independently attributable source for the earlier two-column helper is present in the supplied materials. Consequently, the project cannot truthfully reconstruct the code dependency that produced those 12 archived control results. Updating the call site to V3 would be a new post-hoc implementation and must not be described as the historical source.

`reproduce.py` is therefore disabled before input generation, ledger reservation, or enumeration. The archived result files remain non-evidentiary provenance under `campaign-status.json`; this limitation does not alter the written proofs or the current V3 unit tests.
