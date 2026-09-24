# `chain-selection-v0-vectors.json` provenance

Vendored byte for byte from the TypeScript SDK. Nothing in this repository
generates or edits it. A change to its bytes is a change to what both
implementations are asserted to do, and it belongs upstream, in the repository
named below, not here.

| field | value |
|---|---|
| source repository | `aeoess/agent-passport-system` (TypeScript SDK) |
| source path | `fixtures/chain-selection/chain-selection-vectors-v0.json` |
| generator | `fixtures/chain-selection/generate-fixtures.ts` in that repository |
| generator reference commit | `86fe72df0bbf998b4e952976eefeebcb04753c20`, the `src/` tree whose implementation produced every recorded outcome, also written inside the JSON at `sdk_commit` |
| SDK commit carrying the file | `08aa690526f909bf47b05c49fb0ef6cf8f9f63ba`, the commit that adds `src/v2/chain-selection` and this vector file |
| SHA-256 of the file as vendored | `ccef7e27b6af314a0c49dc3d957579592565b521b9ecacf3d54c5e9b3f82d753` |

`tests/cross_impl/test_chain_selection_v0_vectors.py` asserts that SHA-256
against the file on disk, so the vendored copy cannot drift from the bytes this
port was checked against without a test saying so.

The two commits differ on purpose. `86fe72d` pins the implementation the recorded
outcomes came from, and the module and the vector file were added on top of it,
so the commit that carries the file is the later `08aa690`.

To re-fetch the exact bytes:

```
git -C <agent-passport-system> show 08aa690:fixtures/chain-selection/chain-selection-vectors-v0.json
```

## Renamed on vendoring

`chain-selection-vectors-v0.json` upstream, `chain-selection-v0-vectors.json`
here, matching the `<name>-<version>-vectors.json` shape the other vendored
vector files in this directory already use.

## What it covers

draft-pidlisnyi-aps-03 section 3.3 lines 594-596 for selection and for the
refusal to union, in cases CS-01 to CS-07 and CS-12 to CS-19. Cases CS-08 to
CS-11 exercise the fallback surface, which is **proposed, not draft-03**, against
invariant candidate L11 of the `aeoess/agent-authority-lifecycle` concept
document.
