# authority-bounds v0 vectors: provenance

`vectors.json` in this directory is a byte-for-byte copy of
`conformance/authority-bounds/v0/vectors.json` in the TypeScript SDK
(`aeoess/agent-passport-system`), which is where it is authored.

    SHA-256  7d8818f4d28661876bfc73a8ae7f2dce27e132ee942706d10a6ae8c460dac7f2

Both repositories pin that digest inside their own parity test
(`tests/v2/bounds.test.ts` and `tests/test_bounds.py`), so the two copies can be shown
identical without either repository importing the other, and a one-sided edit fails the
test on the side that was edited.

## What is hand specified and what is minted

Hand specified, and therefore not circular: every `bound_state`, `reason_code`, `ending`,
`lifecycle` verdict, `missing` limb set, expected boolean and expected error code.

Minted once by the TypeScript implementation: the `signature` values and the
`exhaustion_id` values. Those exist for the cross-language check. This Python port signs
and content-addresses the same bodies with the same private keys and has to produce the
same characters, so reading them here proves parity rather than restating the TypeScript
answer. The private keys are derived from fixed labels, so the whole file is reproducible.

## Status

PROPOSED and OPT-IN. Not required by draft-pidlisnyi-aps-03, whose relevant text is quoted
verbatim in the file's own `specification_position` block, alongside the SHA-256 of the
draft text those quotes came from. Concept source: the aeoess/agent-authority-lifecycle
concept document, invariant L10 and invariant candidates CAND-01 and CAND-02.
