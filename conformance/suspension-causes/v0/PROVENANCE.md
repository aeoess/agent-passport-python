# suspension-causes v0 vectors: provenance

`vectors.json` in this directory is a byte-for-byte copy of
`conformance/suspension-causes/v0/vectors.json` in the TypeScript SDK
(`aeoess/agent-passport-system`), which is where it is authored.

    SHA-256  fc4c04b53299d35cb7bc810565f5bf8b7a1fea1d5b2e53478778a3642728df97

Both repositories pin that digest inside their own parity test
(`tests/v2/suspension.test.ts` and `tests/test_suspension.py`), so the two copies can be
shown identical without either repository importing the other, and a one-sided edit fails
the test on the side that was edited.

Expectations in the file are hand specified. Nothing in it is computed by the code under
test, so running it in either SDK is not circular.

Status: PROPOSED and OPT-IN. Not required by draft-pidlisnyi-aps-03, which states no
suspension rule, no restriction rule, no release rule and no lifecycle-standing rule.
Concept source: the aeoess/agent-authority-lifecycle concept document, invariant L8 and
invariant candidate CAND-05, both proposed.
