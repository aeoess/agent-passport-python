# lifecycle-state v0 vectors: provenance

`vectors.json` in this directory is a byte-for-byte copy of
`conformance/lifecycle-state/v0/vectors.json` in the TypeScript SDK
(`aeoess/agent-passport-system`), which is where it is authored.

    SHA-256  32bc491378494e0336a9a1b3b56eae897c8a0f13591d136cec08831cf5b7ab91

Both repositories pin that digest inside their own parity test
(`tests/v2/lifecycle-state.test.ts` and `tests/test_lifecycle_state.py`), so the two
copies can be shown identical without either repository importing the other, and a
one-sided edit fails the test on the side that was edited.

Expectations in the file are hand specified. Nothing in it is computed by the code under
test, so running it in either SDK is not circular.

Status: PROPOSED and OPT-IN. Not required by draft-pidlisnyi-aps-03. Concept source: the
aeoess/agent-authority-lifecycle concept document.
