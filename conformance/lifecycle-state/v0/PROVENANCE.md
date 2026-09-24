# lifecycle-state v0 vectors: provenance

`vectors.json` in this directory is a byte-for-byte copy of
`conformance/lifecycle-state/v0/vectors.json` in the TypeScript SDK
(`aeoess/agent-passport-system`), which is where it is authored.

    SHA-256  e2efab4001ee7593cdd38a3f6bfb9d35e9946e865f93ae62c71c8587d1cccf6f

Both repositories pin that digest inside their own parity test
(`tests/v2/lifecycle-state.test.ts` and `tests/test_lifecycle_state.py`), so the two
copies can be shown identical without either repository importing the other, and a
one-sided edit fails the test on the side that was edited.

Expectations in the file are hand specified. Nothing in it is computed by the code under
test, so running it in either SDK is not circular.

Status: PROPOSED and OPT-IN. Not required by draft-pidlisnyi-aps-03. Concept source: the
aeoess/agent-authority-lifecycle concept document.
