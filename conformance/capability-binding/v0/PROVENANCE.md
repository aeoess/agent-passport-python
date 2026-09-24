# capability-binding v0 vectors: provenance

`vectors.json` in this directory is a byte-for-byte copy of
`conformance/capability-binding/v0/vectors.json` in the TypeScript SDK
(`aeoess/agent-passport-system`), which is where it is authored.

    SHA-256  d25efe67c9b065caa72045613430bb238b52aaafe8c0c0aa354bb31696cf3829

Both repositories pin that digest inside their own parity test
(`tests/v2/capability-binding.test.ts` and `tests/test_capability_binding.py`), so the two
copies can be shown identical without either repository importing the other, and a
one-sided edit fails the test on the side that was edited.

Expectations in the file are hand specified. Nothing in it is computed by the code under
test, so running it in either SDK is not circular.

The identifier-continuity records are stored UNSIGNED. Each runner signs them with the
private key of the custodian named in `sign_as`, using its own `sign` over its own
`identifier_record_signed_bytes`, then evaluates. No signature is stored in the file, so a
canonical-byte divergence between the two SDKs shows up as a failed signature check rather
than as two runners agreeing on a blob neither of them produced.

Status: PROPOSED and OPT-IN. Not required by draft-pidlisnyi-aps-03, which defines no pin
syntax and states no rule pinning a tool to an implementation digest or a schema. Concept
source: the aeoess/agent-authority-lifecycle concept document, invariant candidate CAND-07
as rewritten.
