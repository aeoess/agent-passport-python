# activation v0 vectors: provenance

`vectors.json` in this directory is a byte-for-byte copy of
`conformance/activation/v0/vectors.json` in the TypeScript SDK
(`aeoess/agent-passport-system`), which is where it is authored and where its generator,
`conformance/activation/v0/generate.mts`, lives.

    SHA-256  9340152cc3ddd4c0ac02d07b8cb8ccb85f7174ab72e4ffab6ad279d6027ee48e

Both repositories pin that digest inside their own parity test
(`tests/v2/activation.test.ts` and `tests/test_activation.py`), so the two copies can be
shown identical without either repository importing the other, and a one-sided edit fails
the test on the side that was edited.

Expectations in the file are hand specified as literals in the generator. Nothing in it is
computed by `verify_activation`, `validate_activation_condition` or `compose_activation`, so
running it in either SDK is not circular.

Signing keys are deterministic, derived from the seed labels the file itself prints under
`seed_labels`:

    private key = SHA-256("aps-conformance:activation-v0:" + label)

so a regeneration reproduces the artifact and no secret material is introduced.

Status: PROPOSED and OPT-IN. Not required by draft-pidlisnyi-aps-03, which states no
activation-condition rule, no attestor role and no attestation-acceptance rule. Concept
source: the aeoess/agent-authority-lifecycle concept document, invariant candidates CAND-04,
CAND-13 (activation half) and BROAD-L7, all proposed.
