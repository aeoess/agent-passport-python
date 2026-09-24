# authority-state v0 vectors: provenance

`vectors.json` in this directory is a byte-for-byte copy of
`conformance/authority-state/v0/vectors.json` in the TypeScript SDK
(`aeoess/agent-passport-system`), which is where it is authored.

    SHA-256  4c2292d56f4e26fee62e7d70518d1d4a2fc5d7b2762ebfe4d3e8bc804cd15f45

Both repositories pin that digest inside their own parity test
(`tests/v2/authority-state.test.ts` and `tests/test_authority_state.py`), so the two
copies can be shown identical without either repository importing the other, and a
one-sided edit fails the test on the side that was edited.

Expectations in the file are hand specified. Nothing in it is computed by the code under
test, so running it in either SDK is not circular.

The file covers every part of the surface that needs no signature: the marker constructor,
the monotonicity comparison, resolver routing, the fencing gate, withdrawal evaluation and
the corrected view. The limb where a retained revocation record verifies against a
delegation and produces a `revoked` answer needs real Ed25519 records, so each SDK covers
it in its own test against records that SDK mints.

Status: PROPOSED and OPT-IN. Not required by draft-pidlisnyi-aps-03, which has no
occurrence of `epoch`, `fencing` or `snapshot` and defines no record for withdrawing a
revocation. Concept source: the aeoess/agent-authority-lifecycle concept document (the
`Authority epoch` concept, invariants L3, L7 and L11, the `Authority rollback` open
question) and its invariant candidates CAND-08 and CAND-02.
