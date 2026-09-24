# status-coverage v0 vectors: provenance

`vectors.json` in this directory is a byte-for-byte copy of
`conformance/status-coverage/v0/vectors.json` in the TypeScript SDK
(`aeoess/agent-passport-system`), which is where it is authored.

    SHA-256  dc3c0165d9e90488a772c14ffe2ba64fefe90c504b7d48d8aa3cd916bd6649e5

Both repositories pin that digest inside their own parity test
(`tests/v2/status-coverage.test.ts` and `tests/test_status_coverage.py`), so the two
copies can be shown identical without either repository importing the other, and a
one-sided edit fails the test on the side that was edited.

Expectations in the file are hand specified. Nothing in it is computed by the code under
test, so running it in either SDK is not circular.

Status: PROPOSED, EXPERIMENTAL and OPT-IN. Not required by draft-pidlisnyi-aps-03, whose
section 3.3 rules one revocation result per chain member and says nothing about two
sources answering about the same member, a per-source freshness bound, coverage over a
declared source set, or an offline admission on a snapshot. Concept source: the
aeoess/agent-authority-lifecycle concept document, invariant L7 and invariant candidate
BROAD-L7.

The coverage block in these vectors reports whether a DECLARED required-source set was
covered. It is not a completeness claim, and invariant L12 stays exactly as open as it
was.
