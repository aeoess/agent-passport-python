// Generator for the composite receipt-and-decision cross-implementation vector file
// (tests/cross_impl/receipt-decision-composite-vectors.json).
//
// Unlike gen_receipt_v1_stage_vectors.mts, this generator fixes NO expectation of its own.
// The Python module under test, src/agent_passport/receipt_core/composite.py, is a parity
// port of the TypeScript reference src/v2/receipt-core/composite.ts, so what the vector file
// records is the reference's own result object for each case, verbatim, and the Python test
// asserts equality with it field for field. The claim the file supports is exactly "the two
// implementations return the same object for these inputs" and nothing more. It is not a
// draft-conformance statement, and no case in it should be described that way.
//
// The records come from the action-result-binding conformance fixture rather than being
// minted here: they are a pinned three-stage chain plus six action-result records that each
// differ from the accepted one by exactly one named defect, so the inputs are bytes neither
// SDK produced for this test.
//
// The predecessor axis is exercised through all of its states. The TypeScript reference opts
// in on OWN-PROPERTY PRESENCE, so `absent` below passes no property at all and every other
// variant passes one, undefined and null included. The Python port maps that to a
// module-private sentinel default, and the two absent JavaScript values to None. That
// mapping is the single most important thing this file pins.
//
// The TS repository is located purely through the APS_TS_REPO environment variable, the
// pinned commit purely through APS_TS_COMMIT, and the conformance fixture purely through
// APS_CHAIN_FIXTURE. This file must never contain a local absolute path literal: a
// pre-commit hook blocks commits containing local home paths.
//
// Usage:
//   APS_TS_REPO=/path/to/agent-passport-system-worktree \
//   APS_TS_COMMIT=<sha> \
//   APS_CHAIN_FIXTURE=/path/to/aps-conformance-suite/fixtures/action-result-binding/chain.json \
//   node --experimental-strip-types tests/cross_impl/gen_receipt_decision_composite_vectors.mts <output.json>
//
// (or `npx tsx` in place of node, from a checkout that has tsx installed.)

import { execFileSync } from 'node:child_process'
import { readFileSync, writeFileSync } from 'node:fs'

const tsRepo = process.env.APS_TS_REPO
const tsCommit = process.env.APS_TS_COMMIT
const chainFixture = process.env.APS_CHAIN_FIXTURE
const outPath = process.argv[2]

function fail(message: string): never {
  console.error(`STOP: ${message}`)
  process.exit(1)
}

if (!tsRepo) fail('APS_TS_REPO is not set')
if (!tsCommit) fail('APS_TS_COMMIT is not set')
if (!chainFixture) fail('APS_CHAIN_FIXTURE is not set')
if (!outPath) fail('output path argument is required')

{
  const head = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: tsRepo, encoding: 'utf8' }).trim()
  if (!head.startsWith(tsCommit) && !tsCommit.startsWith(head)) {
    fail(`TS repo HEAD is ${head}, expected ${tsCommit}`)
  }
  const porcelain = execFileSync('git', ['status', '--porcelain'], { cwd: tsRepo, encoding: 'utf8' })
  if (porcelain.trim() !== '') fail(`TS repo is not clean:\n${porcelain}`)
}

const src = (file: string): string => new URL(`file://${tsRepo}/src/${file}`).href
const { verifyReceiptWithDecisionV1 } = await import(src('v2/receipt-core/composite.js'))

type Json = null | boolean | number | string | Json[] | { [key: string]: Json }

const chain = JSON.parse(readFileSync(chainFixture, 'utf8')) as {
  cases: Record<string, Json>
  receipts: Record<string, Json>
  decision_evidence: Record<string, Json>
  identities: Record<string, string>
  verification_keys: Record<string, string>
}

// The fixture publishes the verification key per key_id. A key_id it does not carry resolves
// to nothing, which is the resolver outcome the reference reads as an unestablished signer
// authority rather than a bad signature. No case here reaches that state.
const resolveKey = (_signer: string, keyId: string): string | undefined => chain.verification_keys[keyId]

const BOUNDARY = chain.identities.enforcement_boundary

// Every record the composite is run over. The six cases are the fixture's own, each carrying
// exactly one named defect; the two chain records are the intent and the consumed permit
// decision, which exercise the stages where the predecessor axis does not apply at all.
const RECORDS: { id: string; record: Json }[] = [
  ...Object.keys(chain.cases).sort().map(id => ({ id: `case:${id}`, record: chain.cases[id] })),
  { id: 'chain:intent', record: chain.receipts.intent },
  { id: 'chain:decision_permit', record: chain.receipts.decision_permit },
  { id: 'chain:decision_deny', record: chain.receipts.decision_deny },
]

// The predecessor variants, in the vocabulary the vector file uses. `absent` is the only one
// that passes no property; every other entry passes one, which is the opt-in.
const PREDECESSORS: { id: string; present: boolean; value?: Json }[] = [
  { id: 'absent', present: false },
  { id: 'undefined', present: true, value: undefined as unknown as Json },
  { id: 'null', present: true, value: null },
  { id: 'false', present: true, value: false },
  { id: 'empty_object', present: true, value: {} },
  { id: 'intent', present: true, value: chain.receipts.intent },
  { id: 'decision_permit', present: true, value: chain.receipts.decision_permit },
]

const cases: Json[] = []
for (const { id: recordId, record } of RECORDS) {
  for (const evidenceId of Object.keys(chain.decision_evidence).sort()) {
    const evidence = chain.decision_evidence[evidenceId]
    for (const predecessor of PREDECESSORS) {
      const options: Record<string, unknown> = { boundaryIdentity: BOUNDARY }
      // Written this way on purpose: assigning the property is what the opt-in reads, and
      // assigning it undefined is a DIFFERENT state from never assigning it.
      if (predecessor.present) options.predecessor = predecessor.value
      const result = verifyReceiptWithDecisionV1(record, evidence, resolveKey, options)
      cases.push({
        id: `${recordId}|evidence:${evidenceId}|predecessor:${predecessor.id}`,
        record_id: recordId,
        evidence_id: evidenceId,
        predecessor_id: predecessor.id,
        // `predecessor_supplied` is the opt-in itself: false means the argument is not passed
        // at all on either side, true means it is passed carrying `predecessor_value`.
        predecessor_supplied: predecessor.present,
        predecessor_value: predecessor.present ? (predecessor.value ?? null) : null,
        boundary_identity: BOUNDARY,
        record,
        evidence,
        // The reference's result object verbatim. JSON.stringify drops nothing here: every
        // member of ReceiptWithDecisionVerificationV1 is defined on every path.
        expected: result,
      }) as unknown as Json
    }
  }
}

const document = {
  description:
    'Cross-implementation vectors for the section 5.6 composite receipt-and-decision verifier and its opt-in section 5.3.3 predecessor axis. Each case records the TypeScript reference result object verbatim for the inputs it carries, and the Python test asserts its own result equals that object field for field. This file states that the two implementations agree on these inputs. It states nothing about draft conformance, and no expectation in it was derived from the draft text: for that surface see receipt-v1-stage-vectors.json, whose generator fixes every expectation from the draft independently and refuses to write when TypeScript disagrees. The predecessor axis is OPT-IN HARDENING rather than a required verifier check: draft-pidlisnyi-aps-03 section 5.3.3 lines 1104-1105 states the prev relation and section 5.6 line 1219 lists prev validation, neither with a BCP 14 keyword. predecessor_supplied false is the argument not passed, which both implementations report as not_checked; predecessor_id undefined and null are two distinct JavaScript values that both map to Python None and both report not_established. The error and failure code strings are this SDK pair own vocabulary, which the draft does not name.',
  draft: 'draft-pidlisnyi-aps-03 sections 5.3.3, 5.4 and 5.6',
  generated_from: { repository: 'agent-passport-system', commit: tsCommit },
  records_from: {
    suite: 'aps-conformance-suite',
    family: 'fixtures/action-result-binding/chain.json',
    note: 'A pinned three-stage chain plus six action-result records that each differ from the accepted one by exactly one named defect. The records are inputs to this file and were minted by neither SDK for this test.',
  },
  // The fixture's published verification keys, copied so the replaying implementation builds
  // the same resolver from the vector file alone and never reaches for the suite on disk.
  resolver_keys: chain.verification_keys,
  conventions: {
    call: 'run the composite verifier over record with evidence, a resolver that returns resolver_keys[key_id] and nothing for an unknown key_id, and the fixture enforcement boundary as the boundary identity.',
    predecessor:
      'when predecessor_supplied is false, pass no predecessor at all: no own property in TypeScript, the argument omitted in Python. When it is true, pass predecessor_value, with the TypeScript-only distinction that predecessor_id "undefined" passes undefined where "null" passes null; Python passes None for both, and both implementations report not_established either way.',
    comparison: 'compare the full result object with expected, field for field, key order ignored.',
  },
  withheld: [
    'The predecessor record\'s own signatures. The primitive does not verify them on either side, and a valid predecessor axis here says the two records are linked by digest and agree on decision_ref, nothing more.',
    'Resolver outcomes other than a resolved key. Those are exercised by receipt-v1-stage-vectors.json, whose cases name the resolver kind per case.',
    'The single-use and freshness obligations of draft lines 1093-1099, which are enforcement-boundary state rather than properties of these artifacts.',
  ],
  counts: {
    total: cases.length,
    records: RECORDS.length,
    evidences: Object.keys(chain.decision_evidence).length,
    predecessor_variants: PREDECESSORS.length,
  },
  cases,
}

writeFileSync(outPath, `${JSON.stringify(document, null, 2)}\n`)
console.log(`wrote ${cases.length} cases to ${outPath}`)
