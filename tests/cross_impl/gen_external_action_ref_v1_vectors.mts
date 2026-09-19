// Generator for the section 4.2 external correlation form
// (action-ref-v1-jcs-sha256) cross-implementation vector file
// (tests/cross_impl/external-action-ref-v1-vectors.json).
//
// Every case, its expected result (accept/reject), its failure code, and its
// expected_provenance are fixed by a written vector specification. This
// script only fills in digests, and records what the TypeScript SDK actually
// does on every case, by calling the TS reference implementation directly;
// it does not decide any expected result itself. If the TS reference
// disagrees with a fixed expected result on an ACCEPT case, or if the two
// anchored no-normalization cases collide, the script exits nonzero and
// names the offending case instead of silently recording whatever TS
// produced. Reject cases carry no such requirement: the TypeScript SDK is
// known to diverge from the section 4.2 requirement text on several of them
// (see the module header of src/agent_passport/external_action_ref.py), and
// this script only records what TS actually does there ("ts_behaviour"), it
// never enforces the spec's answer against it.
//
// This file must never claim the TypeScript SDK is "verified": recording
// its behaviour is not a conformance claim, only a data point next to the
// spec's own answer.
//
// The TS repository is located purely through the APS_TS_REPO environment
// variable (a file:// URL is built from it) and the pinned commit purely
// through APS_TS_COMMIT. This file must never contain a local absolute path
// literal, because a pre-commit hook blocks commits containing local home
// paths.
//
// Usage:
//   APS_TS_REPO=/path/to/agent-passport-system \
//   APS_TS_COMMIT=<sha> \
//   npx tsx tests/cross_impl/gen_external_action_ref_v1_vectors.mts <output.json>

import { execFileSync } from 'node:child_process'
import { writeFileSync } from 'node:fs'

// -------------------------------------------------------------------------
// Environment / preflight
// -------------------------------------------------------------------------

const tsRepo = process.env.APS_TS_REPO
const tsCommit = process.env.APS_TS_COMMIT
const outPath = process.argv[2]

if (!tsRepo) fail('APS_TS_REPO is not set')
if (!tsCommit) fail('APS_TS_COMMIT is not set')
if (!outPath) fail('output path argument is required')

function fail(message: string): never {
  console.error(`STOP: ${message}`)
  process.exit(1)
}

// Re-verify the precondition already checked once: the TS
// reference must be sitting exactly on the pinned commit with a clean tree.
// This does not embed any path literal: both values are read from the
// environment at run time.
{
  const actualHead = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: tsRepo, encoding: 'utf8' }).trim()
  if (actualHead !== tsCommit) {
    fail(`TS repo HEAD is ${actualHead}, expected ${tsCommit}`)
  }
  const porcelain = execFileSync('git', ['status', '--porcelain'], { cwd: tsRepo, encoding: 'utf8' })
  if (porcelain.trim() !== '') {
    fail(`TS repo is not clean:\n${porcelain}`)
  }
}

const moduleUrl = new URL('src/core/external-action-ref.ts', `file://${tsRepo}/`).href
const { computeExternalActionRefV1 } = (await import(moduleUrl)) as {
  computeExternalActionRefV1: (input: unknown) => string
}

// -------------------------------------------------------------------------
// Fixed metadata (verbatim from the written specification, not derived, not invented)
// -------------------------------------------------------------------------

const FAILURE_CODES = [
  { code: 'not_string', meaning: 'a field is not a string (number, null, array, object)', draft_lines: '859-866' },
  {
    code: 'bad_timestamp',
    meaning:
      'timestamp not exactly YYYY-MM-DDTHH:MM:SS.sssZ, or not a valid RFC 3339 date and time (month 01-12, ' +
      'day existing in the month, hour 00-23, minute 00-59, second 00-60, 60 accepted lexically per RFC 3339)',
    draft_lines: '866-871',
  },
  {
    code: 'lone_surrogate',
    meaning: 'a string contains an unpaired UTF-16 surrogate (no UTF-8 encoding exists for the canonicalized JSON)',
    draft_lines: '855-857',
  },
] as const

const FAILURE_DRAFT_LINES: Record<string, string> = Object.fromEntries(
  FAILURE_CODES.map((row) => [row.code, row.draft_lines]),
)

const WITHHELD: { case: string; reason: string }[] = []

const EXPECTED_PROVENANCE_VALUES = {
  'draft-derived':
    'The expected value follows directly from the requirement text: the failure-code table for every reject ' +
    'case, and the section 4.2 construction formula (external_action_ref = lowercase-hex(SHA-256(canonicalize' +
    '(input_object)))), computed with strict RFC 8785 JCS and no domain-separation tag, for the digest on every ' +
    'accept case. It holds independent of whether the TypeScript reference implementation is marked conformant ' +
    'for this construction.',
  'ts-conformant-regression':
    'This label covers the digest construction on valid inputs only: for every accept case, the expected ' +
    'value is the digest produced by the TypeScript reference implementation (computeExternalActionRefV1) at ' +
    'the pinned commit. Three of these (EX-P01..EX-P03) are additionally pinned as byte matches against ' +
    'independent ecosystem implementations outside this project (see provenance_note on each); the rest are ' +
    'the TS reference\'s own output, recorded as a cross-implementation regression value and independently ' +
    'cross-checked against an rfc8785-based recomputation (see ' +
    'tests/cross_impl/crosscheck_external_action_ref_v1_vectors.py) rather than trusted outright. Reject ' +
    'cases are never labeled ts-conformant-regression; their ts_behaviour records show where the TypeScript ' +
    'SDK at the pinned commit departs from the section 4.2 text.',
}

const TS_BEHAVIOUR_NOTE =
  'ts_behaviour on a reject case records what the TypeScript reference implementation actually does on that ' +
  'input, observed by calling it directly at the pinned commit. It is not a conformance claim: this file does ' +
  'not assert the TypeScript SDK is verified against section 4.2, only reports its behaviour next to the ' +
  'spec\'s own answer. "accepts" means TS returned a digest where the spec requires a rejection; "rejects" ' +
  'means TS threw, and the accompanying message is the TypeScript SDK\'s own error text (SDK vocabulary, not ' +
  'protocol vocabulary).'

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

type Provenance = 'draft-derived' | 'ts-conformant-regression'

function draftLinesForFailure(code: string): string {
  const lines = FAILURE_DRAFT_LINES[code]
  if (!lines) fail(`unknown failure code ${code} referenced by a case`)
  return lines
}

function tsInputOf(input: Record<string, unknown>): unknown {
  return {
    actionType: input.action_type,
    agentId: input.agent_id,
    scope: input.scope,
    timestamp: input.timestamp,
  }
}

const cases: Record<string, unknown>[] = []
const counts = {
  total: 0,
  accept: 0,
  reject: 0,
  by_expected_provenance: { 'draft-derived': 0, 'ts-conformant-regression': 0 } as Record<string, number>,
}

// -------------------------------------------------------------------------
// BASE input (EX-P04)
// -------------------------------------------------------------------------

const BASE = {
  action_type: 'commerce_preflight',
  agent_id: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
  scope: 'commerce:write',
  timestamp: '2026-04-08T12:00:00.000Z',
}

function base(overrides: Record<string, unknown>): Record<string, unknown> {
  return { ...BASE, ...overrides }
}

// -------------------------------------------------------------------------
// Accept cases (EX-P01..EX-P09)
// -------------------------------------------------------------------------

interface AcceptCase {
  id: string
  input: Record<string, unknown>
  anchor?: string
  provenance?: Provenance
  provenance_note?: string
}

const ANCHOR_NOTE_P01 =
  'The TS test suite pins 584bc79bb11ce3af5058b3da84d03f85e4aa464a175bd4f913aeb82a22cef60f as a byte match ' +
  'against an independent ecosystem implementation (argentum-core).'
const ANCHOR_NOTE_P02 = 'Anchor fdd7f810499f06be24355ca8e2bfb8c4b965cc80c838f41fa074683443d89f5a (action-ref-verify vector 0001).'
const ANCHOR_NOTE_P03 = 'Anchor d7a591f6afb04565baca3ef862324b692bfb7be731aa53d98f3814bb3cb6bdb0 (action-ref-verify vector 0006).'
const NO_NORMALIZATION_NOTE =
  'EX-P05 uses scope "café:read" with the é decomposed (e + combining acute accent, U+0301); EX-P06 ' +
  'uses the same scope with the é precomposed (U+00E9). Their digests must differ from each other, because ' +
  'the external form applies no Unicode normalization (draft lines 873-876).'
const LEAP_SECOND_NOTE =
  'RFC 3339 admits second 60 and section 4.2 names RFC 3339; accepted lexically. The TypeScript SDK at ' +
  'the pinned commit gives this digest.'

const acceptCases: AcceptCase[] = [
  {
    id: 'EX-P01',
    input: { action_type: 'payment.send', agent_id: 'pioneer-agent-001', scope: 'mycelium:payment', timestamp: '2026-05-24T10:30:00.000Z' },
    anchor: '584bc79bb11ce3af5058b3da84d03f85e4aa464a175bd4f913aeb82a22cef60f',
    provenance_note: ANCHOR_NOTE_P01,
  },
  {
    id: 'EX-P02',
    input: { action_type: 'oracle.signal', agent_id: 'nexus-agent-xa12.onrender.com', scope: 'BTC', timestamp: '2025-05-18T11:40:31.000Z' },
    anchor: 'fdd7f810499f06be24355ca8e2bfb8c4b965cc80c838f41fa074683443d89f5a',
    provenance_note: ANCHOR_NOTE_P02,
  },
  {
    id: 'EX-P03',
    input: { action_type: 'oracle.signal', agent_id: 'test-negative-zero.example.com', scope: 'BTC', timestamp: '2025-01-01T00:00:00.000Z' },
    anchor: 'd7a591f6afb04565baca3ef862324b692bfb7be731aa53d98f3814bb3cb6bdb0',
    provenance_note: ANCHOR_NOTE_P03,
  },
  { id: 'EX-P04', input: base({}) },
  { id: 'EX-P05', input: base({ scope: 'café:read' }), provenance_note: NO_NORMALIZATION_NOTE },
  { id: 'EX-P06', input: base({ scope: 'café:read' }), provenance_note: NO_NORMALIZATION_NOTE },
  { id: 'EX-P07', input: base({ agent_id: 'did:example:\u{1F600}', action_type: 'quote" backslash\\ ctrl\u0007' }) },
  { id: 'EX-P08', input: base({ timestamp: '2028-02-29T23:59:59.999Z' }) },
  { id: 'EX-P09', input: base({ timestamp: '0000-01-01T00:00:00.000Z' }) },
  { id: 'EX-P10', input: base({ timestamp: '2016-12-31T23:59:60.000Z' }), provenance: 'draft-derived', provenance_note: LEAP_SECOND_NOTE },
  { id: 'EX-P11', input: base({ timestamp: '2026-04-08T12:00:60.000Z' }), provenance: 'draft-derived', provenance_note: LEAP_SECOND_NOTE },
]

const digestById = new Map<string, string>()

for (const c of acceptCases) {
  let digest: string
  try {
    digest = computeExternalActionRefV1(tsInputOf(c.input))
  } catch (e) {
    fail(`${c.id}: TS rejected an input the spec expects to accept: ${(e as Error).message}`)
  }
  if (c.anchor && digest !== c.anchor) {
    fail(`${c.id}: TS digest ${digest} does not match the pinned anchor ${c.anchor}`)
  }
  digestById.set(c.id, digest)
  const provenance: Provenance = c.provenance ?? 'ts-conformant-regression'
  counts.total++
  counts.accept++
  counts.by_expected_provenance[provenance]++
  cases.push({
    id: c.id,
    input: c.input,
    expected: { result: 'accept', external_action_ref: digest },
    expected_provenance: provenance,
    draft_lines: '852-857',
    ...(c.provenance_note ? { provenance_note: c.provenance_note } : {}),
  })
}

const digestP05 = digestById.get('EX-P05')
const digestP06 = digestById.get('EX-P06')
if (!digestP05 || !digestP06) fail('EX-P05/EX-P06 digest unavailable for the no-normalization check')
if (digestP05 === digestP06) {
  fail('EX-P05 and EX-P06 produced the same digest; the external form must not normalize scope')
}

// -------------------------------------------------------------------------
// Reject cases (EX-N01..EX-N12)
// -------------------------------------------------------------------------

interface RejectCase {
  id: string
  input: Record<string, unknown>
  failure: string
  draft_lines?: string
}

const rejectCases: RejectCase[] = [
  { id: 'EX-N01', input: base({ timestamp: '2025-05-18T11:40:31Z' }), failure: 'bad_timestamp' },
  { id: 'EX-N02', input: base({ timestamp: '2025-05-18T11:40:31.000000Z' }), failure: 'bad_timestamp' },
  { id: 'EX-N03', input: base({ timestamp: '2025-05-18T11:40:31.000+00:00' }), failure: 'bad_timestamp' },
  { id: 'EX-N04', input: base({ timestamp: '2025-05-18t11:40:31.000z' }), failure: 'bad_timestamp' },
  { id: 'EX-N05', input: base({ timestamp: '2026-13-01T00:00:00.000Z' }), failure: 'bad_timestamp' },
  { id: 'EX-N06', input: base({ timestamp: '2026-02-30T00:00:00.000Z' }), failure: 'bad_timestamp' },
  { id: 'EX-N07', input: base({ timestamp: '2026-04-08T24:00:00.000Z' }), failure: 'bad_timestamp' },
  { id: 'EX-N08', input: base({ timestamp: '2026-04-08T12:60:00.000Z' }), failure: 'bad_timestamp' },
  { id: 'EX-N09', input: base({ scope: ['commerce:write'] }), failure: 'not_string' },
  { id: 'EX-N10', input: base({ agent_id: 123 }), failure: 'not_string' },
  { id: 'EX-N11', input: base({ timestamp: 1747568431000 }), failure: 'not_string' },
  { id: 'EX-N12', input: base({ scope: '\uD800' }), failure: 'lone_surrogate' },
  {
    id: 'EX-N13',
    input: base({ timestamp: ['2026-04-08T12:00:00.000Z'] }),
    failure: 'not_string',
    draft_lines: '866-871',
  },
]

for (const c of rejectCases) {
  let tsBehaviour: Record<string, unknown>
  try {
    const digest = computeExternalActionRefV1(tsInputOf(c.input))
    tsBehaviour = {
      behaviour: 'accepts',
      external_action_ref: digest,
      note: 'TypeScript SDK behaviour at the pinned commit differs from the draft text',
    }
  } catch (e) {
    tsBehaviour = { behaviour: 'rejects', message: (e as Error).message }
  }
  const provenance: Provenance = 'draft-derived'
  counts.total++
  counts.reject++
  counts.by_expected_provenance[provenance]++
  cases.push({
    id: c.id,
    input: c.input,
    expected: { result: 'reject', failure: c.failure },
    expected_provenance: provenance,
    draft_lines: c.draft_lines ?? draftLinesForFailure(c.failure),
    ts_behaviour: tsBehaviour,
  })
}

// -------------------------------------------------------------------------
// Assemble and write
// -------------------------------------------------------------------------

const document = {
  name: 'action-ref-v1-jcs-sha256 (section 4.2 external correlation form) vectors',
  draft: 'draft-pidlisnyi-aps-03 section 4.2 (published text lines 845-892)',
  generated_from: {
    repository: 'aeoess/agent-passport-system',
    commit: tsCommit,
    module: 'src/core/external-action-ref.ts',
    generator: 'tests/cross_impl/gen_external_action_ref_v1_vectors.mts',
  },
  expected_provenance_values: EXPECTED_PROVENANCE_VALUES,
  failure_codes: FAILURE_CODES,
  withheld: WITHHELD,
  ts_behaviour_note: TS_BEHAVIOUR_NOTE,
  counts,
  cases,
}

writeFileSync(outPath, JSON.stringify(document, null, 2) + '\n', 'utf8')
console.log(`wrote ${cases.length} cases to ${outPath}`)
console.log(JSON.stringify(counts, null, 2))
