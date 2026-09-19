// Generator for the aps-action-ref-v2 / payload_ref cross-implementation
// vector file (tests/cross_impl/action-ref-v2-vectors.json).
//
// Every case, its expected result (accept/reject), its failure code, and its
// expected_provenance are FIXED by a written vector specification (job 2,
// batch 1 , not shipped in this repo, kept by the orchestrator). This script
// only fills in digests and the TypeScript SDK's own error messages by
// calling the TS reference implementation directly; it does not decide any
// expected result itself. If the TS reference disagrees with a fixed
// expected result, the script exits nonzero and names the offending case
// instead of silently recording whatever TS produced.
//
// The TS repository is located purely through the APS_TS_REPO environment
// variable (a file:// URL is built from it) and the pinned commit purely
// through APS_TS_COMMIT , this file must never contain a local absolute
// path literal, because a pre-commit hook blocks commits containing local
// home paths.
//
// Usage:
//   APS_TS_REPO=/path/to/agent-passport-system \
//   APS_TS_COMMIT=<sha> \
//   npx tsx tests/cross_impl/gen_action_ref_v2_vectors.mts <output.json>

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

// Re-verify the precondition the orchestrator already checked once: the TS
// reference must be sitting exactly on the pinned commit with a clean tree.
// This does not embed any path literal , both values are read from the
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

const moduleUrl = new URL('src/v2/action-reference/v2.ts', `file://${tsRepo}/`).href
const {
  computeActionRefV2,
  computeActionRefV2FromJson,
  computePayloadRefV1,
  createActionReferenceInputV2,
} = await import(moduleUrl) as {
  computeActionRefV2: (input: unknown) => string
  computeActionRefV2FromJson: (raw: string) => string
  computePayloadRefV1: (payload: unknown) => string
  createActionReferenceInputV2: (input: {
    agent_id: string
    action_type: string
    target: string
    payload_ref: string
    scope_required: readonly string[]
    issued_at: string
    nonce: string
  }) => unknown
}

// -------------------------------------------------------------------------
// Fixed metadata (verbatim from the written specification, not derived, not invented)
// -------------------------------------------------------------------------

const FAILURE_CODES = [
  { code: 'not_object', meaning: 'input is not a JSON object', draft_lines: '757' },
  { code: 'missing_member', meaning: 'a required member is absent', draft_lines: '757-768' },
  { code: 'unknown_member', meaning: 'a member outside the eight', draft_lines: '813-814' },
  { code: 'duplicate_member', meaning: 'a member name occurs twice in the serialized document, compared after escape decoding', draft_lines: '814-817' },
  { code: 'wrong_profile', meaning: 'profile is not "aps-action-ref-v2"', draft_lines: '789' },
  { code: 'not_string', meaning: 'a string field holds a non-string (number, null, array, object)', draft_lines: '789-799' },
  { code: 'empty_string', meaning: 'a string field or a scope element is ""', draft_lines: '798-799' },
  { code: 'bad_hex', meaning: 'payload_ref not 64 lowercase hex, or nonce not 32 lowercase hex', draft_lines: '793-794, 797-798, 815' },
  { code: 'bad_timestamp', meaning: 'issued_at not exactly YYYY-MM-DDTHH:MM:SS.sssZ, or not a valid calendar instant', draft_lines: '796-797, 815' },
  { code: 'scope_not_array', meaning: 'scope_required is not an array', draft_lines: '794' },
  { code: 'scope_not_canonical', meaning: 'scope array not NFC, not sorted by UTF-8 bytes, or not duplicate-free', draft_lines: '794-796, 814, 822-824' },
  { code: 'lone_surrogate', meaning: 'a string contains an unpaired UTF-16 surrogate', draft_lines: '819-821' },
  { code: 'non_i_json', meaning: 'a value that is not I-JSON (unsafe integer, non-finite number, invalid JSON text)', draft_lines: '814, 804-805' },
] as const

const FAILURE_DRAFT_LINES: Record<string, string> = Object.fromEntries(
  FAILURE_CODES.map((row) => [row.code, row.draft_lines]),
)

const WITHHELD = [
  {
    case: 'scope_required = []',
    reason:
      'draft lines 798-800 let a profile permit an empty scope_required array, but the input object names ' +
      'no profile, so the default is not determined by the text.',
  },
  {
    case: 'issued_at with second 60 (leap second, for example "2016-12-31T23:59:60.000Z")',
    reason:
      'RFC 3339 permits a leap second, APS says "UTC timestamp with exactly three fractional digits", and ' +
      'the text does not say whether leap seconds are admissible.',
  },
]

const EXPECTED_PROVENANCE_VALUES = {
  'draft-derived':
    'The expected value follows directly from the requirement text: the failure-code table for every reject ' +
    'case that carries no provenance_note, ' +
    'case, the payload_ref formula (draft lines 804-805) computed independently with the rfc8785 Python ' +
    'package for every payload_ref digest (the job 1 conformance matrix does not mark payload_ref conformant ' +
    'for TS, because the aps-mcp-1 profile uses a different domain tag), and the NFC-normalize/sort/dedupe ' +
    'rule (draft lines 794-796, 819-824) for the canonical scope_required form recorded on every create-entry ' +
    'case. It holds independent of whether the TS reference implementation is marked conformant.',
  'ts-conformant-regression':
    'The expected value is the result produced by the corrected TS reference implementation (a digest, or for ' +
    'the two payload cases that carry a provenance_note a rejection under the SDK I-JSON integer boundary) ' +
    '(computeActionRefV2 / computeActionRefV2FromJson / createActionReferenceInputV2). The job 1 conformance ' +
    'matrix marks the section 4.1 action_ref construction conformant for TS, so this file pins that ' +
    'implementation\'s own output as a cross-implementation regression value, independently cross-checked ' +
    'against an rfc8785-based recomputation (see cross_checks) rather than trusted outright.',
}

const CROSS_CHECKS = {
  description:
    'Every payload_ref value and every accepted action_ref value in this file is independently recomputed in ' +
    'Python by tests/cross_impl/crosscheck_action_ref_v2_vectors.py, using the rfc8785 package (an RFC 8785 ' +
    'JSON Canonicalization Scheme implementation outside this project, not this project\'s own canonicalizer): ' +
    'payload_ref as sha256(b"APS-ACTION-PAYLOAD-V1\\x00" + rfc8785.dumps(payload)) and an accepted action_ref ' +
    'as sha256(b"APS-ACTION-REF-V2\\x00" + rfc8785.dumps(canonical_input)), both lowercase hex, compared byte ' +
    'for byte against the value recorded in this file. The script does not import agent_passport and does not ' +
    'depend on the TS SDK, so a mismatch means the value recorded in this file is wrong, not that the TS SDK ' +
    'is non-conformant.',
  command: 'python tests/cross_impl/crosscheck_action_ref_v2_vectors.py',
}

const TS_ERROR_MESSAGES_NOTE =
  "ts_error_message values are the TypeScript SDK's own messages, recorded for reference. They are SDK " +
  'vocabulary, not protocol vocabulary; the normative failure is the failure code.'

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

type Provenance = 'draft-derived' | 'ts-conformant-regression'

interface CaseResult {
  id: string
  entry: 'payload' | 'object' | 'json' | 'create'
  [key: string]: unknown
}

const cases: CaseResult[] = []
const counts = {
  total: 0,
  by_entry: { payload: 0, object: 0, json: 0, create: 0 } as Record<string, number>,
  by_expected_provenance: { 'draft-derived': 0, 'ts-conformant-regression': 0 } as Record<string, number>,
}

function record(entry: CaseResult['entry'], provenance: Provenance): void {
  counts.total++
  counts.by_entry[entry]++
  counts.by_expected_provenance[provenance]++
}

function draftLinesForFailure(code: string): string {
  const lines = FAILURE_DRAFT_LINES[code]
  if (!lines) fail(`unknown failure code ${code} referenced by a case`)
  return lines
}

// -------------------------------------------------------------------------
// payload_ref cases
// -------------------------------------------------------------------------

interface PayloadCase {
  id: string
  payload: unknown
  expected: { result: 'accept' } | { result: 'reject'; failure: string }
  provenance?: Provenance
  provenance_note?: string
}

const INTEGER_BOUNDARY_NOTE =
  'Rejection rests on the I-JSON integer boundary both SDKs apply (an integer-valued number above 2**53-1 in magnitude is ' +
  'not accepted). RFC 7493 section 2.2 states that boundary as interoperability advice, so the expected result is the ' +
  'SDK policy for a row the job 1 matrix marks conformant, not a value the draft text fixes on its own.'

const payloadCases: PayloadCase[] = [
  { id: 'PR-P01', payload: { amount: '5000', currency: 'USD', merchant: 'example' }, expected: { result: 'accept' } },
  { id: 'PR-P02', payload: {}, expected: { result: 'accept' } },
  { id: 'PR-P03', payload: [], expected: { result: 'accept' } },
  { id: 'PR-P04', payload: { cart: ['sku-1'] }, expected: { result: 'accept' } },
  { id: 'PR-P05', payload: { a: 1, b: 1.5, c: -0, d: 1.2345e-20, e: 1e-7, f: 0.1, g: -1.25e-10 }, expected: { result: 'accept' } },
  {
    id: 'PR-P06',
    payload: { '\u20ac': 1, '\r': 2, '\ufb33': 3, '1': 4, '\u{1F600}': 5, '\u0080': 6, '\u00f6': 7 },
    expected: { result: 'accept' },
  },
  {
    id: 'PR-P07',
    payload: { n: null, t: true, f: false, s: 'quote" backslash\\ tab\t newline\n bell\u0007', arr: [1, [2, [3]], { z: 0, a: 0 }] },
    expected: { result: 'accept' },
  },
  { id: 'PR-P08', payload: { u: '\u2028\u2029 \u{1F600} caf\u00e9' }, expected: { result: 'accept' } },
  { id: 'PR-P09', payload: { max: 9007199254740991, min: -9007199254740991 }, expected: { result: 'accept' } },
  { id: 'PR-N01', payload: { big: 9007199254740992 }, expected: { result: 'reject', failure: 'non_i_json' }, provenance: 'ts-conformant-regression', provenance_note: INTEGER_BOUNDARY_NOTE },
  { id: 'PR-N03', payload: { big: 1e21 }, expected: { result: 'reject', failure: 'non_i_json' }, provenance: 'ts-conformant-regression', provenance_note: INTEGER_BOUNDARY_NOTE },
  { id: 'PR-N02', payload: { s: '\uD800' }, expected: { result: 'reject', failure: 'lone_surrogate' } },
]

const payloadRefById = new Map<string, string>()

for (const c of payloadCases) {
  const provenance: Provenance = c.provenance ?? 'draft-derived'
  const draft_lines = c.expected.result === 'accept' ? '804-805' : draftLinesForFailure(c.expected.failure)
  let expectedOut: Record<string, unknown>
  try {
    const ref = computePayloadRefV1(c.payload)
    if (c.expected.result !== 'accept') {
      fail(`${c.id}: TS accepted a payload expected to reject (${c.expected.failure})`)
    }
    payloadRefById.set(c.id, ref)
    expectedOut = { result: 'accept', payload_ref: ref }
  } catch (e) {
    if (c.expected.result !== 'reject') {
      fail(`${c.id}: TS rejected a payload expected to accept: ${(e as Error).message}`)
    }
    expectedOut = { result: 'reject', failure: c.expected.failure, ts_error_message: (e as Error).message }
  }
  record('payload', provenance)
  cases.push({
    id: c.id,
    entry: 'payload',
    input: c.payload,
    expected: expectedOut,
    expected_provenance: provenance,
    draft_lines,
    ...(c.provenance_note ? { provenance_note: c.provenance_note } : {}),
  })
}

// -------------------------------------------------------------------------
// BASE input object
// -------------------------------------------------------------------------

const payloadRefP01 = payloadRefById.get('PR-P01')
if (!payloadRefP01) fail('PR-P01 payload_ref unavailable for BASE construction')
const payloadRefP04 = payloadRefById.get('PR-P04')
if (!payloadRefP04) fail('PR-P04 payload_ref unavailable')

const BASE = {
  profile: 'aps-action-ref-v2',
  agent_id: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
  action_type: 'commerce_preflight',
  target: 'https://api.example/payments',
  payload_ref: payloadRefP01,
  scope_required: ['commerce:read', 'commerce:write'],
  issued_at: '2026-04-08T12:00:00.000Z',
  nonce: '00112233445566778899aabbccddeeff',
} as const

function base(overrides: Record<string, unknown>): Record<string, unknown> {
  return { ...BASE, ...overrides }
}

// -------------------------------------------------------------------------
// action_ref cases, entry "object"
// -------------------------------------------------------------------------

interface ObjectCase {
  id: string
  input: unknown
  expected: { result: 'accept' } | { result: 'reject'; failure: string }
}

const objectCases: ObjectCase[] = [
  { id: 'AR-P01', input: base({}), expected: { result: 'accept' } },
  { id: 'AR-P02', input: base({ scope_required: ['commerce:write'] }), expected: { result: 'accept' } },
  { id: 'AR-P03', input: base({ target: 'https://api.example/refunds' }), expected: { result: 'accept' } },
  { id: 'AR-P04', input: base({ payload_ref: payloadRefP04 }), expected: { result: 'accept' } },
  { id: 'AR-P05', input: base({ nonce: 'ffeeddccbbaa99887766554433221100' }), expected: { result: 'accept' } },
  { id: 'AR-P06', input: base({ issued_at: '2026-04-08T12:00:00.001Z' }), expected: { result: 'accept' } },
  { id: 'AR-P07', input: base({ scope_required: ['café:read', 'repo:write'] }), expected: { result: 'accept' } },
  { id: 'AR-P08', input: base({ scope_required: ['｡:x', '😀:y'] }), expected: { result: 'accept' } },
  { id: 'AR-P09', input: base({ target: 'https://api.example/p?q="a\\b"\n\u2028' }), expected: { result: 'accept' } },
  { id: 'AR-P10', input: base({ agent_id: 'did:example:😀' }), expected: { result: 'accept' } },
  { id: 'AR-P11', input: base({ issued_at: '2028-02-29T23:59:59.999Z' }), expected: { result: 'accept' } },
  { id: 'AR-P12', input: base({ issued_at: '0001-01-01T00:00:00.000Z' }), expected: { result: 'accept' } },
  { id: 'AR-P13', input: base({ issued_at: '2000-02-29T00:00:00.000Z' }), expected: { result: 'accept' } },
  {
    id: 'AR-P14',
    input: base({
      nonce: '00000000000000000000000000000000',
      payload_ref: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    }),
    expected: { result: 'accept' },
  },
  {
    id: 'AR-P15',
    input: base({
      scope_required: [
        '*', 'commerce:*', 'commerce:read', 'data:read', 'data:write',
        'repo:read', 'repo:write', 'z:1', 'z:10', 'z:2',
      ],
    }),
    expected: { result: 'accept' },
  },
  { id: 'AR-P16', input: base({ target: 'https://api.example/' + 'a'.repeat(980) }), expected: { result: 'accept' } },

  { id: 'AR-N01', input: { ...base({}), extra: 'x' }, expected: { result: 'reject', failure: 'unknown_member' } },
  { id: 'AR-N02', input: (() => { const { nonce, ...rest } = base({}); return rest })(), expected: { result: 'reject', failure: 'missing_member' } },
  { id: 'AR-N03', input: base({ profile: 'aps-action-ref-v1' }), expected: { result: 'reject', failure: 'wrong_profile' } },
  { id: 'AR-N04', input: base({ agent_id: '' }), expected: { result: 'reject', failure: 'empty_string' } },
  { id: 'AR-N05', input: base({ action_type: '' }), expected: { result: 'reject', failure: 'empty_string' } },
  { id: 'AR-N06', input: base({ target: '' }), expected: { result: 'reject', failure: 'empty_string' } },
  { id: 'AR-N07', input: base({ agent_id: 123 }), expected: { result: 'reject', failure: 'not_string' } },
  { id: 'AR-N08', input: base({ target: null }), expected: { result: 'reject', failure: 'not_string' } },
  { id: 'AR-N09', input: base({ payload_ref: payloadRefP01.toUpperCase() }), expected: { result: 'reject', failure: 'bad_hex' } },
  { id: 'AR-N10', input: base({ payload_ref: payloadRefP01.slice(0, 63) }), expected: { result: 'reject', failure: 'bad_hex' } },
  { id: 'AR-N11', input: base({ payload_ref: payloadRefP01.slice(0, 63) + 'g' }), expected: { result: 'reject', failure: 'bad_hex' } },
  { id: 'AR-N12', input: base({ payload_ref: 12345 }), expected: { result: 'reject', failure: 'not_string' } },
  { id: 'AR-N13', input: base({ nonce: BASE.nonce.slice(0, 31) }), expected: { result: 'reject', failure: 'bad_hex' } },
  { id: 'AR-N14', input: base({ nonce: BASE.nonce.toUpperCase() }), expected: { result: 'reject', failure: 'bad_hex' } },
  { id: 'AR-N15', input: base({ issued_at: '2026-04-08T12:00:00Z' }), expected: { result: 'reject', failure: 'bad_timestamp' } },
  { id: 'AR-N16', input: base({ issued_at: '2026-04-08T12:00:00.000000Z' }), expected: { result: 'reject', failure: 'bad_timestamp' } },
  { id: 'AR-N17', input: base({ issued_at: '2026-04-08T12:00:00.000+00:00' }), expected: { result: 'reject', failure: 'bad_timestamp' } },
  { id: 'AR-N18', input: base({ issued_at: '2026-04-08t12:00:00.000z' }), expected: { result: 'reject', failure: 'bad_timestamp' } },
  { id: 'AR-N19', input: base({ issued_at: '2026-02-30T00:00:00.000Z' }), expected: { result: 'reject', failure: 'bad_timestamp' } },
  { id: 'AR-N20', input: base({ issued_at: '2026-04-08T24:00:00.000Z' }), expected: { result: 'reject', failure: 'bad_timestamp' } },
  { id: 'AR-N21', input: base({ issued_at: '2026-13-01T00:00:00.000Z' }), expected: { result: 'reject', failure: 'bad_timestamp' } },
  { id: 'AR-N22', input: base({ issued_at: '2027-02-29T00:00:00.000Z' }), expected: { result: 'reject', failure: 'bad_timestamp' } },
  { id: 'AR-N23', input: base({ issued_at: ['2026-04-08T12:00:00.000Z'] }), expected: { result: 'reject', failure: 'not_string' } },
  { id: 'AR-N24', input: base({ nonce: ['00112233445566778899aabbccddeeff'] }), expected: { result: 'reject', failure: 'not_string' } },
  { id: 'AR-N25', input: base({ payload_ref: [payloadRefP01] }), expected: { result: 'reject', failure: 'not_string' } },
  { id: 'AR-N26', input: base({ payload_ref: [[payloadRefP01]] }), expected: { result: 'reject', failure: 'not_string' } },
  { id: 'AR-N27', input: base({ scope_required: 'commerce:write' }), expected: { result: 'reject', failure: 'scope_not_array' } },
  { id: 'AR-N28', input: base({ scope_required: ['commerce:write', 'commerce:read'] }), expected: { result: 'reject', failure: 'scope_not_canonical' } },
  { id: 'AR-N29', input: base({ scope_required: ['commerce:read', 'commerce:read'] }), expected: { result: 'reject', failure: 'scope_not_canonical' } },
  { id: 'AR-N30', input: base({ scope_required: ['café:read'] }), expected: { result: 'reject', failure: 'scope_not_canonical' } },
  { id: 'AR-N31', input: base({ scope_required: ['😀:y', '｡:x'] }), expected: { result: 'reject', failure: 'scope_not_canonical' } },
  { id: 'AR-N32', input: base({ scope_required: [''] }), expected: { result: 'reject', failure: 'empty_string' } },
  { id: 'AR-N33', input: base({ scope_required: [1] }), expected: { result: 'reject', failure: 'not_string' } },
  { id: 'AR-N34', input: base({ agent_id: 'did:example:\uD800' }), expected: { result: 'reject', failure: 'lone_surrogate' } },
  { id: 'AR-N35', input: base({ scope_required: ['\uDC00:x'] }), expected: { result: 'reject', failure: 'lone_surrogate' } },
  { id: 'AR-N36', input: [base({})], expected: { result: 'reject', failure: 'not_object' } },
  { id: 'AR-N37', input: null, expected: { result: 'reject', failure: 'not_object' } },
]

const actionRefById = new Map<string, string>()

for (const c of objectCases) {
  const provenance: Provenance = c.expected.result === 'accept' ? 'ts-conformant-regression' : 'draft-derived'
  const draft_lines = c.expected.result === 'accept' ? '807-808' : draftLinesForFailure(c.expected.failure)
  let expectedOut: Record<string, unknown>
  try {
    const ref = computeActionRefV2(c.input)
    if (c.expected.result !== 'accept') {
      fail(`${c.id}: TS accepted an input expected to reject (${c.expected.failure})`)
    }
    actionRefById.set(c.id, ref)
    expectedOut = { result: 'accept', action_ref: ref }
  } catch (e) {
    if (c.expected.result !== 'reject') {
      fail(`${c.id}: TS rejected an input expected to accept: ${(e as Error).message}`)
    }
    expectedOut = { result: 'reject', failure: c.expected.failure, ts_error_message: (e as Error).message }
  }
  record('object', provenance)
  cases.push({
    id: c.id,
    entry: 'object',
    input: c.input,
    expected: expectedOut,
    expected_provenance: provenance,
    draft_lines,
  })
}

// -------------------------------------------------------------------------
// action_ref cases, entry "json"
// -------------------------------------------------------------------------

/** Serialize `entries` (in the given order) as a JSON object text, with a
 *  space after every colon and every comma. Used only for AJ-P01, which
 *  exists to prove the strict parser is order- and whitespace-insensitive. */
function serializeSpaced(entries: [string, unknown][]): string {
  const parts = entries.map(([k, v]) => `${JSON.stringify(k)}: ${JSON.stringify(v)}`)
  return '{' + parts.join(', ') + '}'
}

const AJ_P01_RAW = serializeSpaced([
  ['nonce', BASE.nonce],
  ['issued_at', BASE.issued_at],
  ['scope_required', BASE.scope_required],
  ['payload_ref', BASE.payload_ref],
  ['target', BASE.target],
  ['action_type', BASE.action_type],
  ['agent_id', BASE.agent_id],
  ['profile', BASE.profile],
])

const AJ_N01_INSERT = '"agent_id":"did:example:attacker",'
const AJ_N01_RAW = (() => {
  const plain = JSON.stringify(base({}))
  return '{' + AJ_N01_INSERT + plain.slice(1)
})()

// "escaped duplicate": the inserted member name decodes to the same logical
// name ("agent_id") as AJ-N01, but is written with a JSON \u escape for one
// of its characters, so the duplicate is only visible after escape
// decoding , the exact case draft lines 814-817 describe ("compared after
// escape decoding" / "MUST NOT accept the last occurrence silently").
const AJ_N02_INSERT = '"\\u0061gent_id":"did:example:attacker",'
const AJ_N02_RAW = (() => {
  const plain = JSON.stringify(base({}))
  return '{' + AJ_N02_INSERT + plain.slice(1)
})()

// The JSON *escape text* for a lone high surrogate, not a raw code unit:
// JSON.stringify already emits \uXXXX for an unpaired surrogate (a
// well-formed-JSON.stringify guarantee), so building the target from an
// actual lone-surrogate JS string and then JSON.stringify-ing the object
// produces exactly that escape text in the raw document.
const AJ_N03_RAW = JSON.stringify(base({ target: 'https://api.example/\uD800' }))

const AJ_N04_RAW = JSON.stringify(base({})) + ' {}'

const AJ_N05_RAW = (() => {
  const plain = JSON.stringify(base({}))
  return plain.slice(0, -1) + ',"x":1e400}'
})()

interface JsonCase {
  id: string
  raw: string
  expected: { result: 'accept' } | { result: 'reject'; failure?: string }
  equalsActionRefOf?: string
}

const jsonCases: JsonCase[] = [
  { id: 'AJ-P01', raw: AJ_P01_RAW, expected: { result: 'accept' }, equalsActionRefOf: 'AR-P01' },
  { id: 'AJ-N01', raw: AJ_N01_RAW, expected: { result: 'reject', failure: 'duplicate_member' } },
  { id: 'AJ-N02', raw: AJ_N02_RAW, expected: { result: 'reject', failure: 'duplicate_member' } },
  { id: 'AJ-N03', raw: AJ_N03_RAW, expected: { result: 'reject', failure: 'lone_surrogate' } },
  { id: 'AJ-N04', raw: AJ_N04_RAW, expected: { result: 'reject', failure: 'non_i_json' } },
  { id: 'AJ-N05', raw: AJ_N05_RAW, expected: { result: 'reject' } }, // failure class recorded from actual TS behavior
]

for (const c of jsonCases) {
  let failure = c.expected.result === 'reject' ? c.expected.failure : undefined
  let expectedOut: Record<string, unknown>
  try {
    const ref = computeActionRefV2FromJson(c.raw)
    if (c.expected.result !== 'accept') {
      fail(`${c.id}: TS accepted a JSON document expected to reject`)
    }
    if (c.equalsActionRefOf) {
      const other = actionRefById.get(c.equalsActionRefOf)
      if (ref !== other) {
        fail(`${c.id}: action_ref ${ref} does not equal ${c.equalsActionRefOf} (${other}) as the spec requires`)
      }
    }
    expectedOut = { result: 'accept', action_ref: ref }
  } catch (e) {
    if (c.expected.result !== 'reject') {
      fail(`${c.id}: TS rejected a JSON document expected to accept: ${(e as Error).message}`)
    }
    const message = (e as Error).message
    if (!failure) {
      // AJ-N05 only: the spec leaves the failure class open and asks that we
      // record whichever class TS actually reports, STOPping only if TS
      // does not reject at all (handled by the catch itself firing).
      if (/non-finite number|non-I-JSON|IJsonValidationError|unsupported/i.test(message)) {
        failure = 'non_i_json'
      } else if (/unknown field/i.test(message)) {
        failure = 'unknown_member'
      } else {
        fail(`${c.id}: TS rejected but its message matches neither non_i_json nor unknown_member: ${message}`)
      }
    }
    expectedOut = { result: 'reject', failure, ts_error_message: message }
  }
  const provenance: Provenance = c.expected.result === 'accept' ? 'ts-conformant-regression' : 'draft-derived'
  const draft_lines = c.expected.result === 'accept' ? '807-808' : draftLinesForFailure(failure as string)
  record('json', provenance)
  cases.push({
    id: c.id,
    entry: 'json',
    input_json: c.raw,
    expected: expectedOut,
    expected_provenance: provenance,
    draft_lines,
  })
}

// -------------------------------------------------------------------------
// action_ref cases, entry "create"
// -------------------------------------------------------------------------

interface CreateCase {
  id: string
  scopeInput: string[]
  expected: { result: 'accept' } | { result: 'reject'; failure: string }
  equalsActionRefOf?: string
}

const createCases: CreateCase[] = [
  { id: 'AC-P01', scopeInput: ['repo:write', 'café:read'], expected: { result: 'accept' }, equalsActionRefOf: 'AR-P07' },
  { id: 'AC-P02', scopeInput: ['commerce:write', 'commerce:read'], expected: { result: 'accept' }, equalsActionRefOf: 'AR-P01' },
  { id: 'AC-P03', scopeInput: ['😀:y', '｡:x'], expected: { result: 'accept' }, equalsActionRefOf: 'AR-P08' },
  { id: 'AC-N01', scopeInput: ['caf\u00e9:read', 'cafe\u0301:read'], expected: { result: 'reject', failure: 'scope_not_canonical' } },
]

for (const c of createCases) {
  const createInput = {
    agent_id: BASE.agent_id,
    action_type: BASE.action_type,
    target: BASE.target,
    payload_ref: BASE.payload_ref,
    scope_required: c.scopeInput,
    issued_at: BASE.issued_at,
    nonce: BASE.nonce,
  }
  const provenance: Provenance = c.expected.result === 'accept' ? 'ts-conformant-regression' : 'draft-derived'
  const draft_lines = c.expected.result === 'accept' ? '794-796, 807-808, 819-824' : draftLinesForFailure(c.expected.failure)
  let expectedOut: Record<string, unknown>
  try {
    const canonical = createActionReferenceInputV2(createInput)
    if (c.expected.result !== 'accept') {
      fail(`${c.id}: TS accepted a create input expected to reject (${c.expected.failure})`)
    }
    const ref = computeActionRefV2(canonical)
    if (c.equalsActionRefOf) {
      const other = actionRefById.get(c.equalsActionRefOf)
      if (ref !== other) {
        fail(`${c.id}: action_ref ${ref} does not equal ${c.equalsActionRefOf} (${other}) as the spec requires`)
      }
    }
    expectedOut = { result: 'accept', action_ref: ref, canonical_input: canonical }
  } catch (e) {
    if (c.expected.result !== 'reject') {
      fail(`${c.id}: TS rejected a create input expected to accept: ${(e as Error).message}`)
    }
    expectedOut = { result: 'reject', failure: c.expected.failure, ts_error_message: (e as Error).message }
  }
  record('create', provenance)
  cases.push({
    id: c.id,
    entry: 'create',
    create_input: createInput,
    expected: expectedOut,
    expected_provenance: provenance,
    draft_lines,
  })
}

// -------------------------------------------------------------------------
// Assemble and write
// -------------------------------------------------------------------------

const document = {
  name: 'aps-action-ref-v2 and payload_ref vectors',
  draft: 'draft-pidlisnyi-aps-03 section 4.1 (published text lines 751-832)',
  generated_from: {
    repository: 'aeoess/agent-passport-system',
    commit: tsCommit,
    module: 'src/v2/action-reference/v2.ts',
    generator: 'tests/cross_impl/gen_action_ref_v2_vectors.mts',
  },
  expected_provenance_values: EXPECTED_PROVENANCE_VALUES,
  failure_codes: FAILURE_CODES,
  withheld: WITHHELD,
  counts,
  cross_checks: CROSS_CHECKS,
  ts_error_messages_note: TS_ERROR_MESSAGES_NOTE,
  cases,
}

writeFileSync(outPath, JSON.stringify(document, null, 2) + '\n', 'utf8')
console.log(`wrote ${cases.length} cases to ${outPath}`)
console.log(JSON.stringify(counts, null, 2))
