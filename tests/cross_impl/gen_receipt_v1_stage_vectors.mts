// Generator for the ReceiptV1 stage cross-implementation vector file
// (tests/cross_impl/receipt-v1-stage-vectors.json).
//
// The expected result of every case is fixed in this script, next to the draft
// lines (draft-pidlisnyi-aps-03 sections 5.1, 5.2, 5.3 and 5.6) or the RFC 3339
// citation it rests on, and that text is copied into the case's derivation. This
// script does not decide any of those. It builds the exact record each case
// describes, calls the TypeScript reference implementation, and fills in the bytes
// any implementation must reproduce (receipt_id, signature values). If the TS
// reference disagrees with a fixed expectation, the script prints
// "STOP: <case id>: expected ... got ..." and exits 1 without writing the output
// file, instead of recording whatever TypeScript produced.
//
// The TS repository is located purely through the APS_TS_REPO environment variable
// and the pinned commit purely through APS_TS_COMMIT. This file must never contain
// a local absolute path literal: a pre-commit hook blocks commits containing local
// home paths.
//
// Usage:
//   APS_TS_REPO=/path/to/agent-passport-system \
//   APS_TS_COMMIT=<sha> \
//   npx tsx tests/cross_impl/gen_receipt_v1_stage_vectors.mts <output.json>

import { execFileSync } from 'node:child_process'
import { writeFileSync } from 'node:fs'

const tsRepo = process.env.APS_TS_REPO
const tsCommit = process.env.APS_TS_COMMIT
const outPath = process.argv[2]

function fail(message: string): never {
  console.error(`STOP: ${message}`)
  process.exit(1)
}

if (!tsRepo) fail('APS_TS_REPO is not set')
if (!tsCommit) fail('APS_TS_COMMIT is not set')
if (!outPath) fail('output path argument is required')

{
  const head = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: tsRepo, encoding: 'utf8' }).trim()
  if (head !== tsCommit) fail(`TS repo HEAD is ${head}, expected ${tsCommit}`)
  const porcelain = execFileSync('git', ['status', '--porcelain'], { cwd: tsRepo, encoding: 'utf8' })
  if (porcelain.trim() !== '') fail(`TS repo is not clean:\n${porcelain}`)
}

const src = (file: string): string => new URL(`file://${tsRepo}/src/${file}`).href
const { createReceiptV1, validateReceiptV1, verifyReceiptV1 } = await import(src('v2/receipt-core/receipt.js'))
const { validateReceiptStageV1 } = await import(src('v2/receipt-core/stage.js'))
const { publicKeyFromPrivate } = await import(src('crypto/keys.js'))

type Json = null | boolean | number | string | Json[] | { [key: string]: Json }
type Mutation = Record<string, Json | undefined>

const AGENT = 'did:example:agent'
const BOUNDARY = 'did:example:gateway'
const AGENT_KEY = '00'.repeat(32)
const BOUNDARY_KEY = '11'.repeat(32)
const OTHER_KEY = '22'.repeat(32)
const ISSUED_AT = '2026-07-18T12:00:00.000Z'
const VALID_UNTIL = '2026-07-18T12:00:05.000Z'
const hex = (c: string): string => c.repeat(64)

const BASES = {
  intent: {
    signer: AGENT,
    key: AGENT_KEY,
    body: {
      profile: 'aps-receipt-v1',
      receipt_type: 'aps:action-intent:v1',
      issuer: AGENT,
      subject_agent: AGENT,
      action_ref: hex('a'),
      delegation_ref: `sha256:${hex('b')}`,
      issued_at: ISSUED_AT,
      evidence_refs: [],
      result: { profile: 'aps-action-intent-result-v1', status: 'declared' },
    } as Record<string, Json>,
  },
  decision: {
    signer: BOUNDARY,
    key: BOUNDARY_KEY,
    body: {
      profile: 'aps-receipt-v1',
      receipt_type: 'aps:policy-decision:v1',
      issuer: BOUNDARY,
      subject_agent: AGENT,
      action_ref: hex('a'),
      delegation_ref: `sha256:${hex('b')}`,
      decision_ref: hex('c'),
      prev: hex('d'),
      issued_at: ISSUED_AT,
      evidence_refs: [],
      result: {
        profile: 'aps-core-decision-output-v1',
        verdict: 'permit',
        effective_authority_ref: hex('e'),
        constraints: [],
        valid_until: VALID_UNTIL,
      },
    } as Record<string, Json>,
  },
  result: {
    signer: BOUNDARY,
    key: BOUNDARY_KEY,
    body: {
      profile: 'aps-receipt-v1',
      receipt_type: 'aps:action-result:v1',
      issuer: BOUNDARY,
      subject_agent: AGENT,
      action_ref: hex('a'),
      delegation_ref: `sha256:${hex('b')}`,
      decision_ref: hex('c'),
      prev: hex('d'),
      issued_at: ISSUED_AT,
      evidence_refs: [],
      result: { profile: 'aps-action-result-v1', status: 'succeeded', effect_ref: hex('f'), error_code: null },
    } as Record<string, Json>,
  },
} as const

type BaseName = keyof typeof BASES

/** Applying a mutation: undefined removes the member, since a ReceiptV1 member that is
 *  not applicable is absent and not null (draft line 988). A mutation named `result.X`
 *  replaces one member of the result object. */
function applyMutation(body: Record<string, Json>, mutation: Mutation): Record<string, Json> {
  const next: Record<string, Json> = JSON.parse(JSON.stringify(body))
  for (const [key, value] of Object.entries(mutation)) {
    if (key.startsWith('result.')) {
      const member = key.slice('result.'.length)
      const result = next.result as Record<string, Json>
      if (value === undefined) delete result[member]
      else result[member] = value
      continue
    }
    if (value === undefined) delete next[key]
    else next[key] = value
  }
  return next
}

type Provenance = 'draft-derived' | 'ruling-derived'

interface EnvelopeCase {
  id: string
  kind: 'envelope'
  provenance?: Provenance
  title: string
  base: BaseName
  mutate?: Mutation
  accepts: boolean
  lines: string
  note: string
}

interface StageCase {
  id: string
  kind: 'stage'
  provenance?: Provenance
  title: string
  base: BaseName
  mutate?: Mutation
  context?: { expected_receipt_type?: string; boundary_identity?: string }
  expect: {
    status: 'valid' | 'invalid' | 'indeterminate' | 'unsupported'
    stage: string | null
    boundary_identity: 'verified' | 'mismatch' | 'not_established' | 'not_applicable'
    failure_codes: string[]
  }
  lines: string
  note: string
}

interface VerifyCase {
  id: string
  kind: 'verify'
  title: string
  base: BaseName
  mutate?: Mutation
  /** How the key resolver behaves for this case. */
  resolver: 'correct' | 'none' | 'raises' | 'other_key'
  expect: {
    status: 'valid' | 'invalid' | 'indeterminate' | 'unsupported'
    signer_authority: 'verified' | 'not_established' | 'invalid' | 'not_checked'
    errors: string[]
  }
  lines: string
  note: string
}

type Case = EnvelopeCase | StageCase | VerifyCase

// -------------------------------------------------------------------------
// The cases. Every expectation below is fixed from the draft text cited with it.
// -------------------------------------------------------------------------

const ENVELOPE: EnvelopeCase[] = [
  { id: 'RC-E01', kind: 'envelope', title: 'A conforming action-intent record is accepted', base: 'intent', accepts: true,
    lines: 'L938-999, L1052-1055', note: 'The control. Every rejection below is a one-member change from this record, so a rejection is the rule firing and not a broken fixture.' },
  { id: 'RC-E02', kind: 'envelope', title: 'action_ref as a one-element array', base: 'intent', mutate: { action_ref: [hex('a')] }, accepts: false,
    lines: 'L981-982, L1652-1660', note: 'action_ref is the aps-action-ref-v2 digest, a string. A malformed artifact gets a defined result and is not coerced into a conforming one.' },
  { id: 'RC-E03', kind: 'envelope', title: 'receipt_id as a one-element array', base: 'intent', mutate: { receipt_id: [hex('a')] }, accepts: false,
    lines: 'L959, L1652-1660', note: 'receipt_id is 64 lowercase hexadecimal characters, a string.' },
  { id: 'RC-E04', kind: 'envelope', title: 'issuer as a number', base: 'intent', mutate: { issuer: 1 }, accepts: false,
    lines: 'L980, L1652-1660', note: 'issuer is the party responsible for the record, a string identifier.' },
  { id: 'RC-E05', kind: 'envelope', title: 'subject_agent as an object', base: 'intent', mutate: { subject_agent: { did: 'x' } }, accepts: false,
    lines: 'L981, L1652-1660', note: 'subject_agent is the acting agent, a string identifier.' },
  { id: 'RC-E06', kind: 'envelope', title: 'receipt_type as a number', base: 'intent', mutate: { receipt_type: 1 }, accepts: false,
    lines: 'L979-980, L1652-1660', note: 'receipt_type identifies a stage defined in section 5.3, a string.' },
  { id: 'RC-E07', kind: 'envelope', title: 'delegation_ref as a bare 64 hex digest', base: 'intent', mutate: { delegation_ref: hex('b') }, accepts: false,
    lines: 'L964, L982, L484', note: 'delegation_ref identifies the selected AuthorityDelegationV1 leaf; the envelope example writes it with the "sha256:" prefix and section 3.1 gives delegation_id that exact form.' },
  { id: 'RC-E08', kind: 'envelope', title: 'delegation_ref with uppercase hexadecimal', base: 'intent', mutate: { delegation_ref: `sha256:${'B'.repeat(64)}` }, accepts: false,
    lines: 'L964, L484', note: 'The digest is lowercase hexadecimal.' },
  { id: 'RC-E09', provenance: 'ruling-derived', kind: 'envelope', title: 'delegation_ref as an identifier that is not a digest', base: 'intent', mutate: { delegation_ref: 'did:example:authority-basis' }, accepts: false,
    lines: 'L964, L982-984', note: 'The authority-basis case of line 983 has no encoding anywhere in section 5, so the only form this validator can check is the one the envelope example states. Recorded as a question, not as an accepted alternative.' },
  { id: 'RC-E10', kind: 'envelope', title: 'evidence_refs sha256 as a one-element array', base: 'intent', mutate: { evidence_refs: [{ artifact_type: 'a', sha256: [hex('d')] as unknown as Json }] }, accepts: false,
    lines: 'L991-993, L1652-1660', note: 'sha256 is the lowercase hexadecimal digest of the artifact bytes, a string.' },
  { id: 'RC-E11', kind: 'envelope', title: 'evidence_refs artifact_type as a number', base: 'intent', mutate: { evidence_refs: [{ artifact_type: 2 as unknown as Json, sha256: hex('d') }] }, accepts: false,
    lines: 'L991-993', note: 'An evidence reference contains exactly artifact_type and sha256, and artifact_type names the rules that select the bytes.' },
  { id: 'RC-E12', kind: 'envelope', title: 'evidence_refs out of order', base: 'intent', mutate: { evidence_refs: [{ artifact_type: 'z', sha256: hex('d') }, { artifact_type: 'a', sha256: hex('d') }] }, accepts: false,
    lines: 'L993-995', note: 'References are sorted first by the UTF-8 bytes of artifact_type and then by the ASCII bytes of sha256.' },
  { id: 'RC-E13', kind: 'envelope', title: 'A duplicate evidence reference', base: 'intent', mutate: { evidence_refs: [{ artifact_type: 'a', sha256: hex('d') }, { artifact_type: 'a', sha256: hex('d') }] }, accepts: false,
    lines: 'L991', note: 'evidence_refs is duplicate-free.' },
  { id: 'RC-E14', kind: 'envelope', title: 'An unknown envelope member', base: 'intent', mutate: { extra: 'x' }, accepts: false,
    lines: 'L938, L938-989', note: 'A ReceiptV1 is a closed JSON object.' },
  { id: 'RC-E15', kind: 'envelope', title: 'A not-applicable member present as null', base: 'intent', mutate: { decision_ref: null }, accepts: false,
    lines: 'L988-989', note: 'A member that is not applicable is absent, not null.' },
  { id: 'RC-E16', kind: 'envelope', title: 'A conforming leap second in issued_at', base: 'intent', mutate: { issued_at: '2026-06-30T23:59:60.000Z' }, accepts: true,
    lines: 'L986, RFC 3339 5.7 and Appendix D', note: 'RFC 3339 admits time-second 60 for a leap second and writes it YYYY-MM-DDT23:59:60Z. No leap-second table is consulted; the hour, minute and day settle it.' },
  { id: 'RC-E17', kind: 'envelope', title: 'Second 60 that is not on the last day of a month', base: 'intent', mutate: { issued_at: '2026-06-29T23:59:60.000Z' }, accepts: false,
    lines: 'L986, RFC 3339 5.7 and Appendix D', note: 'Every second-60 value outside 23:59 on the last day of its month is invalid.' },
  { id: 'RC-E18', kind: 'envelope', title: 'Second 60 that is not at 23:59', base: 'intent', mutate: { issued_at: '2026-06-30T22:59:60.000Z' }, accepts: false,
    lines: 'L986, RFC 3339 5.7 and Appendix D', note: 'Same rule, failing on the hour.' },
  { id: 'RC-E19', kind: 'envelope', title: 'February 29 outside a leap year', base: 'intent', mutate: { issued_at: '2026-02-29T12:00:00.000Z' }, accepts: false,
    lines: 'L986', note: 'The timestamp must be a calendar instant, checked in the proleptic Gregorian calendar.' },
  { id: 'RC-E20', kind: 'envelope', title: 'A Unicode noncharacter in a string value', base: 'intent', mutate: { issuer: 'did:example:a﷐' }, accepts: false,
    lines: 'L1213', note: 'A verifier parses bounded I-JSON. The same reading of I-JSON is applied on the section 4.1 and section 3 surfaces of these SDKs.' },
  { id: 'RC-E21', kind: 'envelope', title: 'A Unicode noncharacter in an object key', base: 'intent', mutate: { 'result.k￿': 'v' }, accepts: false,
    lines: 'L1213', note: 'The rule covers member names as well as values.' },
  { id: 'RC-E22', kind: 'envelope', title: 'An unpaired surrogate in a string', base: 'intent', mutate: { issuer: 'did:example:a\ud800' }, accepts: false,
    lines: 'L819-821, L1213', note: 'A string containing an unpaired UTF-16 surrogate has no UTF-8 encoding and is rejected rather than repaired.' },
]

const STAGE: StageCase[] = [
  { id: 'RC-S01', kind: 'stage', title: 'A conforming action intent', base: 'intent',
    expect: { status: 'valid', stage: 'action-intent', boundary_identity: 'not_applicable', failure_codes: [] },
    lines: 'L1052-1058', note: 'The control for the intent stage.' },
  { id: 'RC-S02', kind: 'stage', title: 'An action intent issued by someone other than the acting agent', base: 'intent', mutate: { issuer: BOUNDARY },
    expect: { status: 'invalid', stage: 'action-intent', boundary_identity: 'not_applicable', failure_codes: ['INTENT_ISSUER_NOT_ACTING_AGENT'] },
    lines: 'L1053', note: 'issuer and subject_agent MUST be the acting agent.' },
  { id: 'RC-S03', kind: 'stage', title: 'An action intent carrying prev', base: 'intent', mutate: { prev: hex('d') },
    expect: { status: 'invalid', stage: 'action-intent', boundary_identity: 'not_applicable', failure_codes: ['INTENT_PREV_PRESENT'] },
    lines: 'L1053-1054, L986-988', note: 'prev MUST be absent from an action-intent record.' },
  { id: 'RC-S04', kind: 'stage', title: 'An action intent carrying decision_ref', base: 'intent', mutate: { decision_ref: hex('c') },
    expect: { status: 'invalid', stage: 'action-intent', boundary_identity: 'not_applicable', failure_codes: ['INTENT_DECISION_REF_PRESENT'] },
    lines: 'L1053-1054, L984-986', note: 'decision_ref MUST be absent from an action-intent record.' },
  { id: 'RC-S05', kind: 'stage', title: 'An action intent whose result status is not declared', base: 'intent', mutate: { 'result.status': 'succeeded' },
    expect: { status: 'invalid', stage: 'action-intent', boundary_identity: 'not_applicable', failure_codes: ['INTENT_RESULT_INVALID'] },
    lines: 'L1054-1055', note: 'result MUST contain exactly profile aps-action-intent-result-v1 and status declared.' },
  { id: 'RC-S06', kind: 'stage', title: 'An action intent whose result carries an extra member', base: 'intent', mutate: { 'result.extra': 1 },
    expect: { status: 'invalid', stage: 'action-intent', boundary_identity: 'not_applicable', failure_codes: ['INTENT_RESULT_INVALID'] },
    lines: 'L1054-1055, L995-996', note: 'Exactly those two members: the result is the closed typed object defined by receipt_type.' },
  { id: 'RC-S07', kind: 'stage', title: 'An action intent under another result profile', base: 'intent', mutate: { 'result.profile': 'aps-action-intent-result-v2' },
    expect: { status: 'invalid', stage: 'action-intent', boundary_identity: 'not_applicable', failure_codes: ['INTENT_RESULT_PROFILE'] },
    lines: 'L1054-1055', note: 'A wrong result profile for a stage that is recognised is invalid, not unsupported: that result object is closed.' },
  { id: 'RC-S08', kind: 'stage', title: 'A conforming policy decision with the boundary identity supplied', base: 'decision', context: { boundary_identity: BOUNDARY },
    expect: { status: 'valid', stage: 'policy-decision', boundary_identity: 'verified', failure_codes: [] },
    lines: 'L1069-1091', note: 'The control for the decision stage.' },
  { id: 'RC-S09', provenance: 'ruling-derived', kind: 'stage', title: 'The same decision with no boundary identity supplied', base: 'decision',
    expect: { status: 'indeterminate', stage: 'policy-decision', boundary_identity: 'not_established', failure_codes: [] },
    lines: 'L1072, L1226-1228', note: 'The expected boundary identity is verifier trust input. Unestablished is indeterminate and never valid, and a caller may not collapse it into valid.' },
  { id: 'RC-S10', provenance: 'ruling-derived', kind: 'stage', title: 'A decision whose issuer is not the supplied boundary', base: 'decision', context: { boundary_identity: 'did:example:other-gateway' },
    expect: { status: 'invalid', stage: 'policy-decision', boundary_identity: 'mismatch', failure_codes: ['BOUNDARY_IDENTITY_MISMATCH'] },
    lines: 'L1072', note: 'A mismatch against a supplied identity is invalid.' },
  { id: 'RC-S11', provenance: 'ruling-derived', kind: 'stage', title: 'A decision whose issuer equals its subject_agent', base: 'decision', mutate: { issuer: AGENT }, context: { boundary_identity: AGENT },
    expect: { status: 'valid', stage: 'policy-decision', boundary_identity: 'verified', failure_codes: [] },
    lines: 'L1072', note: 'The draft states no rule that issuer differs from subject_agent for this stage. None is invented: the record stands or falls on the supplied boundary identity.' },
  { id: 'RC-S12', kind: 'stage', title: 'A decision with no prev', base: 'decision', mutate: { prev: undefined }, context: { boundary_identity: BOUNDARY },
    expect: { status: 'invalid', stage: 'policy-decision', boundary_identity: 'verified', failure_codes: ['DECISION_PREV_MISSING'] },
    lines: 'L986-987, L1072-1073', note: 'prev is REQUIRED for a policy-decision record and is the receipt_id of the action-intent record.' },
  { id: 'RC-S13', kind: 'stage', title: 'A decision with no decision_ref', base: 'decision', mutate: { decision_ref: undefined }, context: { boundary_identity: BOUNDARY },
    expect: { status: 'invalid', stage: 'policy-decision', boundary_identity: 'verified', failure_codes: ['DECISION_REF_MISSING'] },
    lines: 'L984-985, L1073-1074', note: 'decision_ref is REQUIRED for a policy-decision record.' },
  { id: 'RC-S14', kind: 'stage', title: 'A verdict outside the three the draft names', base: 'decision', mutate: { 'result.verdict': 'approve' }, context: { boundary_identity: BOUNDARY },
    expect: { status: 'invalid', stage: 'policy-decision', boundary_identity: 'verified', failure_codes: ['DECISION_RESULT_INVALID'] },
    lines: 'L1086', note: 'verdict is permit, deny, or narrow.' },
  { id: 'RC-S15', kind: 'stage', title: 'A permit with a null effective_authority_ref', base: 'decision', mutate: { 'result.effective_authority_ref': null }, context: { boundary_identity: BOUNDARY },
    expect: { status: 'invalid', stage: 'policy-decision', boundary_identity: 'verified', failure_codes: ['DECISION_RESULT_INVALID'] },
    lines: 'L1089-1090', note: 'effective_authority_ref is null for deny and a digest for permit or narrow.' },
  { id: 'RC-S16', kind: 'stage', title: 'A permit with a null valid_until', base: 'decision', mutate: { 'result.valid_until': null }, context: { boundary_identity: BOUNDARY },
    expect: { status: 'invalid', stage: 'policy-decision', boundary_identity: 'verified', failure_codes: ['DECISION_RESULT_INVALID'] },
    lines: 'L1090-1091', note: 'valid_until is null for deny and a timestamp later than issued_at for permit or narrow.' },
  { id: 'RC-S17', kind: 'stage', title: 'A conforming deny decision', base: 'decision',
    mutate: { 'result.verdict': 'deny', 'result.effective_authority_ref': null, 'result.valid_until': null }, context: { boundary_identity: BOUNDARY },
    expect: { status: 'valid', stage: 'policy-decision', boundary_identity: 'verified', failure_codes: [] },
    lines: 'L1089-1091', note: 'A deny decision carries both nulls by rule. It is a conforming record, not a temporal failure.' },
  { id: 'RC-S18', kind: 'stage', title: 'A deny decision that still carries an effective_authority_ref', base: 'decision',
    mutate: { 'result.verdict': 'deny', 'result.valid_until': null }, context: { boundary_identity: BOUNDARY },
    expect: { status: 'invalid', stage: 'policy-decision', boundary_identity: 'verified', failure_codes: ['DECISION_RESULT_INVALID'] },
    lines: 'L1089-1090', note: 'Null for deny is a rule in both directions.' },
  { id: 'RC-S19', kind: 'stage', title: 'valid_until equal to issued_at', base: 'decision', mutate: { 'result.valid_until': ISSUED_AT }, context: { boundary_identity: BOUNDARY },
    expect: { status: 'invalid', stage: 'policy-decision', boundary_identity: 'verified', failure_codes: ['DECISION_VALID_UNTIL_NOT_AFTER_ISSUED_AT'] },
    lines: 'L1090-1091', note: 'Later than issued_at is strict, and the comparison is against this record own issuance time.' },
  { id: 'RC-S20', kind: 'stage', title: 'Constraints not sorted by UTF-8 bytes', base: 'decision', mutate: { 'result.constraints': ['b', 'a'] }, context: { boundary_identity: BOUNDARY },
    expect: { status: 'invalid', stage: 'policy-decision', boundary_identity: 'verified', failure_codes: ['DECISION_RESULT_INVALID'] },
    lines: 'L1086-1087, L822-824', note: 'constraints is a duplicate-free array of NFC strings sorted by UTF-8 bytes. A verifier accepts the canonical form and does not normalize an untrusted wire object.' },
  { id: 'RC-S21', kind: 'stage', title: 'A duplicate constraint', base: 'decision', mutate: { 'result.constraints': ['a', 'a'] }, context: { boundary_identity: BOUNDARY },
    expect: { status: 'invalid', stage: 'policy-decision', boundary_identity: 'verified', failure_codes: ['DECISION_RESULT_INVALID'] },
    lines: 'L1086-1087', note: 'Duplicate-free.' },
  { id: 'RC-S22', kind: 'stage', title: 'A constraint that is not in NFC', base: 'decision', mutate: { 'result.constraints': ['é'] }, context: { boundary_identity: BOUNDARY },
    expect: { status: 'invalid', stage: 'policy-decision', boundary_identity: 'verified', failure_codes: ['DECISION_RESULT_INVALID'] },
    lines: 'L1086-1087', note: 'The decomposed form of the same character is not the NFC form.' },
  { id: 'RC-S23', kind: 'stage', title: 'Canonical constraints are accepted', base: 'decision', mutate: { 'result.constraints': ['a', 'b'] }, context: { boundary_identity: BOUNDARY },
    expect: { status: 'valid', stage: 'policy-decision', boundary_identity: 'verified', failure_codes: [] },
    lines: 'L1086-1087', note: 'The control for the three rejections above.' },
  { id: 'RC-S24', kind: 'stage', title: 'A decision result under another profile', base: 'decision', mutate: { 'result.profile': 'aps-core-decision-output-v2' }, context: { boundary_identity: BOUNDARY },
    expect: { status: 'invalid', stage: 'policy-decision', boundary_identity: 'verified', failure_codes: ['DECISION_RESULT_INVALID'] },
    lines: 'L1078, L1226-1227', note: 'A wrong result profile for a recognised stage is invalid, where an unknown envelope profile is unsupported.' },
  { id: 'RC-S25', kind: 'stage', title: 'A conforming succeeded action result', base: 'result', context: { boundary_identity: BOUNDARY },
    expect: { status: 'valid', stage: 'action-result', boundary_identity: 'verified', failure_codes: [] },
    lines: 'L1101-1130', note: 'The control for the result stage.' },
  { id: 'RC-S26', kind: 'stage', title: 'succeeded with no effect_ref', base: 'result', mutate: { 'result.effect_ref': null }, context: { boundary_identity: BOUNDARY },
    expect: { status: 'invalid', stage: 'action-result', boundary_identity: 'verified', failure_codes: ['RESULT_EFFECT_REF_REQUIRED'] },
    lines: 'L1125-1126', note: 'For succeeded, effect_ref is REQUIRED.' },
  { id: 'RC-S27', kind: 'stage', title: 'succeeded carrying an error_code', base: 'result', mutate: { 'result.error_code': 'E_X' }, context: { boundary_identity: BOUNDARY },
    expect: { status: 'invalid', stage: 'action-result', boundary_identity: 'verified', failure_codes: ['RESULT_ERROR_CODE_PRESENT'] },
    lines: 'L1125-1126', note: 'For succeeded, error_code is null.' },
  { id: 'RC-S28', kind: 'stage', title: 'A conforming failed result with no effect artifact', base: 'result',
    mutate: { 'result.status': 'failed', 'result.effect_ref': null, 'result.error_code': 'E_TIMEOUT' }, context: { boundary_identity: BOUNDARY },
    expect: { status: 'valid', stage: 'action-result', boundary_identity: 'verified', failure_codes: [] },
    lines: 'L1126-1128', note: 'For failed, effect_ref is either a digest of a returned error artifact or null.' },
  { id: 'RC-S29', kind: 'stage', title: 'A conforming failed result with an error artifact digest', base: 'result',
    mutate: { 'result.status': 'failed', 'result.error_code': 'E_TIMEOUT' }, context: { boundary_identity: BOUNDARY },
    expect: { status: 'valid', stage: 'action-result', boundary_identity: 'verified', failure_codes: [] },
    lines: 'L1126-1128', note: 'The other admitted pairing for failed.' },
  { id: 'RC-S30', kind: 'stage', title: 'failed with an empty error_code', base: 'result',
    mutate: { 'result.status': 'failed', 'result.effect_ref': null, 'result.error_code': '' }, context: { boundary_identity: BOUNDARY },
    expect: { status: 'invalid', stage: 'action-result', boundary_identity: 'verified', failure_codes: ['RESULT_ERROR_CODE_REQUIRED'] },
    lines: 'L1126-1127', note: 'For failed, error_code is a non-empty stable identifier. Stability is not machine-checkable and is not claimed.' },
  { id: 'RC-S31', kind: 'stage', title: 'A conforming unknown result', base: 'result',
    mutate: { 'result.status': 'unknown', 'result.effect_ref': null }, context: { boundary_identity: BOUNDARY },
    expect: { status: 'valid', stage: 'action-result', boundary_identity: 'verified', failure_codes: [] },
    lines: 'L1128', note: 'For unknown, both are null.' },
  { id: 'RC-S32', kind: 'stage', title: 'unknown carrying an effect_ref', base: 'result', mutate: { 'result.status': 'unknown' }, context: { boundary_identity: BOUNDARY },
    expect: { status: 'invalid', stage: 'action-result', boundary_identity: 'verified', failure_codes: ['RESULT_UNKNOWN_NOT_NULL'] },
    lines: 'L1128', note: 'Both null means both.' },
  { id: 'RC-S33', kind: 'stage', title: 'A status outside the three the draft names', base: 'result', mutate: { 'result.status': 'partial' }, context: { boundary_identity: BOUNDARY },
    expect: { status: 'invalid', stage: 'action-result', boundary_identity: 'verified', failure_codes: ['RESULT_STATUS'] },
    lines: 'L1125', note: 'status is succeeded, failed, or unknown.' },
  { id: 'RC-S34', kind: 'stage', title: 'An action result missing a result member', base: 'result', mutate: { 'result.error_code': undefined }, context: { boundary_identity: BOUNDARY },
    expect: { status: 'invalid', stage: 'action-result', boundary_identity: 'verified', failure_codes: ['RESULT_MEMBERS'] },
    lines: 'L1106-1114', note: 'result contains exactly profile, status, effect_ref and error_code.' },
  { id: 'RC-S35', kind: 'stage', title: 'effect_ref as a one-element array', base: 'result', mutate: { 'result.effect_ref': [hex('f')] }, context: { boundary_identity: BOUNDARY },
    expect: { status: 'invalid', stage: 'action-result', boundary_identity: 'verified', failure_codes: ['RESULT_EFFECT_REF'] },
    lines: 'L1128-1130, L1652-1660', note: 'A non-null effect_ref is a lowercase hexadecimal digest, a string.' },
  { id: 'RC-S36', kind: 'stage', title: 'An action result under another result profile', base: 'result', mutate: { 'result.profile': 'aps-action-result-v2' }, context: { boundary_identity: BOUNDARY },
    expect: { status: 'invalid', stage: 'action-result', boundary_identity: 'verified', failure_codes: ['RESULT_PROFILE'] },
    lines: 'L1110', note: 'profile is aps-action-result-v1.' },
  { id: 'RC-S37', kind: 'stage', title: 'An action result with no prev and no decision_ref', base: 'result', mutate: { prev: undefined, decision_ref: undefined }, context: { boundary_identity: BOUNDARY },
    expect: { status: 'invalid', stage: 'action-result', boundary_identity: 'verified', failure_codes: ['RESULT_PREV_MISSING', 'RESULT_DECISION_REF_MISSING'] },
    lines: 'L984-988, L1104-1106', note: 'Both are REQUIRED for an action-result record.' },
  { id: 'RC-S38', provenance: 'ruling-derived', kind: 'stage', title: 'A receipt_type outside section 5.3', base: 'intent', mutate: { receipt_type: 'aps:action:v1' },
    expect: { status: 'unsupported', stage: null, boundary_identity: 'not_applicable', failure_codes: ['UNSUPPORTED_RECEIPT_TYPE'] },
    lines: 'L979-980, L1226-1228', note: 'receipt_type identifies a stage defined in section 5.3. A value outside those three is unsupported and never valid, and its body is not judged against a stage schema it may not belong to. Section 5.1 does not state this case, so it is recorded as ruled rather than as draft text.' },
  { id: 'RC-S39', kind: 'stage', title: 'Another envelope profile', base: 'intent', mutate: { profile: 'aps-receipt-v2' },
    expect: { status: 'unsupported', stage: null, boundary_identity: 'not_applicable', failure_codes: ['UNSUPPORTED_PROFILE'] },
    lines: 'L979, L1226-1227', note: 'An unknown required profile is unsupported.' },
  { id: 'RC-S40', kind: 'stage', title: 'A malformed envelope with a known stage type', base: 'intent', mutate: { issued_at: 'yesterday' },
    expect: { status: 'invalid', stage: null, boundary_identity: 'not_applicable', failure_codes: ['SCHEMA_INVALID'] },
    lines: 'L986, L1213-1215', note: 'The closed envelope check runs before the stage rules, and a structural failure is invalid whatever the receipt_type says.' },
  { id: 'RC-S41', kind: 'stage', title: 'The caller expects a stage the record does not name', base: 'intent', context: { expected_receipt_type: 'aps:policy-decision:v1' },
    expect: { status: 'invalid', stage: null, boundary_identity: 'not_applicable', failure_codes: ['STAGE_MISMATCH'] },
    lines: 'L979-980, L1219-1220', note: 'The stage comes from the record. A caller-supplied expectation that disagrees with receipt_type is itself a failure, not a way to select the rules.' },
]

const VERIFY: VerifyCase[] = [
  { id: 'RC-V01', kind: 'verify', title: 'A resolvable key and a good signature', base: 'intent', resolver: 'correct',
    expect: { status: 'valid', signer_authority: 'verified', errors: [] },
    lines: 'L1036-1039', note: 'The control.' },
  { id: 'RC-V02', kind: 'verify', title: 'The resolver returns no key', base: 'intent', resolver: 'none',
    expect: { status: 'indeterminate', signer_authority: 'not_established', errors: ['signer_authority_indeterminate'] },
    lines: 'L322, L360-369, L1226', note: 'Key resolution is its own outcome and missing live state is indeterminate. An unresolved key is not evidence that a signature is wrong.' },
  { id: 'RC-V03', kind: 'verify', title: 'The resolver raises', base: 'intent', resolver: 'raises',
    expect: { status: 'indeterminate', signer_authority: 'not_established', errors: ['signer_authority_indeterminate'] },
    lines: 'L360-369, L1226, L1656-1660', note: 'A failing resolver is a resolution outcome, and a verification interface handles it through a defined result.' },
  { id: 'RC-V04', kind: 'verify', title: 'A resolvable key that did not sign this receipt', base: 'intent', resolver: 'other_key',
    expect: { status: 'invalid', signer_authority: 'invalid', errors: ['signature_invalid'] },
    lines: 'L1038-1041, L1225-1226', note: 'A resolved key whose signature does not verify is an invalid cryptographic check.' },
  { id: 'RC-V05', kind: 'verify', title: 'Another envelope profile', base: 'intent', mutate: { profile: 'aps-receipt-v2' }, resolver: 'correct',
    expect: { status: 'unsupported', signer_authority: 'not_checked', errors: ['unsupported_profile'] },
    lines: 'L1226-1228', note: 'Unsupported is its own answer and is not collapsed into invalid or into valid.' },
]

const CASES: Case[] = [...ENVELOPE, ...STAGE, ...VERIFY]

// -------------------------------------------------------------------------
// Build each record, run the reference, and stop on any disagreement.
// -------------------------------------------------------------------------

const publicKeys: Record<string, string> = {
  [AGENT]: publicKeyFromPrivate(AGENT_KEY),
  [BOUNDARY]: publicKeyFromPrivate(BOUNDARY_KEY),
}

function mint(base: BaseName, mutate: Mutation | undefined): { receipt: Record<string, Json>; signed: boolean } {
  const { signer, key, body } = BASES[base]
  const fields = applyMutation(body as Record<string, Json>, mutate ?? {})
  // A record the draft accepts is minted through the reference issuer, so its
  // receipt_id and signature are the bytes any implementation must reproduce. A record
  // built to be rejected often cannot be signed at all, and is then carried unsigned
  // with the placeholder id: the structural rules under test run before any signature
  // is examined, which is what makes that sound.
  try {
    const receipt = createReceiptV1(fields as never, [{ signer, key_id: `${signer}#key-1`, private_key: key }])
    // The mutation is applied again over the minted record, because the issuer owns two
    // of the members a case may be about: it computes receipt_id and it sorts
    // evidence_refs. Re-applying is a no-op for every other member, whose value is
    // already the mutated one. The structural rules these cases test run before any
    // signature is examined, so a post-minting edit does not weaken them.
    const reapplied = applyMutation(receipt as Record<string, Json>, mutate ?? {})
    // signed means exactly this: the receipt_id and signature value in the record are the
    // reference issuer's own output over this exact body. Re-applying the mutation is a
    // no-op for every case whose members the issuer does not own, and those records keep
    // an intact signature; where it changes something, the signature no longer covers the
    // body and the flag says so.
    const signed = JSON.stringify(reapplied) === JSON.stringify(receipt)
    return { receipt: reapplied, signed }
  } catch {
    const signerId = typeof fields.issuer === 'string' ? fields.issuer : signer
    return {
      receipt: { ...fields, receipt_id: '0'.repeat(64), signatures: [{ signer: signerId, key_id: `${signerId}#key-1`, alg: 'Ed25519', value: '0'.repeat(128) }] },
      signed: false,
    }
  }
}

const out: Json[] = []
for (const testCase of CASES) {
  const { receipt, signed } = mint(testCase.base, (testCase as { mutate?: Mutation }).mutate)

  if (testCase.kind === 'envelope') {
    let accepted = true
    let message = ''
    try { validateReceiptV1(receipt as never) } catch (err) { accepted = false; message = err instanceof Error ? err.message : String(err) }
    if (accepted !== testCase.accepts) {
      fail(`${testCase.id}: expected the envelope validator to ${testCase.accepts ? 'accept' : 'reject'}, got ${accepted ? 'accept' : `reject (${message})`}`)
    }
    if (testCase.accepts && !signed) fail(`${testCase.id}: an accepted case must be mintable through the reference issuer`)
    out.push({
      id: testCase.id, kind: 'envelope', title: testCase.title, expected_provenance: testCase.provenance ?? 'draft-derived',
      derivation: { lines: testCase.lines, note: testCase.note },
      receipt: receipt as Json, signed,
      expected: { accepts: testCase.accepts },
      ts_behaviour: { message: accepted ? null : message },
    })
    continue
  }

  if (testCase.kind === 'stage') {
    const options: Record<string, string> = {}
    if (testCase.context?.expected_receipt_type) options.expectedReceiptType = testCase.context.expected_receipt_type
    if (testCase.context?.boundary_identity) options.boundaryIdentity = testCase.context.boundary_identity
    const actual = validateReceiptStageV1(receipt as never, options as never)
    const codes = (actual.failures as { code: string }[]).map(f => f.code)
    if (actual.status !== testCase.expect.status) fail(`${testCase.id}: expected status ${testCase.expect.status}, got ${actual.status} (${codes.join(',')})`)
    if ((actual.stage ?? null) !== testCase.expect.stage) fail(`${testCase.id}: expected stage ${testCase.expect.stage}, got ${actual.stage}`)
    if (actual.boundary_identity !== testCase.expect.boundary_identity) fail(`${testCase.id}: expected boundary ${testCase.expect.boundary_identity}, got ${actual.boundary_identity}`)
    if (codes.sort().join(',') !== [...testCase.expect.failure_codes].sort().join(',')) {
      fail(`${testCase.id}: expected codes ${testCase.expect.failure_codes.join(',')}, got ${codes.join(',')}`)
    }
    out.push({
      id: testCase.id, kind: 'stage', title: testCase.title, expected_provenance: testCase.provenance ?? 'draft-derived',
      derivation: { lines: testCase.lines, note: testCase.note },
      receipt: receipt as Json, signed,
      context: { expected_receipt_type: testCase.context?.expected_receipt_type ?? null, boundary_identity: testCase.context?.boundary_identity ?? null },
      expected: { status: testCase.expect.status, stage: testCase.expect.stage, boundary_identity: testCase.expect.boundary_identity, sdk_failure_codes: testCase.expect.failure_codes },
    })
    continue
  }

  const resolvers = {
    correct: (signer: string) => publicKeys[signer],
    none: () => undefined,
    raises: () => { throw new Error('resolver unavailable') },
    other_key: () => publicKeyFromPrivate(OTHER_KEY),
  }
  const actual = verifyReceiptV1(receipt as never, resolvers[testCase.resolver] as never)
  if (actual.status !== testCase.expect.status) fail(`${testCase.id}: expected status ${testCase.expect.status}, got ${actual.status} (${actual.errors.join(',')})`)
  if (actual.signer_authority !== testCase.expect.signer_authority) fail(`${testCase.id}: expected signer_authority ${testCase.expect.signer_authority}, got ${actual.signer_authority}`)
  const expectedErrors = [...testCase.expect.errors].sort().join(',')
  if ([...actual.errors].sort().join(',') !== expectedErrors) fail(`${testCase.id}: expected errors ${expectedErrors}, got ${actual.errors.join(',')}`)
  out.push({
    id: testCase.id, kind: 'verify', title: testCase.title, expected_provenance: 'draft-derived',
    derivation: { lines: testCase.lines, note: testCase.note },
    receipt: receipt as Json, signed,
    resolver: testCase.resolver,
    public_keys: publicKeys as unknown as Json,
    other_public_key: publicKeyFromPrivate(OTHER_KEY),
    expected: { status: testCase.expect.status, signer_authority: testCase.expect.signer_authority, sdk_errors: testCase.expect.errors },
  })
}

const counts = {
  total: out.length,
  by_kind: {
    envelope: ENVELOPE.length,
    stage: STAGE.length,
    verify: VERIFY.length,
  },
  by_provenance: {
    'draft-derived': out.filter(c => (c as { expected_provenance: string }).expected_provenance === 'draft-derived').length,
    'ruling-derived': out.filter(c => (c as { expected_provenance: string }).expected_provenance === 'ruling-derived').length,
  },
}

const document = {
  description: 'Cross-implementation vectors for the ReceiptV1 envelope and the section 5.3 stage rules of draft-pidlisnyi-aps-03 (sections 5.1, 5.2, 5.3 and 5.6). Every expected acceptance, rejection and state is fixed in the generator from the draft text or from RFC 3339, cited per case in its derivation, and the generator exits without writing this file if the TypeScript reference disagrees with one of them. sdk_failure_codes and sdk_errors are this SDK pair own vocabulary, which the draft does not name: the draft fixes the state, not the code string, and the Python port sharing these strings is SDK parity rather than a protocol claim. A case whose signed flag is true carries a receipt_id and a signature value that are the output of the TypeScript reference issuer over that exact body, so they are bytes another implementation must reproduce. A case whose flag is false carries either an all-zero placeholder, because the record is one the issuer refuses to mint at all, or a signature that no longer covers the body because the case edits a member the issuer owns; either way the structural rule under test runs before any signature is examined, which is what makes those cases sound. This file is not "TS verified" and no case in it should be described that way.',
  draft: 'draft-pidlisnyi-aps-03 sections 5.1, 5.2, 5.3 and 5.6',
  generated_from: { repository: 'agent-passport-system', commit: tsCommit },
  provenance_definitions: {
    'draft-derived': 'the expected acceptance, rejection or state follows from the draft text, with RFC 3339 where cited; TypeScript output was not consulted to decide it.',
    'ruling-derived': 'the draft names the case but does not fix its outcome, and the expected outcome comes from a ruling recorded by the principal for this programme. The case derivation says which question it answers. These are the cases a later revision of the draft would have to state in normative text for the expectation to become draft-derived.',
  },
  keys: {
    note: 'Deterministic test keys. The private keys are the byte patterns below, which are test values and never key material for anything real.',
    agent: { id: AGENT, private_key: AGENT_KEY, public_key: publicKeys[AGENT] },
    boundary: { id: BOUNDARY, private_key: BOUNDARY_KEY, public_key: publicKeys[BOUNDARY] },
    other: { private_key: OTHER_KEY, public_key: publicKeyFromPrivate(OTHER_KEY) },
  },
  conventions: {
    envelope: 'run the envelope validator over receipt in its full form, values included, and compare acceptance with expected.accepts. An unsigned fixture carries an all-zero receipt_id and an all-zero signature value, both of which satisfy the hexadecimal forms, so the case turns on the member under test.',
    stage: 'run the stage validator over receipt with the context expected_receipt_type and boundary_identity when they are not null, and compare status, stage, boundary_identity and the failure code set.',
    verify: 'run the receipt verifier with a key resolver of the named kind: correct returns the public key for the signer, none returns nothing, raises throws, other_key returns the unrelated public key. Compare status, signer_authority and the error set.',
  },
  withheld: [
    'delegation_ref for an authority basis with no delegation: section 5.1 line 983 names the case and section 5 gives it no encoding anywhere. Only the "sha256:" form of a delegation_id is exercised here, and the binding of that value to a leaf is the section 5.6 composition point, which needs a chain and is not a single-record rule.',
    'Recomputation of action_ref from an independently supplied action, recomputation of decision_ref from its components, and resolution of prev against the record it names: all three are section 5.6 composition points rather than stage rules, and a single-record vector cannot carry the second artifact.',
    'The approval obligations of lines 1093 to 1099, which are enforcement-boundary state: expiry, atomic consumption of receipt_id, rechecking time and revocation, and completing the spend reservation.',
    'Evidence resolution under section 5.5, implemented nowhere in either SDK.',
  ],
  counts,
  cases: out,
}

writeFileSync(outPath, `${JSON.stringify(document, null, 2)}\n`)
console.log(`wrote ${out.length} cases to ${outPath}`)
