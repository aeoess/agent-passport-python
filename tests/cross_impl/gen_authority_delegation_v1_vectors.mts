// Generator for the AuthorityDelegationV1 cross-implementation vector file
// (tests/cross_impl/authority-delegation-v1-vectors.json).
//
// The expected result of every case is fixed in this script, next to the
// draft lines (draft-pidlisnyi-aps-03 sections 3.1, 3.2, 3.3, 3.4 and 3.6),
// RFC 3339 or RFC 7493 citation it rests on, which is copied into the
// case's derivation. This script does not decide any of those; it builds
// the exact records and contexts each case's fixed expectation describes,
// calls the TypeScript reference implementation, and fills in bytes
// (delegation_id, signature, public keys) and TypeScript's own behaviour
// (state, failure codes, index, accept/reject, issue/refuse, budget ledger
// results) by calling that reference directly. If the TS reference
// disagrees with a fixed expectation, the script prints
// "STOP: <case id>: expected ... got ..." and exits 1 without writing the
// output file, instead of silently recording whatever TS produced or
// changing the expectation to match TypeScript. The STOP rule has
// exceptions: AD-I07 to AD-I10 and AD-I15 to AD-I16 carry inputs the
// TypeScript issuer cannot take (no revocation input, no key resolver, no
// now); for those, TypeScript's actual behaviour is recorded without
// stopping and the fixed expectation is left unchanged.
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
//   npx tsx tests/cross_impl/gen_authority_delegation_v1_vectors.mts <output.json>

import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
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

const adUrl = new URL('src/v2/authority-delegation/index.ts', `file://${tsRepo}/`).href
const keysUrl = new URL('src/crypto/keys.ts', `file://${tsRepo}/`).href

const AD = (await import(adUrl)) as {
  issueAuthorityDelegation: (body: any, key: string) => any
  issueSubAuthorityDelegation: (parent: any, body: any, key: string) => any
  verifyAuthorityDelegationChain: (chain: readonly unknown[], options: any) => any
  parseAuthorityDelegationJson: (source: string) => any
  computeAuthorityDelegationId: (body: any) => string
  signAuthorityDelegation: (delegation: any, key: string) => string
  InMemoryAuthorityBudgetLedger: new () => {
    reserve: (chain: readonly any[], actionRef: string, unit: string, amount: string) => any
    markDispatched: (actionRef: string) => any
    commit: (actionRef: string) => any
    cancel: (actionRef: string) => any
    counter: (delegationId: string) => { reserved: string; committed: string }
  }
}
const { sign, publicKeyFromPrivate } = (await import(keysUrl)) as {
  sign: (message: string, privateKeyHex: string) => string
  publicKeyFromPrivate: (privateKeyHex: string) => string
}
void sign // imported for parity with the TS API surface; signing goes through AD.signAuthorityDelegation

// -------------------------------------------------------------------------
// Keys: the five labels and their seeds, DIDs and verification methods
// -------------------------------------------------------------------------

const LABELS = ['principal', 'agent-a', 'agent-b', 'agent-c', 'outsider'] as const
type Label = (typeof LABELS)[number]

const DID: Record<Label, string> = {
  principal: 'did:example:principal',
  'agent-a': 'did:example:agent-a',
  'agent-b': 'did:example:agent-b',
  'agent-c': 'did:example:agent-c',
  outsider: 'did:example:outsider',
}
const VM: Record<Label, string> = {
  principal: 'did:example:principal#key-1',
  'agent-a': 'did:example:agent-a#key-1',
  'agent-b': 'did:example:agent-b#key-1',
  'agent-c': 'did:example:agent-c#key-1',
  outsider: 'did:example:outsider#key-1',
}

function seedHex(label: Label): string {
  return createHash('sha256').update('aps-authority-delegation-v1-vectors:' + label, 'ascii').digest('hex')
}

const keysInfo = LABELS.map((label) => ({
  label,
  seed_hex: seedHex(label),
  public_key_hex: publicKeyFromPrivate(seedHex(label)),
  did: DID[label],
  verification_method: VM[label],
}))

interface KeyEntry { issuer: string; verification_method: string; public_key_hex: string }

const ALL_KEY_ENTRIES: KeyEntry[] = keysInfo.map((k) => ({
  issuer: k.did,
  verification_method: k.verification_method,
  public_key_hex: k.public_key_hex,
}))

function keysWithout(label: Label): KeyEntry[] {
  return ALL_KEY_ENTRIES.filter((e) => e.issuer !== DID[label])
}

// -------------------------------------------------------------------------
// Generic helpers
// -------------------------------------------------------------------------

function clone<T>(value: T): T {
  return structuredClone(value)
}

function mutate<T>(base: T, fn: (draft: T) => void): T {
  const draft = clone(base)
  fn(draft)
  return draft
}

/** "Signed by L": delegation_id = computeAuthorityDelegationId(body), then
 *  signature = signAuthorityDelegation({...body, delegation_id}, seed(L)).
 *  Used uniformly for every record this generator builds, valid or
 *  deliberately invalid: it bypasses issueAuthorityDelegation's own shape
 *  assertion (which would throw for a deliberately malformed body), and for
 *  a schema-valid body it produces byte-identical output to
 *  issueAuthorityDelegation(body, seed(L)) (verified against the TS
 *  reference before this file was written: both go through the same
 *  computeAuthorityDelegationId + signAuthorityDelegation primitives, and no
 *  vector in this file carries an integer-valued number outside the safe
 *  range, which is the only documented behavioural difference between the
 *  "ForWrite" and unrestricted canonicalizers). */
function forceSign(body: any, label: Label): any {
  const delegation_id = AD.computeAuthorityDelegationId(body)
  const unsigned = { ...body, delegation_id }
  return { ...unsigned, signature: AD.signAuthorityDelegation(unsigned, seedHex(label)) }
}

/** Same recipe, but with an explicit (possibly stale) delegation_id instead
 *  of the one computed from `body`. Used only where the case says to keep a
 *  stale id. */
function forceSignWithId(body: any, delegationId: string, label: Label): any {
  const unsigned = { ...body, delegation_id: delegationId }
  return { ...unsigned, signature: AD.signAuthorityDelegation(unsigned, seedHex(label)) }
}

/** issueAuthorityDelegation(body, seed(label)): used for the base valid
 *  records (R, C1, C2) and their valid variants, per the spec's explicit
 *  instruction to use this TS entry point for valid records. */
function issue(body: any, label: Label): any {
  return AD.issueAuthorityDelegation(body, seedHex(label))
}

/** AD-N-S13 only: the mutated body cannot be canonicalized (a lone
 *  surrogate). Per the spec, its delegation_id becomes "sha256:" + 64
 *  zeros and its signature 128 zeros. Confirms the throw actually happens;
 *  STOPs if it does not, since that would mean this generator's
 *  understanding of the construction is wrong, not that TS disagrees with
 *  an expectation. */
function forceSignExpectingCanonicalizationFailure(body: any, label: Label, caseId: string): any {
  try {
    AD.computeAuthorityDelegationId(body)
  } catch {
    return { ...body, delegation_id: `sha256:${'0'.repeat(64)}`, signature: '0'.repeat(128) }
  }
  fail(`${caseId}: expected computeAuthorityDelegationId to throw on a lone surrogate, but it did not`)
}

function flipLastHexChar(hex: string): string {
  const last = hex[hex.length - 1]
  const replacement = last === 'f' ? 'e' : 'f'
  return hex.slice(0, -1) + replacement
}

function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true
  if (typeof a !== typeof b) return false
  if (a === null || b === null) return a === b
  if (typeof a !== 'object') return false
  if (Array.isArray(a) !== Array.isArray(b)) return false
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return false
    return a.every((item, i) => deepEqual(item, b[i]))
  }
  const aObj = a as Record<string, unknown>
  const bObj = b as Record<string, unknown>
  const aKeys = Object.keys(aObj).sort()
  const bKeys = Object.keys(bObj).sort()
  if (aKeys.length !== bKeys.length) return false
  return aKeys.every((key, i) => key === bKeys[i] && deepEqual(aObj[key], bObj[key]))
}

// -------------------------------------------------------------------------
// Output accumulation
// -------------------------------------------------------------------------

interface CaseOut {
  id: string
  kind: 'chain' | 'wire' | 'issue_root' | 'issue_child' | 'budget'
  title: string
  expected_provenance: 'draft-derived' | 'ts-conformant-regression'
  derivation: { lines: string; note: string }
  [key: string]: unknown
}

const cases: CaseOut[] = []
const counts = {
  total: 0,
  by_kind: { chain: 0, wire: 0, issue_root: 0, issue_child: 0, budget: 0 } as Record<string, number>,
  by_provenance: { 'draft-derived': 0, 'ts-conformant-regression': 0 } as Record<string, number>,
}

function record(kind: CaseOut['kind'], provenance: CaseOut['expected_provenance']): void {
  counts.total++
  counts.by_kind[kind]++
  counts.by_provenance[provenance]++
}

// -------------------------------------------------------------------------
// Chain-case context conventions: the key resolver, trust policy and revocation resolver a chain case carries
// -------------------------------------------------------------------------

type RevocationValue = 'active' | 'revoked' | 'unknown' | 'unavailable'
interface TrustSpec {
  mode: 'table' | 'unavailable'
  trusted_root_ids?: string[]
}
interface RevocationSpec {
  default: RevocationValue
  by_index?: Record<string, RevocationValue>
}
interface ContextSpec {
  now: string
  keys: KeyEntry[]
  trust: TrustSpec
  revocation: RevocationSpec
}

const DEFAULT_NOW = '2026-07-18T23:00:00.000Z'

function defaultContext(chain: any[]): ContextSpec {
  return {
    now: DEFAULT_NOW,
    keys: ALL_KEY_ENTRIES,
    trust: { mode: 'table', trusted_root_ids: chain.length > 0 ? [chain[0].delegation_id] : [] },
    revocation: { default: 'active' },
  }
}

function buildOptions(spec: ContextSpec, chain: any[]) {
  const resolveVerificationKey = (issuer: string, vm: string): string | null => {
    const hit = spec.keys.find((k) => k.issuer === issuer && k.verification_method === vm)
    return hit ? hit.public_key_hex : null
  }
  const trustRoot =
    spec.trust.mode === 'table'
      ? (root: any) => (spec.trust.trusted_root_ids ?? []).includes(root.delegation_id)
      : () => {
          throw new Error('trust policy unavailable')
        }
  const resolveRevocation = (delegation: any): RevocationValue => {
    const idx = chain.indexOf(delegation)
    const key = String(idx)
    const value = spec.revocation.by_index && key in spec.revocation.by_index ? spec.revocation.by_index[key] : spec.revocation.default
    if (value === 'unavailable') throw new Error('revocation resolver unavailable')
    return value
  }
  return { now: spec.now, resolveVerificationKey, trustRoot, resolveRevocation }
}

// -------------------------------------------------------------------------
// Base bodies and records: R, C1 and C2, and the shared record-construction helpers
// -------------------------------------------------------------------------

const BODY_R = {
  record_type: 'aps:authority-delegation:v1',
  version: '1.0',
  parent_delegation_id: null,
  issuer: 'did:example:principal',
  subject: 'did:example:agent-a',
  verification_method: 'did:example:principal#key-1',
  issued_at: '2026-07-18T22:00:00.000Z',
  nonce: '00112233445566778899aabbccddeeff',
  authority: {
    scope: { profile: 'aps-hierarchical-v1', grants: ['commerce:*', 'travel:book'] },
    spend: { mode: 'bounded', unit: 'iso4217:USD:minor', per_action: '5000', cumulative: '10000' },
    depth: { remaining: 2 },
    time: { not_before: '2026-07-18T22:00:00.000Z', not_after: '2026-07-19T22:00:00.000Z' },
    reputation: { profile: 'aps-score-0-100-v1', ceiling: 80 },
    values: { profile: 'aps-values-identifiers-v1', required: ['F-001', 'F-003'] },
    reversibility: { profile: 'aps-tci-v1', ceiling: 'compensable' },
  },
}

const R = issue(BODY_R, 'principal')

const BODY_C1 = {
  record_type: 'aps:authority-delegation:v1',
  version: '1.0',
  parent_delegation_id: R.delegation_id,
  issuer: 'did:example:agent-a',
  subject: 'did:example:agent-b',
  verification_method: 'did:example:agent-a#key-1',
  issued_at: '2026-07-18T22:10:00.000Z',
  nonce: '102132435465768798a9bacbdcedfe0f',
  authority: {
    scope: { profile: 'aps-hierarchical-v1', grants: ['commerce:checkout'] },
    spend: { mode: 'bounded', unit: 'iso4217:USD:minor', per_action: '2500', cumulative: '5000' },
    depth: { remaining: 1 },
    time: { not_before: '2026-07-18T22:10:00.000Z', not_after: '2026-07-19T12:00:00.000Z' },
    reputation: { profile: 'aps-score-0-100-v1', ceiling: 70 },
    values: { profile: 'aps-values-identifiers-v1', required: ['F-001', 'F-003', 'F-007'] },
    reversibility: { profile: 'aps-tci-v1', ceiling: 'tentative' },
  },
}

const C1 = issue(BODY_C1, 'agent-a')

const BODY_C2 = {
  record_type: 'aps:authority-delegation:v1',
  version: '1.0',
  parent_delegation_id: C1.delegation_id,
  issuer: 'did:example:agent-b',
  subject: 'did:example:agent-c',
  verification_method: 'did:example:agent-b#key-1',
  issued_at: '2026-07-18T22:20:00.000Z',
  nonce: 'fedcba98765432100123456789abcdef',
  authority: {
    scope: { profile: 'aps-hierarchical-v1', grants: ['commerce:checkout'] },
    spend: { mode: 'bounded', unit: 'iso4217:USD:minor', per_action: '1000', cumulative: '2000' },
    depth: { remaining: 0 },
    time: { not_before: '2026-07-18T22:20:00.000Z', not_after: '2026-07-19T06:00:00.000Z' },
    reputation: { profile: 'aps-score-0-100-v1', ceiling: 70 },
    values: { profile: 'aps-values-identifiers-v1', required: ['F-001', 'F-003', 'F-007'] },
    reversibility: { profile: 'aps-tci-v1', ceiling: 'tentative' },
  },
}

const C2 = issue(BODY_C2, 'agent-b')

const RU = mutate(BODY_R, (b) => { b.authority.spend = { mode: 'unbounded' } })
const RU_REC = issue(RU, 'principal')

// -------------------------------------------------------------------------
// Chain-case runner
// -------------------------------------------------------------------------

interface ChainCaseSpec {
  id: string
  title: string
  chain: any[]
  contextOverrides?: Partial<ContextSpec>
  expectedState: 'valid' | 'invalid' | 'indeterminate' | 'unsupported'
  expectedCode?: string
  /** Exact ordered list of codes, for a case whose one root cause trips more than one check (e.g. a
   *  non-I-JSON record under an unsupported profile). Takes precedence over expectedCode when given. */
  expectedCodes?: string[]
  expectedIndex?: number | null
  lines: string
  note: string
}

function pushChainCase(spec: ChainCaseSpec): void {
  const ctxSpec: ContextSpec = { ...defaultContext(spec.chain), ...(spec.contextOverrides ?? {}) }
  const options = buildOptions(ctxSpec, spec.chain)
  const result = AD.verifyAuthorityDelegationChain(spec.chain, options)

  if (result.state !== spec.expectedState) {
    fail(`${spec.id}: expected state ${spec.expectedState}, got ${result.state} (failures: ${JSON.stringify(result.failures)})`)
  }
  let sdk_codes: string[] = []
  let index: number | null = null
  if (spec.expectedState === 'valid') {
    if (result.failures.length !== 0) {
      fail(`${spec.id}: expected valid with no failures, got ${JSON.stringify(result.failures)}`)
    }
  } else {
    if (result.failures.length === 0) fail(`${spec.id}: expected failures for state ${spec.expectedState}, got none`)
    sdk_codes = result.failures.map((f: any) => f.code)
    if (spec.expectedCodes) {
      if (sdk_codes.length !== spec.expectedCodes.length || sdk_codes.some((c, i) => c !== spec.expectedCodes![i])) {
        fail(`${spec.id}: expected codes ${JSON.stringify(spec.expectedCodes)}, got ${JSON.stringify(sdk_codes)}`)
      }
    } else if (!sdk_codes.every((c) => c === spec.expectedCode)) {
      fail(`${spec.id}: expected code ${spec.expectedCode}, got ${JSON.stringify(sdk_codes)}`)
    }
    const indices = result.failures.map((f: any) => (typeof f.index === 'number' ? f.index : null))
    index = indices[0]
    if (!indices.every((i: number | null) => i === index)) {
      fail(`${spec.id}: mixed failure indices ${JSON.stringify(indices)}`)
    }
    if (index !== (spec.expectedIndex ?? null)) {
      fail(`${spec.id}: expected index ${spec.expectedIndex ?? null}, got ${index}`)
    }
  }

  record('chain', 'draft-derived')
  cases.push({
    id: spec.id,
    kind: 'chain',
    title: spec.title,
    expected_provenance: 'draft-derived',
    derivation: { lines: spec.lines, note: spec.note },
    chain: spec.chain,
    context: ctxSpec,
    expected: { state: result.state, sdk_codes, index },
    ts_behaviour: { state: result.state, codes: sdk_codes, index },
  })
}

// -------------------------------------------------------------------------
// Chain cases, positive
// -------------------------------------------------------------------------

pushChainCase({
  id: 'AD-P01', title: 'Root record alone, valid', chain: [R], expectedState: 'valid',
  lines: 'L424-431, L480-494', note: 'A well-formed, currently valid root record with a trusted policy accepts.',
})

pushChainCase({
  id: 'AD-P02', title: 'Root and one child, valid', chain: [R, C1], expectedState: 'valid',
  lines: 'L511-575, L580-586', note: 'C1 narrows every facet of R and continues the chain correctly.',
})

pushChainCase({
  id: 'AD-P03', title: 'Root, child, grandchild, valid', chain: [R, C1, C2], expectedState: 'valid',
  lines: 'L531-533', note: "C2's depth 0 is C1's depth 1 minus one hop, the minimum required decrement.",
})

{
  const bodyE = mutate(BODY_C1, (b) => {
    b.parent_delegation_id = R.delegation_id
    b.issuer = 'did:example:agent-a'
    b.subject = 'did:example:agent-b'
    b.verification_method = 'did:example:agent-a#key-1'
    b.issued_at = '2026-07-18T22:00:00.000Z'
    b.nonce = '0f1e2d3c4b5a69788796a5b4c3d2e1f0'
    b.authority = clone(BODY_R.authority)
    b.authority.depth = { remaining: 1 }
  })
  const E = issue(bodyE, 'agent-a')
  pushChainCase({
    id: 'AD-P04', title: 'Equal facets narrow only by depth', chain: [R, E], expectedState: 'valid',
    lines: 'L516-566, L532-538',
    note: 'Every comparison admits equality; depth still drops by one hop and issuance at the parent\'s not_before is inside the half-open window.',
  })
}

{
  const c1UnderUnbounded = issue(mutate(BODY_C1, (b) => { b.parent_delegation_id = RU_REC.delegation_id }), 'agent-a')
  pushChainCase({
    id: 'AD-P05', title: 'Unbounded parent, bounded child', chain: [RU_REC, c1UnderUnbounded],
    expectedState: 'valid', lines: 'L527-528', note: 'A bounded child under an unbounded parent has no parent limit to exceed.',
  })
}

{
  const c1Unbounded = mutate(BODY_C1, (b) => {
    b.parent_delegation_id = RU_REC.delegation_id
    b.authority.spend = { mode: 'unbounded' }
  })
  const c1UnboundedRec = issue(c1Unbounded, 'agent-a')
  pushChainCase({
    id: 'AD-P06', title: 'Unbounded parent, unbounded child', chain: [RU_REC, c1UnboundedRec], expectedState: 'valid',
    lines: 'L571-574', note: 'An unbounded child under an unbounded parent is the equal component of the order, not a widening.',
  })
}

{
  const rootStar = issue(mutate(BODY_R, (b) => { b.authority.scope.grants = ['*'] }), 'principal')
  const childP07 = issue(mutate(BODY_C1, (b) => {
    b.parent_delegation_id = rootStar.delegation_id
    b.authority.scope.grants = ['commerce:checkout', 'travel:*']
  }), 'agent-a')
  pushChainCase({
    id: 'AD-P07', title: 'Root scope "*" covers any child scope', chain: [rootStar, childP07], expectedState: 'valid',
    lines: 'L516-517', note: 'The wildcard "*" grant covers every child grant.',
  })
}

{
  const rootCommerceStar = issue(mutate(BODY_R, (b) => { b.authority.scope.grants = ['commerce:*'] }), 'principal')
  const childP08 = issue(mutate(BODY_C1, (b) => {
    b.parent_delegation_id = rootCommerceStar.delegation_id
    b.authority.scope.grants = ['commerce']
  }), 'agent-a')
  pushChainCase({
    id: 'AD-P08', title: '"commerce:*" covers the bare grant "commerce"', chain: [rootCommerceStar, childP08], expectedState: 'valid',
    lines: 'L518-519', note: '"p:*" covers "p".',
  })

  const childP09 = issue(mutate(BODY_C1, (b) => {
    b.parent_delegation_id = rootCommerceStar.delegation_id
    b.authority.scope.grants = ['commerce:*']
  }), 'agent-a')
  pushChainCase({
    id: 'AD-P09', title: '"commerce:*" covers itself', chain: [rootCommerceStar, childP09], expectedState: 'valid',
    lines: 'L518-519', note: 'A grant beginning "commerce:" is covered by the identical wildcard grant.',
  })

  const childP10 = issue(mutate(BODY_C1, (b) => {
    b.parent_delegation_id = rootCommerceStar.delegation_id
    b.authority.scope.grants = ['commerce:checkout:*']
  }), 'agent-a')
  pushChainCase({
    id: 'AD-P10', title: '"commerce:*" covers a longer wildcard descendant', chain: [rootCommerceStar, childP10], expectedState: 'valid',
    lines: 'L518-519', note: '"commerce:checkout:*" is a descendant of "commerce:*".',
  })
}

{
  const childP11 = issue(mutate(BODY_C1, (b) => { b.authority.scope.grants = [] }), 'agent-a')
  pushChainCase({
    id: 'AD-P11', title: 'Empty child scope is vacuously covered', chain: [R, childP11], expectedState: 'valid',
    lines: 'L519-521', note: 'An empty grants array is vacuously covered, and is itself sorted, unique and irredundant.',
  })
}

{
  const rootSpendBounds = issue(mutate(BODY_R, (b) => {
    b.authority.spend = { mode: 'bounded', unit: 'iso4217:USD:minor', per_action: '0', cumulative: '9223372036854775807' }
  }), 'principal')
  const childSpendBounds = issue(mutate(BODY_C1, (b) => {
    b.parent_delegation_id = rootSpendBounds.delegation_id
    b.authority.spend = { mode: 'bounded', unit: 'iso4217:USD:minor', per_action: '0', cumulative: '0' }
  }), 'agent-a')
  pushChainCase({
    id: 'AD-P12', title: 'Spend bounds at the extremes', chain: [rootSpendBounds, childSpendBounds], expectedState: 'valid',
    lines: 'L524-527', note: 'Zero and the maximum canonical quantity are both admissible bounds that narrow correctly.',
  })
}

{
  const rootDepth255 = issue(mutate(BODY_R, (b) => { b.authority.depth = { remaining: 255 } }), 'principal')
  const childDepth254 = issue(mutate(BODY_C1, (b) => {
    b.parent_delegation_id = rootDepth255.delegation_id
    b.authority.depth = { remaining: 254 }
  }), 'agent-a')
  pushChainCase({
    id: 'AD-P13', title: 'Depth bounds at the extremes', chain: [rootDepth255, childDepth254], expectedState: 'valid',
    lines: 'L531-533', note: 'Depth 255 down to 254 consumes exactly one hop at the top of the range.',
  })
}

{
  const rootRep100 = issue(mutate(BODY_R, (b) => { b.authority.reputation = { profile: 'aps-score-0-100-v1', ceiling: 100 } }), 'principal')
  const childRep0 = issue(mutate(BODY_C1, (b) => {
    b.parent_delegation_id = rootRep100.delegation_id
    b.authority.reputation = { profile: 'aps-score-0-100-v1', ceiling: 0 }
  }), 'agent-a')
  pushChainCase({
    id: 'AD-P14', title: 'Reputation bounds at the extremes', chain: [rootRep100, childRep0], expectedState: 'valid',
    lines: 'L541-542', note: 'Reputation ceiling 100 down to 0 still narrows.',
  })
}

{
  const rootIrrev = issue(mutate(BODY_R, (b) => { b.authority.reversibility = { profile: 'aps-tci-v1', ceiling: 'irreversible' } }), 'principal')
  const childComp = issue(mutate(BODY_C1, (b) => {
    b.parent_delegation_id = rootIrrev.delegation_id
    b.authority.reversibility = { profile: 'aps-tci-v1', ceiling: 'compensable' }
  }), 'agent-a')
  const grandchildTent = issue(mutate(BODY_C2, (b) => {
    b.parent_delegation_id = childComp.delegation_id
    b.authority.reversibility = { profile: 'aps-tci-v1', ceiling: 'tentative' }
  }), 'agent-b')
  pushChainCase({
    id: 'AD-P15', title: 'Reversibility ladder narrows down', chain: [rootIrrev, childComp, grandchildTent], expectedState: 'valid',
    lines: 'L553-566', note: 'irreversible -> compensable -> tentative is monotonically non-increasing on the three-class ladder.',
  })
}

{
  const RL = issue(mutate(BODY_R, (b) => {
    b.issued_at = '2016-12-31T23:59:59.000Z'
    b.authority.time = { not_before: '2016-12-31T23:59:59.000Z', not_after: '2017-01-01T00:00:01.000Z' }
  }), 'principal')
  const CL = issue(mutate(BODY_C1, (b) => {
    b.parent_delegation_id = RL.delegation_id
    b.issued_at = '2016-12-31T23:59:60.000Z'
    b.authority.time = { not_before: '2016-12-31T23:59:60.000Z', not_after: '2017-01-01T00:00:00.500Z' }
  }), 'agent-a')
  pushChainCase({
    id: 'AD-P16', title: 'Leap second is lexically admissible', chain: [RL, CL],
    contextOverrides: { now: '2016-12-31T23:59:60.500Z' }, expectedState: 'valid',
    lines: 'L796-797 and L480-481 (RFC 3339 timestamps), RFC 3339 sections 5.1 and 5.6',
    note: '2016-12-31T23:59:60Z was an actual leap second, which RFC 3339 sections 5.6 and 5.7 admit; same-format timestamps sort as strings into time order (RFC 3339 section 5.1).',
  })
}

{
  const R0000 = issue(mutate(BODY_R, (b) => {
    b.issued_at = '0000-01-01T00:00:00.000Z'
    b.authority.time = { not_before: '0000-01-01T00:00:00.000Z', not_after: '0000-12-31T23:59:59.999Z' }
  }), 'principal')
  pushChainCase({
    id: 'AD-P17', title: 'Year 0000, including its leap day', chain: [R0000],
    contextOverrides: { now: '0000-02-29T12:00:00.000Z' }, expectedState: 'valid',
    lines: 'L480-481, L198-199, RFC 3339 section 5.6',
    note: 'date-fullyear = 4DIGIT and the proleptic Gregorian leap-year rule make year 0000 (and its February 29) valid; no draft text excludes it.',
  })
}

pushChainCase({
  id: 'AD-P18', title: 'now equal to not_before (start inclusive)', chain: [R],
  contextOverrides: { now: '2026-07-18T22:00:00.000Z' }, expectedState: 'valid',
  lines: 'L535', note: 'The half-open validity window includes its start instant.',
})

pushChainCase({
  id: 'AD-P19', title: 'now one millisecond before not_after', chain: [R],
  contextOverrides: { now: '2026-07-19T21:59:59.999Z' }, expectedState: 'valid',
  lines: 'L535', note: 'The half-open validity window excludes its end instant, so the millisecond before it is still valid.',
})

{
  const c1LastMs = issue(mutate(BODY_C1, (b) => {
    b.issued_at = '2026-07-19T21:59:59.999Z'
    b.authority.time = { not_before: '2026-07-19T21:59:59.999Z', not_after: '2026-07-19T22:00:00.000Z' }
  }), 'agent-a')
  pushChainCase({
    id: 'AD-P20', title: "Child issued in the parent's last millisecond", chain: [R, c1LastMs],
    contextOverrides: { now: '2026-07-19T21:59:59.999Z' }, expectedState: 'valid',
    lines: 'L535-538', note: "The child is issued and currently valid one millisecond before the parent's expiry, inside the half-open window.",
  })
}

// -------------------------------------------------------------------------
// Chain cases, negative: closed schema and canonical values
// -------------------------------------------------------------------------

function rootOnlyInvalid(id: string, title: string, lines: string, note: string, code: string, fn: (b: any) => void, state: 'invalid' | 'unsupported' = 'invalid'): void {
  const body = mutate(BODY_R, fn)
  pushChainCase({ id, title, chain: [forceSign(body, 'principal')], expectedState: state, expectedCode: code, expectedIndex: 0, lines, note })
}

rootOnlyInvalid('AD-N-S01', 'Extra top-level member', 'L480', 'The v1 schema is closed; an unknown member is rejected.', 'SCHEMA_INVALID', (b) => { b.comment = 'x' })
rootOnlyInvalid('AD-N-S02', 'Missing nonce', 'L426-427', 'nonce is a required member.', 'SCHEMA_INVALID', (b) => { delete b.nonce })
rootOnlyInvalid('AD-N-S03', 'authority missing the values facet', 'L429-431', 'authority must carry exactly all seven facets.', 'SCHEMA_INVALID', (b) => { delete b.authority.values })
rootOnlyInvalid('AD-N-S04', 'An eighth authority facet', 'L429-430', 'authority carries exactly seven facets, not eight.', 'SCHEMA_INVALID', (b) => { b.authority.risk = { profile: 'x', ceiling: 1 } })
rootOnlyInvalid('AD-N-S05', 'depth with an extra member', 'L480', 'depth is a closed object of exactly {remaining}.', 'SCHEMA_INVALID', (b) => { b.authority.depth = { remaining: 2, max: 3 } })
rootOnlyInvalid('AD-N-S06', 'Unsupported record_type v2', 'L424-426, L590, L1227', 'The draft states no rule for an unknown record_type; by analogy with L590 and L1227, an unimplemented construct is unsupported, not invalid.', 'UNSUPPORTED_VERSION', (b) => { b.record_type = 'aps:authority-delegation:v2' }, 'unsupported')
rootOnlyInvalid('AD-N-S07', 'Unsupported version 2.0', 'L426', 'The draft states no rule for an unknown version; by analogy with L590 and L1227, an unimplemented construct is unsupported, not invalid.', 'UNSUPPORTED_VERSION', (b) => { b.version = '2.0' }, 'unsupported')

{
  const body = clone(BODY_R)
  const correctId = AD.computeAuthorityDelegationId(body)
  const upperId = 'sha256:' + correctId.slice(7).toUpperCase()
  pushChainCase({
    id: 'AD-N-S08', title: 'delegation_id hex uppercased', chain: [forceSignWithId(body, upperId, 'principal')],
    expectedState: 'invalid', expectedCode: 'SCHEMA_INVALID', expectedIndex: 0,
    lines: 'L456, L484', note: 'delegation_id must be sha256: followed by 64 lowercase hex characters; the signature is computed over the record as written, with the uppercased id.',
  })
}
{
  const body = clone(BODY_R)
  const correctId = AD.computeAuthorityDelegationId(body)
  const noPrefix = correctId.slice(7)
  pushChainCase({
    id: 'AD-N-S09', title: 'delegation_id without the sha256: prefix', chain: [forceSignWithId(body, noPrefix, 'principal')],
    expectedState: 'invalid', expectedCode: 'SCHEMA_INVALID', expectedIndex: 0,
    lines: 'L484', note: 'delegation_id must carry the sha256: prefix.',
  })
}
{
  const badParent = 'sha256:' + 'a'.repeat(63)
  const c1bad = forceSign(mutate(BODY_C1, (b) => { b.parent_delegation_id = badParent }), 'agent-a')
  pushChainCase({
    id: 'AD-N-S10', title: 'parent_delegation_id one hex character short', chain: [R, c1bad],
    expectedState: 'invalid', expectedCode: 'SCHEMA_INVALID', expectedIndex: 1,
    lines: 'L428, L456', note: 'parent_delegation_id must be null or a well-formed delegation digest; no re-link, the malformed value is the fault under test.',
  })
}
rootOnlyInvalid('AD-N-S11', 'issuer is a number', 'L426-427, L204', 'issuer must be an I-JSON string.', 'SCHEMA_INVALID', (b) => { b.issuer = 5 })
rootOnlyInvalid('AD-N-S12', 'issuer is an array', 'L426-427', 'issuer must be a string, not an array.', 'SCHEMA_INVALID', (b) => { b.issuer = ['did:example:principal'] })
{
  const body = mutate(BODY_R, (b) => { b.subject = 'did:example:agent-a\uD800' })
  const rec = forceSignExpectingCanonicalizationFailure(body, 'principal', 'AD-N-S13')
  pushChainCase({
    id: 'AD-N-S13', title: 'subject carries a lone surrogate', chain: [rec],
    expectedState: 'invalid', expectedCode: 'SCHEMA_INVALID', expectedIndex: 0,
    lines: 'L204', note: 'RFC 7493 section 2.1 forbids unpaired surrogates; JCS over validated I-JSON cannot canonicalize this record, so its delegation_id and signature are the all-zero placeholder rather than computed bytes.',
  })
}
rootOnlyInvalid('AD-N-S14', 'issued_at without milliseconds', 'L480-481, L198-199', 'issued_at must be exact UTC-millisecond form.', 'NONCANONICAL_VALUE', (b) => { b.issued_at = '2026-07-18T22:00:00Z' })
rootOnlyInvalid('AD-N-S15', 'issued_at with a numeric offset', 'L480-481, L198-199', 'issued_at must use the Z designator, not a numeric offset.', 'NONCANONICAL_VALUE', (b) => { b.issued_at = '2026-07-18T22:00:00.000+00:00' })
rootOnlyInvalid('AD-N-S16', 'issued_at on June 31 (June has 30 days)', 'RFC 3339 section 5.7', 'June has only 30 days.', 'NONCANONICAL_VALUE', (b) => { b.issued_at = '2026-06-31T22:00:00.000Z' })
rootOnlyInvalid('AD-N-S17', 'issued_at hour 24', 'RFC 3339 section 5.6', 'time-hour is 00-23.', 'NONCANONICAL_VALUE', (b) => { b.issued_at = '2026-07-17T24:00:00.000Z' })
rootOnlyInvalid('AD-N-S18', 'issued_at second 61', 'RFC 3339 section 5.6', 'time-second is 00-60.', 'NONCANONICAL_VALUE', (b) => { b.issued_at = '2026-07-17T23:59:61.000Z' })
rootOnlyInvalid('AD-N-S19', 'issued_at wrapped in an array', 'L480-481', 'issued_at must be a string, not an array.', 'NONCANONICAL_VALUE', (b) => { b.issued_at = ['2026-07-18T22:00:00.000Z'] })
rootOnlyInvalid('AD-N-S20', 'nonce uppercased', 'L462, L481', 'nonce must be 32 lowercase hex characters.', 'NONCANONICAL_VALUE', (b) => { b.nonce = '00112233445566778899AABBCCDDEEFF' })
rootOnlyInvalid('AD-N-S21', 'nonce one byte short', 'L462, L481', 'nonce must be exactly 32 hex characters.', 'NONCANONICAL_VALUE', (b) => { b.nonce = '00112233445566778899aabbccddee' })
{
  const rec = forceSign(clone(BODY_R), 'principal')
  pushChainCase({
    id: 'AD-N-S22', title: 'signature hex uppercased', chain: [{ ...rec, signature: rec.signature.toUpperCase() }],
    expectedState: 'invalid', expectedCode: 'SCHEMA_INVALID', expectedIndex: 0,
    lines: 'L477', note: 'signature must be 128 lowercase hex characters.',
  })
}
rootOnlyInvalid('AD-N-S23', 'scope grants out of UTF-8-byte order', 'L520-521', 'grants must be sorted by UTF-8 bytes; "commerce:*" sorts before "travel:book".', 'NONCANONICAL_VALUE', (b) => { b.authority.scope.grants = ['travel:book', 'commerce:*'] })
rootOnlyInvalid('AD-N-S24', 'Duplicate scope grant', 'L521', 'grants must be unique.', 'NONCANONICAL_VALUE', (b) => { b.authority.scope.grants = ['commerce:*', 'commerce:*'] })
rootOnlyInvalid('AD-N-S25', 'Redundant scope grant under a wildcard', 'L521', '"commerce:*" already covers "commerce:checkout"; the set must be irredundant.', 'NONCANONICAL_VALUE', (b) => { b.authority.scope.grants = ['commerce:*', 'commerce:checkout'] })
rootOnlyInvalid('AD-N-S26', 'Non-ASCII scope segment', 'L516', 'Scope segments are ASCII only.', 'NONCANONICAL_VALUE', (b) => { b.authority.scope.grants = ['commerce:café'] })
rootOnlyInvalid('AD-N-S27', 'Wildcard not in terminal position', 'L517-518', 'A wildcard is only admissible as the terminal segment.', 'NONCANONICAL_VALUE', (b) => { b.authority.scope.grants = ['commerce:*:refund'] })
rootOnlyInvalid('AD-N-S28', 'Wildcard as a leading segment', 'L517-518', 'A wildcard is only admissible as the terminal segment.', 'NONCANONICAL_VALUE', (b) => { b.authority.scope.grants = ['*:commerce'] })
rootOnlyInvalid('AD-N-S29', 'Redundant grant under the bare wildcard', 'L516-517, L521', '"*" covers all, so any other grant alongside it is redundant.', 'NONCANONICAL_VALUE', (b) => { b.authority.scope.grants = ['*', 'commerce:*'] })
rootOnlyInvalid('AD-N-S30', 'Unknown spend mode', 'L523-524', 'spend.mode must be "bounded" or "unbounded".', 'SCHEMA_INVALID', (b) => { b.authority.spend = { mode: 'capped', unit: 'iso4217:USD:minor', per_action: '5000', cumulative: '10000' } })
rootOnlyInvalid('AD-N-S31', 'Bounded spend without a unit', 'L523-524', 'Bounded spend requires unit, per_action and cumulative.', 'NONCANONICAL_VALUE', (b) => { b.authority.spend = { mode: 'bounded', per_action: '5000', cumulative: '10000' } })
rootOnlyInvalid('AD-N-S32', 'per_action exceeds cumulative', 'L525-526', 'per_action cannot exceed cumulative.', 'SCHEMA_INVALID', (b) => { b.authority.spend = { mode: 'bounded', unit: 'iso4217:USD:minor', per_action: '10001', cumulative: '10000' } })
rootOnlyInvalid('AD-N-S33', 'Spend quantity with a leading zero', 'L524-525', 'A canonical quantity has no leading zero.', 'NONCANONICAL_VALUE', (b) => { b.authority.spend.per_action = '05000' })
rootOnlyInvalid('AD-N-S34', 'Spend quantity above the maximum', 'L524-525', 'A canonical quantity is at most 9223372036854775807.', 'NONCANONICAL_VALUE', (b) => { b.authority.spend.cumulative = '9223372036854775808' })
rootOnlyInvalid('AD-N-S35', 'per_action as a JSON number', 'L524-525, RFC 7493 section 2.2', 'Quantities up to the maximum cannot be carried exactly by an I-JSON number; the record example carries strings.', 'NONCANONICAL_VALUE', (b) => { b.authority.spend.per_action = 5000 })
rootOnlyInvalid('AD-N-S36', 'Unbounded spend with an extra field', 'L523', 'Unbounded spend is the closed object {mode}.', 'SCHEMA_INVALID', (b) => { b.authority.spend = { mode: 'unbounded', unit: 'iso4217:USD:minor' } })
rootOnlyInvalid('AD-N-S37', 'Negative spend quantity', 'L524-525', 'A canonical quantity is unsigned.', 'NONCANONICAL_VALUE', (b) => { b.authority.spend.per_action = '-1' })
rootOnlyInvalid('AD-N-S38', 'depth.remaining above the maximum', 'L531', 'depth.remaining is an integer from 0 through 255.', 'SCHEMA_INVALID', (b) => { b.authority.depth.remaining = 256 })
rootOnlyInvalid('AD-N-S39', 'depth.remaining negative', 'L531', 'depth.remaining is an integer from 0 through 255.', 'SCHEMA_INVALID', (b) => { b.authority.depth.remaining = -1 })
rootOnlyInvalid('AD-N-S40', 'depth.remaining non-integer', 'L531', 'depth.remaining must be an integer.', 'SCHEMA_INVALID', (b) => { b.authority.depth.remaining = 1.5 })
rootOnlyInvalid('AD-N-S41', 'depth.remaining as a string', 'L531', 'depth.remaining must be a JSON number, not a string.', 'SCHEMA_INVALID', (b) => { b.authority.depth.remaining = '2' })
rootOnlyInvalid('AD-N-S42', 'time.not_after without milliseconds', 'L480-481', 'time bounds must be canonical UTC milliseconds.', 'NONCANONICAL_VALUE', (b) => { b.authority.time.not_after = '2026-07-19T22:00:00Z' })
rootOnlyInvalid('AD-N-S43', 'reputation ceiling above the maximum', 'L541', 'reputation.ceiling is an integer from 0 through 100.', 'SCHEMA_INVALID', (b) => { b.authority.reputation.ceiling = 101 })
rootOnlyInvalid('AD-N-S44', 'reputation ceiling non-integer', 'L541', 'reputation.ceiling must be an integer.', 'SCHEMA_INVALID', (b) => { b.authority.reputation.ceiling = 79.5 })
rootOnlyInvalid('AD-N-S45', 'values.required out of order', 'L547', 'values.required must be sorted.', 'NONCANONICAL_VALUE', (b) => { b.authority.values.required = ['F-003', 'F-001'] })
rootOnlyInvalid('AD-N-S46', 'Duplicate values.required entry', 'L547', 'values.required must be unique.', 'NONCANONICAL_VALUE', (b) => { b.authority.values.required = ['F-001', 'F-001'] })
rootOnlyInvalid('AD-N-S47', 'Reversibility ceiling outside the three classes', 'L553-565', 'Only tentative, compensable and irreversible are defined.', 'SCHEMA_INVALID', (b) => { b.authority.reversibility.ceiling = 'reversible' })
rootOnlyInvalid('AD-N-S48', 'Reversibility ceiling as an array', 'L553-565, L480', 'reversibility.ceiling must be a string.', 'SCHEMA_INVALID', (b) => { b.authority.reversibility.ceiling = ['compensable'] })
rootOnlyInvalid('AD-N-S49', 'Scope facet without a profile', 'L512-514, L480', 'The scope facet carries profile and grants (L464-465) in a closed schema (L480); a missing member is invalid.', 'SCHEMA_INVALID', (b) => { b.authority.scope = { grants: ['commerce:*', 'travel:book'] } })
{
  const c1bad = forceSign(mutate(BODY_C1, (b) => { b.authority.time.not_before = '2026-07-18T22:05:00.000Z' }), 'agent-a')
  pushChainCase({
    id: 'AD-N-S51', title: 'not_before predates issued_at', chain: [R, c1bad],
    expectedState: 'invalid', expectedCode: 'SCHEMA_INVALID', expectedIndex: 1,
    lines: 'L536-537', note: "C1's issued_at stays 22:10:00.000Z while not_before moves to 22:05:00.000Z, so not_before predates issued_at.",
  })
}
pushChainCase({
  id: 'AD-N-S52', title: 'The empty chain', chain: [],
  contextOverrides: { trust: { mode: 'table', trusted_root_ids: [] } },
  expectedState: 'invalid', expectedCode: 'SCHEMA_INVALID', expectedIndex: null,
  lines: 'L580, L1655-1660', note: 'A root-to-leaf chain has a root; the empty array is a structurally malformed input with a defined result.',
})
rootOnlyInvalid('AD-N-S53', 'Empty half-open validity window', 'L535, L584', 'not_before equal to not_after makes the half-open window empty, so the record is never currently valid.', 'SCHEMA_INVALID', (b) => { b.authority.time = { not_before: '2026-07-18T22:00:00.000Z', not_after: '2026-07-18T22:00:00.000Z' } })

rootOnlyInvalid('AD-N-S54', 'nonce with a trailing line feed', 'L462, L481', 'nonce must be exactly 32 lowercase hex characters, with nothing appended.', 'NONCANONICAL_VALUE', (b) => { b.nonce = b.nonce + '\n' })

{
  const body = clone(BODY_R)
  const correctId = AD.computeAuthorityDelegationId(body)
  const idWithLineFeed = correctId + '\n'
  pushChainCase({
    id: 'AD-N-S55', title: 'delegation_id with a trailing line feed', chain: [forceSignWithId(body, idWithLineFeed, 'principal')],
    expectedState: 'invalid', expectedCode: 'SCHEMA_INVALID', expectedIndex: 0,
    lines: 'L456, L484', note: 'delegation_id must be exactly sha256: followed by 64 lowercase hex characters; the signature is computed over the record as written, with the trailing line feed.',
  })
}

{
  const rec = forceSign(clone(BODY_R), 'principal')
  pushChainCase({
    id: 'AD-N-S56', title: 'signature with a trailing line feed', chain: [{ ...rec, signature: rec.signature + '\n' }],
    expectedState: 'invalid', expectedCode: 'SCHEMA_INVALID', expectedIndex: 0,
    lines: 'L477', note: 'signature must be exactly 128 lowercase hex characters, with nothing appended.',
  })
}

rootOnlyInvalid('AD-N-S57', 'issued_at with a trailing line feed', 'L198-199, L480-481', 'issued_at must be exactly the canonical UTC-millisecond form, with nothing appended.', 'NONCANONICAL_VALUE', (b) => { b.issued_at = b.issued_at + '\n' })
rootOnlyInvalid('AD-N-S58', 'time.not_before with a trailing line feed', 'L480-481', 'time bounds must be exactly the canonical UTC-millisecond form, with nothing appended.', 'NONCANONICAL_VALUE', (b) => { b.authority.time.not_before = b.authority.time.not_before + '\n' })
rootOnlyInvalid('AD-N-S59', 'spend per_action with a trailing line feed', 'L524-525', 'A canonical unsigned decimal integer has nothing appended to it.', 'NONCANONICAL_VALUE', (b) => { b.authority.spend.per_action = b.authority.spend.per_action + '\n' })

{
  // U+FDD0 is a noncharacter (the start of the U+FDD0..U+FDEF block). Written
  // as an explicit JavaScript escape so this file carries no literal
  // noncharacter code point.
  const body = mutate(BODY_R, (b) => { b.issuer = b.issuer + '\uFDD0' })
  const principalKey = ALL_KEY_ENTRIES.find((k) => k.issuer === DID.principal)!
  const extraKey: KeyEntry = { issuer: `${DID.principal}\uFDD0`, verification_method: principalKey.verification_method, public_key_hex: principalKey.public_key_hex }
  pushChainCase({
    id: 'AD-N-S60', title: 'issuer with a trailing noncharacter (U+FDD0)', chain: [forceSign(body, 'principal')],
    contextOverrides: { keys: [...ALL_KEY_ENTRIES, extraKey] },
    expectedState: 'invalid', expectedCode: 'SCHEMA_INVALID', expectedIndex: 0,
    lines: 'L204 with RFC 7493 section 2.1',
    note: 'Every string in the record must be I-JSON; a key entry for the mutated issuer string is added so the key would resolve, proving the fault is the I-JSON check and not an unresolvable key.',
  })
}

// U+10FFFF is a noncharacter (the last code point of the last plane), written
// with the code-point escape as a surrogate pair internally; a valid
// surrogate pair that decodes to a noncharacter is still rejected.
rootOnlyInvalid('AD-N-S61', 'subject with a trailing noncharacter (U+10FFFF)', 'L204 with RFC 7493 section 2.1', 'Every string in the record must be I-JSON; a valid surrogate pair decoding to a noncharacter is still rejected.', 'SCHEMA_INVALID', (b) => { b.subject = b.subject + '\u{10FFFF}' })

{
  // U+FFFF is a noncharacter (the last code point of the BMP).
  const body = mutate(BODY_R, (b) => { b.authority.scope.profile = 'aps-hierarchical-v2' + '\uFFFF' })
  pushChainCase({
    id: 'AD-N-S62', title: 'Unsupported scope profile with a trailing noncharacter (U+FFFF)', chain: [forceSign(body, 'principal')],
    expectedState: 'invalid', expectedCodes: ['SCHEMA_INVALID', 'UNSUPPORTED_PROFILE'], expectedIndex: 0,
    lines: 'L204 with RFC 7493 section 2.1',
    note: 'The record is not I-JSON, so it cannot be valid whatever its profile; the SDK also reports the unknown profile.',
  })
}

// -------------------------------------------------------------------------
// Chain cases, negative: unsupported facet profiles
// -------------------------------------------------------------------------

function rootOnlyUnsupported(id: string, title: string, note: string, fn: (b: any) => void): void {
  rootOnlyInvalid(id, title, 'L512-514, L590', note, 'UNSUPPORTED_PROFILE', fn, 'unsupported')
}

rootOnlyUnsupported('AD-N-U01', 'Unsupported scope profile', 'An unsupported facet profile is unsupported, not invalid.', (b) => { b.authority.scope.profile = 'aps-hierarchical-v2' })
rootOnlyUnsupported('AD-N-U04', 'Unsupported reputation profile', 'An unsupported facet profile is unsupported, not invalid.', (b) => { b.authority.reputation = { profile: 'aps-score-0-1000-v1', ceiling: 80 } })
rootOnlyUnsupported('AD-N-U06', 'Unsupported values profile', 'An unsupported facet profile is unsupported, not invalid.', (b) => { b.authority.values = { profile: 'aps-values-uri-v1', required: ['F-001', 'F-003'] } })
{
  const c1bad = forceSign(mutate(BODY_C1, (b) => { b.authority.scope.profile = 'aps-hierarchical-v2' }), 'agent-a')
  pushChainCase({
    id: 'AD-N-U08', title: 'Scope profile change between parent and child', chain: [R, c1bad],
    expectedState: 'unsupported', expectedCode: 'UNSUPPORTED_PROFILE', expectedIndex: 1,
    lines: 'L512-514, L590', note: "C1's own scope profile is unsupported at the shape level, independent of the parent/child comparison.",
  })
}

// -------------------------------------------------------------------------
// Chain cases, negative: signature, identifier and key resolution
// -------------------------------------------------------------------------

{
  const staleId = R.delegation_id
  const mutated = mutate(BODY_R, (b) => { b.subject = 'did:example:agent-z' })
  const rec = forceSignWithId(mutated, staleId, 'principal')
  pushChainCase({
    id: 'AD-N-C01', title: 'Subject changed after delegation_id was computed, stale id kept', chain: [rec],
    expectedState: 'invalid', expectedCode: 'ID_MISMATCH', expectedIndex: 0,
    lines: 'L484-486, L581', note: 'The stale delegation_id no longer matches the mutated body; the signature is recomputed over the record as written.',
  })
}
{
  const staleId = C1.delegation_id
  const mutated = mutate(BODY_C1, (b) => { b.nonce = '00000000000000000000000000000001' })
  const rec = forceSignWithId(mutated, staleId, 'agent-a')
  pushChainCase({
    id: 'AD-N-C02', title: 'Nonce changed after delegation_id was computed, stale id kept', chain: [R, rec],
    expectedState: 'invalid', expectedCode: 'ID_MISMATCH', expectedIndex: 1,
    lines: 'L484-486, L581', note: 'Same construction as AD-N-C01, one level deeper in the chain.',
  })
}
{
  const rec = forceSign(clone(BODY_R), 'principal')
  const corrupted = { ...rec, signature: flipLastHexChar(rec.signature) }
  pushChainCase({
    id: 'AD-N-C03', title: 'Last hex character of the signature flipped', chain: [corrupted],
    expectedState: 'invalid', expectedCode: 'SIGNATURE_INVALID', expectedIndex: 0,
    lines: 'L488-490, L581, L591', note: 'A single flipped hex character invalidates the Ed25519 signature.',
  })
}
{
  const unsigned = { ...BODY_R, delegation_id: R.delegation_id }
  const rec = { ...unsigned, signature: AD.signAuthorityDelegation(unsigned, seedHex('agent-a')) }
  pushChainCase({
    id: 'AD-N-C04', title: 'Signed with the wrong key', chain: [rec],
    expectedState: 'invalid', expectedCode: 'SIGNATURE_INVALID', expectedIndex: 0,
    lines: 'L488-490, L591', note: "verification_method still names did:example:principal#key-1, but the bytes were signed with agent-a's key.",
  })
}
pushChainCase({
  id: 'AD-N-C05', title: 'Key resolver missing the root issuer', chain: [R],
  contextOverrides: { keys: keysWithout('principal') },
  expectedState: 'indeterminate', expectedCode: 'KEY_RESOLUTION_FAILED', expectedIndex: 0,
  lines: 'L492, L321-323, L589-590', note: 'By analogy with L321-323 (without key-authority evidence the result is indeterminate) and L589-590, the state is indeterminate, not invalid; finer resolution-outcome structure (L360-369) is an open question and not tested here.',
})
pushChainCase({
  id: 'AD-N-C06', title: 'Key resolver missing the child issuer', chain: [R, C1],
  contextOverrides: { keys: keysWithout('agent-a') },
  expectedState: 'indeterminate', expectedCode: 'KEY_RESOLUTION_FAILED', expectedIndex: 1,
  lines: 'L492, L321-323, L589-590', note: 'By analogy with L321-323 (without key-authority evidence the result is indeterminate) and L589-590, the state is indeterminate, not invalid; same reasoning as AD-N-C05, one level deeper in the chain.',
})

// -------------------------------------------------------------------------
// Chain cases, negative: chain structure
// -------------------------------------------------------------------------

pushChainCase({
  id: 'AD-N-H01', title: 'Root repeated as its own child', chain: [R, R],
  expectedState: 'invalid', expectedCode: 'CHAIN_DUPLICATE_ID', expectedIndex: 1,
  lines: 'L582, L585-586', note: 'A repeated delegation_id is caught before the parent-link check that the same input would also fail, in both the draft\'s order and TypeScript\'s.',
})
pushChainCase({
  id: 'AD-N-H02', title: 'Child repeated as its own child', chain: [R, C1, C1],
  expectedState: 'invalid', expectedCode: 'CHAIN_DUPLICATE_ID', expectedIndex: 2,
  lines: 'L582, L585-586', note: 'Same reasoning as AD-N-H01, one level deeper.',
})
pushChainCase({
  id: 'AD-N-H03', title: 'Empty trust table', chain: [R],
  contextOverrides: { trust: { mode: 'table', trusted_root_ids: [] } },
  expectedState: 'invalid', expectedCode: 'ROOT_UNTRUSTED', expectedIndex: 0,
  lines: 'L493-494, L582', note: 'Root acceptance is verifier policy; a definite rejection by that policy is a failed check, not missing information.',
})
pushChainCase({
  id: 'AD-N-H04', title: 'Trust policy unavailable', chain: [R, C1],
  contextOverrides: { trust: { mode: 'unavailable' } },
  expectedState: 'indeterminate', expectedCode: 'ROOT_UNTRUSTED', expectedIndex: 0,
  lines: 'L589-590, L1226', note: 'By analogy with L589-590 and L1226: an unavailable trust policy is missing information, so the result is indeterminate.',
})
pushChainCase({
  id: 'AD-N-H05', title: 'A non-root record used alone', chain: [C1],
  contextOverrides: { trust: { mode: 'table', trusted_root_ids: [C1.delegation_id] } },
  expectedState: 'invalid', expectedCode: 'PARENT_MISMATCH', expectedIndex: 0,
  lines: 'L428-429, L580, L585-586', note: 'A null parent_delegation_id marks the root of a root-to-leaf chain; C1 carries a non-null one.',
})
{
  const c1bad = forceSign(mutate(BODY_C1, (b) => { b.parent_delegation_id = flipLastHexChar(R.delegation_id) }), 'agent-a')
  pushChainCase({
    id: 'AD-N-H06', title: 'parent_delegation_id one hex character off', chain: [R, c1bad],
    expectedState: 'invalid', expectedCode: 'PARENT_MISMATCH', expectedIndex: 1,
    lines: 'L583', note: 'The child names an id that is not the exact parent content address.',
  })
}
{
  const c1bad = forceSign(mutate(BODY_C1, (b) => { b.parent_delegation_id = null }), 'agent-a')
  pushChainCase({
    id: 'AD-N-H07', title: 'Child parent_delegation_id null', chain: [R, c1bad],
    expectedState: 'invalid', expectedCode: 'PARENT_MISMATCH', expectedIndex: 1,
    lines: 'L583', note: 'A non-root chain member must name its immediate parent.',
  })
}
{
  const c1bad = forceSign(mutate(BODY_C1, (b) => {
    b.issuer = 'did:example:principal'
    b.verification_method = 'did:example:principal#key-1'
  }), 'principal')
  pushChainCase({
    id: 'AD-N-H08', title: 'Child issuer is not the parent subject', chain: [R, c1bad],
    expectedState: 'invalid', expectedCode: 'CHAIN_CONTINUITY', expectedIndex: 1,
    lines: 'L583, L585-586', note: "The signature verifies fine (signed by principal, whose key the verification_method names), but the parent's subject is agent-a, not principal.",
  })
}
{
  const c1bad = forceSign(mutate(BODY_C1, (b) => {
    b.issued_at = '2026-07-18T21:59:00.000Z'
    b.authority.time.not_before = '2026-07-18T22:00:00.000Z'
  }), 'agent-a')
  pushChainCase({
    id: 'AD-N-H09', title: 'Child issued before the parent is valid', chain: [R, c1bad],
    expectedState: 'invalid', expectedCode: 'ISSUED_AT_OUTSIDE_PARENT', expectedIndex: 1,
    lines: 'L537-538', note: 'A child MUST be issued while the parent is currently valid; here it is issued one minute before the parent even starts.',
  })
}
{
  const c1bad = forceSign(mutate(BODY_C1, (b) => {
    b.issued_at = '2026-07-19T22:00:00.000Z'
    b.authority.time = { not_before: '2026-07-19T22:00:00.000Z', not_after: '2026-07-19T23:00:00.000Z' }
  }), 'agent-a')
  pushChainCase({
    id: 'AD-N-H10', title: "Child issued exactly at the parent's expiry", chain: [R, c1bad],
    expectedState: 'invalid', expectedCode: 'ISSUED_AT_OUTSIDE_PARENT', expectedIndex: 1,
    lines: 'L537-538, L583-584', note: 'issued_at equals the parent\'s not_after, outside the half-open window; this always also widens time, but the issuance-time check precedes the facet check in both the draft\'s order and TypeScript\'s.',
  })
}

// -------------------------------------------------------------------------
// Chain cases, negative: facet comparisons, [R, C1] with C1 mutated
// -------------------------------------------------------------------------

function facetCase(id: string, title: string, lines: string, note: string, code: string, chain: any[]): void {
  pushChainCase({ id, title, chain, expectedState: 'invalid', expectedCode: code, expectedIndex: 1, lines, note })
}

facetCase('AD-N-F01', 'Child scope not covered by parent', 'L519-520', "\"travel:*\" is not covered by either of the parent's grants.", 'SCOPE_WIDENING',
  [R, forceSign(mutate(BODY_C1, (b) => { b.authority.scope.grants = ['travel:*'] }), 'agent-a')])

{
  const rootExact = issue(mutate(BODY_R, (b) => { b.authority.scope.grants = ['commerce:checkout', 'travel:book'] }), 'principal')
  const childExact = forceSign(mutate(BODY_C1, (b) => {
    b.parent_delegation_id = rootExact.delegation_id
    b.authority.scope.grants = ['commerce:checkout:refund']
  }), 'agent-a')
  facetCase('AD-N-F02', 'Exact grant does not cover a longer path', 'L518', 'An exact grant "commerce:checkout" covers only itself, not "commerce:checkout:refund".', 'SCOPE_WIDENING', [rootExact, childExact])
}

facetCase('AD-N-F03', 'Child scope widened to the bare wildcard', 'L516-519', 'Neither of the parent\'s grants is "*".', 'SCOPE_WIDENING',
  [R, forceSign(mutate(BODY_C1, (b) => { b.authority.scope.grants = ['*'] }), 'agent-a')])
facetCase('AD-N-F04', 'Bounded parent, unbounded child', 'L528-529', 'A bounded parent cannot produce an unbounded child.', 'SPEND_WIDENING',
  [R, forceSign(mutate(BODY_C1, (b) => { b.authority.spend = { mode: 'unbounded' } }), 'agent-a')])
facetCase('AD-N-F05', 'Spend unit changed', 'L526-527, L529', 'Bounded spend unit must remain exact.', 'SPEND_UNIT_CHANGE',
  [R, forceSign(mutate(BODY_C1, (b) => { b.authority.spend.unit = 'iso4217:EUR:minor' }), 'agent-a')])
facetCase('AD-N-F06', 'per_action widened', 'L526-527', "Child per_action 5001 exceeds the parent's 5000.", 'SPEND_WIDENING',
  [R, forceSign(mutate(BODY_C1, (b) => { b.authority.spend.per_action = '5001'; b.authority.spend.cumulative = '6000' }), 'agent-a')])
facetCase('AD-N-F07', 'cumulative widened', 'L526-527', "Child cumulative 10001 exceeds the parent's 10000.", 'SPEND_WIDENING',
  [R, forceSign(mutate(BODY_C1, (b) => { b.authority.spend.per_action = '2500'; b.authority.spend.cumulative = '10001' }), 'agent-a')])

{
  const rootDepth0 = issue(mutate(BODY_R, (b) => { b.authority.depth = { remaining: 0 } }), 'principal')
  const childDepth0 = forceSign(mutate(BODY_C1, (b) => {
    b.parent_delegation_id = rootDepth0.delegation_id
    b.authority.depth = { remaining: 0 }
  }), 'agent-a')
  facetCase('AD-N-F08', 'Parent depth already exhausted', 'L531-532', 'A parent with depth.remaining 0 has no further hop to give, regardless of the child\'s own depth value.', 'DEPTH_EXHAUSTED', [rootDepth0, childDepth0])
}

facetCase('AD-N-F09', 'Child depth widened', 'L532-533', "Child depth 2 exceeds the parent's 2 minus one hop.", 'DEPTH_WIDENING',
  [R, forceSign(mutate(BODY_C1, (b) => { b.authority.depth = { remaining: 2 } }), 'agent-a')])
facetCase('AD-N-F10', 'Time window widened by one millisecond', 'L535-536', "Child not_after exceeds the parent's not_after by one millisecond.", 'TIME_WIDENING',
  [R, forceSign(mutate(BODY_C1, (b) => { b.authority.time.not_after = '2026-07-19T22:00:00.001Z' }), 'agent-a')])
facetCase('AD-N-F11', 'Reputation ceiling widened', 'L541-542', "Child ceiling 81 exceeds the parent's 80.", 'REPUTATION_WIDENING',
  [R, forceSign(mutate(BODY_C1, (b) => { b.authority.reputation.ceiling = 81 }), 'agent-a')])
facetCase('AD-N-F12', 'Required value dropped', 'L547-548', 'Child dropped the ancestor-required value F-003.', 'VALUES_WEAKENING',
  [R, forceSign(mutate(BODY_C1, (b) => { b.authority.values.required = ['F-001', 'F-007'] }), 'agent-a')])
facetCase('AD-N-F13', 'Reversibility ceiling widened', 'L553-566', "Child ceiling irreversible exceeds the parent's compensable.", 'REVERSIBILITY_WIDENING',
  [R, forceSign(mutate(BODY_C1, (b) => { b.authority.reversibility.ceiling = 'irreversible' }), 'agent-a')])

{
  const RL2 = issue(mutate(BODY_R, (b) => {
    b.issued_at = '2016-12-31T23:59:59.000Z'
    b.authority.time = { not_before: '2016-12-31T23:59:59.000Z', not_after: '2016-12-31T23:59:60.999Z' }
  }), 'principal')
  const CL2 = forceSign(mutate(BODY_C1, (b) => {
    b.parent_delegation_id = RL2.delegation_id
    b.issued_at = '2016-12-31T23:59:60.000Z'
    b.authority.time = { not_before: '2016-12-31T23:59:60.000Z', not_after: '2017-01-01T00:00:00.000Z' }
  }), 'agent-a')
  pushChainCase({
    id: 'AD-N-F14', title: 'Leap-second ordering widens time', chain: [RL2, CL2],
    contextOverrides: { now: '2016-12-31T23:59:60.500Z' },
    expectedState: 'invalid', expectedCode: 'TIME_WIDENING', expectedIndex: 1,
    lines: 'RFC 3339 section 5.1', note: 'As strings, "2017-01-01T00:00:00.000Z" sorts after "2016-12-31T23:59:60.999Z", so the child\'s not_after is later than the parent\'s.',
  })
}

// -------------------------------------------------------------------------
// Chain cases, negative: current validity and revocation
// -------------------------------------------------------------------------

pushChainCase({
  id: 'AD-N-V01', title: 'now one millisecond before not_before', chain: [R],
  contextOverrides: { now: '2026-07-18T21:59:59.999Z' },
  expectedState: 'invalid', expectedCode: 'NOT_YET_VALID', expectedIndex: 0,
  lines: 'L535, L584', note: 'now is before the root\'s not_before.',
})
pushChainCase({
  id: 'AD-N-V02', title: 'now equal to not_after (end exclusive)', chain: [R],
  contextOverrides: { now: '2026-07-19T22:00:00.000Z' },
  expectedState: 'invalid', expectedCode: 'EXPIRED', expectedIndex: 0,
  lines: 'L535', note: 'The half-open window excludes its end instant.',
})
pushChainCase({
  id: 'AD-N-V03', title: "now equal to the child's not_after", chain: [R, C1],
  contextOverrides: { now: '2026-07-19T12:00:00.000Z' },
  expectedState: 'invalid', expectedCode: 'EXPIRED', expectedIndex: 1,
  lines: 'L535', note: "The root is still valid at this now; the child has expired.",
})
pushChainCase({
  id: 'AD-N-V04', title: "now before the child's not_before", chain: [R, C1],
  contextOverrides: { now: '2026-07-18T22:05:00.000Z' },
  expectedState: 'invalid', expectedCode: 'NOT_YET_VALID', expectedIndex: 1,
  lines: 'L535', note: "The root is already valid at this now; the child is not yet valid.",
})
pushChainCase({
  id: 'AD-N-V05', title: 'Root revoked', chain: [R, C1],
  contextOverrides: { revocation: { default: 'active', by_index: { '0': 'revoked' } } },
  expectedState: 'invalid', expectedCode: 'REVOKED', expectedIndex: 0,
  lines: 'L584-585, L638', note: 'Revocation is checked per member; revocation is irreversible.',
})
pushChainCase({
  id: 'AD-N-V06', title: 'Child revoked', chain: [R, C1],
  contextOverrides: { revocation: { default: 'active', by_index: { '1': 'revoked' } } },
  expectedState: 'invalid', expectedCode: 'REVOKED', expectedIndex: 1,
  lines: 'L584-585, L638', note: 'Same reasoning as AD-N-V05, one level deeper.',
})
pushChainCase({
  id: 'AD-N-V07', title: 'Child revocation unknown', chain: [R, C1],
  contextOverrides: { revocation: { default: 'active', by_index: { '1': 'unknown' } } },
  expectedState: 'indeterminate', expectedCode: 'REVOCATION_UNKNOWN', expectedIndex: 1,
  lines: 'L589-590', note: 'An unknown revocation result is indeterminate, not valid or invalid.',
})
pushChainCase({
  id: 'AD-N-V08', title: 'Revocation resolver unavailable', chain: [R],
  contextOverrides: { revocation: { default: 'active', by_index: { '0': 'unavailable' } } },
  expectedState: 'indeterminate', expectedCode: 'REVOCATION_UNKNOWN', expectedIndex: 0,
  lines: 'L589-590', note: 'A resolver that raises is treated the same as an unknown result.',
})

// -------------------------------------------------------------------------
// Wire cases: parseAuthorityDelegationJson over raw JSON text
// -------------------------------------------------------------------------

function pushWireCase(id: string, title: string, raw: string, expectAccept: boolean, lines: string, note: string): void {
  let outcome: { result: 'accept' | 'reject'; error?: { name: string; message: string } }
  let parsed: any = null
  try {
    parsed = AD.parseAuthorityDelegationJson(raw)
    outcome = { result: 'accept' }
  } catch (e) {
    const err = e as Error
    outcome = { result: 'reject', error: { name: err.constructor?.name ?? 'Error', message: err.message } }
  }
  if (expectAccept && outcome.result !== 'accept') {
    fail(`${id}: expected accept, TS rejected: ${JSON.stringify(outcome)}`)
  }
  if (!expectAccept && outcome.result !== 'reject') {
    fail(`${id}: expected reject, TS accepted`)
  }
  if (expectAccept && !deepEqual(parsed, R)) {
    fail(`${id}: parsed object does not deep-equal R`)
  }
  record('wire', 'draft-derived')
  cases.push({
    id, kind: 'wire', title,
    expected_provenance: 'draft-derived',
    derivation: { lines, note },
    input_json: raw,
    expected: expectAccept ? { result: 'accept', value: R } : { result: 'reject' },
    ts_behaviour: outcome,
  })
}

pushWireCase('AD-W01', 'R as JSON.stringify(R)', JSON.stringify(R), true,
  'L204', 'JSON whitespace and member order are not significant to the parser.')

{
  function reversedTopLevelPretty(obj: Record<string, unknown>): string {
    const keys = Object.keys(obj).reverse()
    const parts = keys.map((k) => {
      const valJson = JSON.stringify(obj[k], null, 2)
      const reindented = valJson.split('\n').join('\n  ')
      return `  ${JSON.stringify(k)}: ${reindented}`
    })
    return '{\n' + parts.join(',\n') + '\n}'
  }
  const raw = reversedTopLevelPretty(R)
  // Sanity-check this generator's own construction: it must still be valid
  // JSON that deep-equals R, independent of what the parser under test does.
  if (!deepEqual(JSON.parse(raw), R)) fail('AD-W02: constructed reversed/pretty text does not parse back to R')
  pushWireCase('AD-W02', 'R pretty-printed, top-level members reversed', raw, true,
    'L204', 'JCS re-orders members regardless of source order or whitespace.')
}

{
  const plain = JSON.stringify(R)
  const raw = '{"nonce":' + JSON.stringify(R.nonce) + ',' + plain.slice(1)
  pushWireCase('AD-W03', 'Duplicate top-level "nonce" member', raw, false,
    'RFC 7493 section 2.3, L204', 'I-JSON forbids duplicate names.')
}

{
  const plain = JSON.stringify(R)
  const marker = '"scope":{'
  const idx = plain.indexOf(marker)
  if (idx === -1) fail('AD-W04: scope marker not found in R JSON text')
  const insertAt = idx + marker.length
  const raw = plain.slice(0, insertAt) + '"profile":"aps-hierarchical-v1",' + plain.slice(insertAt)
  pushWireCase('AD-W04', 'Duplicate "profile" member inside authority.scope', raw, false,
    'RFC 7493 section 2.3, L204', 'I-JSON forbids duplicate names at any depth.')
}

{
  const raw = JSON.stringify({ ...R, subject: R.subject + '\uD800' })
  pushWireCase('AD-W05', 'subject with a JSON-escaped lone surrogate', raw, false,
    'RFC 7493 section 2.1', 'A lone surrogate is not well-formed Unicode.')
}

pushWireCase('AD-W06', 'Top-level JSON array', '[]', false,
  'L480', 'The wire form is a JSON object, not an array.')

{
  const plain = JSON.stringify(R)
  const raw = plain.slice(0, -1) + ',}'
  pushWireCase('AD-W07', 'Trailing comma after the last top-level member', raw, false,
    'RFC 8259', 'A trailing comma is not valid JSON syntax.')
}

{
  const raw = JSON.stringify({ ...R, comment: 'x' })
  pushWireCase('AD-W08', 'Extra top-level member "comment"', raw, false,
    'L480', 'The v1 schema is closed.')
}

{
  // U+FFFF spelled as a literal six-character JSON \u escape (backslash, u,
  // f, f, f, f) inserted into the wire text by string surgery, not by
  // JSON.stringify (which would emit the noncharacter unescaped, since it is
  // a complete UTF-16 code unit, not a surrogate). This file's own source
  // never carries the noncharacter itself.
  const plain = JSON.stringify(R)
  const marker = `"subject":"${R.subject}"`
  const idx = plain.indexOf(marker)
  if (idx === -1) fail('AD-W09: subject marker not found')
  const insertAt = idx + marker.length - 1 // just before the closing quote
  const raw = plain.slice(0, insertAt) + '\\uffff' + plain.slice(insertAt)
  pushWireCase('AD-W09', 'subject with a JSON-escaped noncharacter (U+FFFF)', raw, false,
    'L204 with RFC 7493 section 2.1', 'A JSON \\u escape can spell a noncharacter, and I-JSON rejects it just the same as a literal one.')
}

// -------------------------------------------------------------------------
// Issuance cases: issueAuthorityDelegation and issueSubAuthorityDelegation
// -------------------------------------------------------------------------

function pushIssueRootCase(
  id: string, title: string, body: any, signingKey: Label,
  expectIssue: boolean, provenance: 'draft-derived' | 'ts-conformant-regression', lines: string, note: string,
): any {
  let outcome: { result: 'issue' | 'refuse'; delegation?: any; error?: string }
  let delegation: any = null
  try {
    delegation = AD.issueAuthorityDelegation(body, seedHex(signingKey))
    outcome = { result: 'issue', delegation }
  } catch (e) {
    outcome = { result: 'refuse', error: (e as Error).message }
  }
  const expectedResult = expectIssue ? 'issue' : 'refuse'
  if (outcome.result !== expectedResult) {
    fail(`${id}: expected ${expectedResult}, TS returned ${outcome.result} (${outcome.error ?? ''})`)
  }
  record('issue_root', provenance)
  cases.push({
    id, kind: 'issue_root', title,
    expected_provenance: provenance,
    derivation: { lines, note },
    body, signing_key: signingKey,
    expected: expectIssue ? { result: 'issue', delegation } : { result: 'refuse' },
    ts_behaviour: outcome.result === 'issue' ? { result: 'issue' } : { result: 'refuse', error: outcome.error },
  })
  return delegation
}

interface IssueChildContext { keys: 'default' | 'without_principal'; revocation_parent: RevocationValue; now?: string }

const ISSUE_CHILD_DEFAULT_NOW = '2026-07-18T23:00:00.000Z'

function pushIssueChildCase(
  id: string, title: string, parent: any, body: any, signingKey: Label, context: IssueChildContext,
  expectIssue: boolean, provenance: 'draft-derived' | 'ts-conformant-regression', lines: string, note: string,
  opts?: { stopOnMismatch?: boolean },
): any {
  const stopOnMismatch = opts?.stopOnMismatch ?? true
  let outcome: { result: 'issue' | 'refuse'; delegation?: any; error?: string }
  let delegation: any = null
  try {
    delegation = AD.issueSubAuthorityDelegation(parent, body, seedHex(signingKey))
    outcome = { result: 'issue', delegation }
  } catch (e) {
    outcome = { result: 'refuse', error: (e as Error).message }
  }
  const expectedResult = expectIssue ? 'issue' : 'refuse'
  if (stopOnMismatch && outcome.result !== expectedResult) {
    fail(`${id}: expected ${expectedResult}, TS returned ${outcome.result} (${outcome.error ?? ''})`)
  }
  const contextOut = {
    keys: context.keys === 'default' ? ALL_KEY_ENTRIES : keysWithout('principal'),
    revocation: { parent: context.revocation_parent },
    now: context.now ?? ISSUE_CHILD_DEFAULT_NOW,
  }
  record('issue_child', provenance)
  cases.push({
    id, kind: 'issue_child', title,
    expected_provenance: provenance,
    derivation: { lines, note },
    parent, body, signing_key: signingKey, context: contextOut,
    expected: expectIssue ? { result: 'issue', delegation: outcome.result === 'issue' ? outcome.delegation : delegation } : { result: 'refuse' },
    ts_behaviour: outcome.result === 'issue'
      ? { result: 'issue', delegation_id: outcome.delegation.delegation_id }
      : { result: 'refuse', error: outcome.error },
  })
  return delegation
}

pushIssueRootCase('AD-I01', 'issue_root: body R, key principal', clone(BODY_R), 'principal', true, 'ts-conformant-regression',
  'section 3.1', "The expected record's delegation_id and signature bytes are TypeScript output for the section 3.1 construction; the cross-check recomputes both.")

pushIssueChildCase('AD-I02', 'issue_child: parent R, body C1, key agent-a', R, clone(BODY_C1), 'agent-a',
  { keys: 'default', revocation_parent: 'active' }, true, 'ts-conformant-regression',
  'section 3.1', 'Same reasoning as AD-I01, one level deeper in the chain.')

pushIssueChildCase('AD-I03', 'issue_child: parent C1, body C2, key agent-b', C1, clone(BODY_C2), 'agent-b',
  { keys: 'default', revocation_parent: 'active' }, true, 'ts-conformant-regression',
  'section 3.1', 'Same reasoning as AD-I01, two levels deeper in the chain.')

pushIssueChildCase('AD-I04', 'issue_child: parent R, body C1 with scope widened', R,
  mutate(BODY_C1, (b) => { b.authority.scope.grants = ['travel:*'] }), 'agent-a',
  { keys: 'default', revocation_parent: 'active' }, false, 'draft-derived',
  'L695, L519-520', 'INV-2 (attenuation) is enforced at issuance.')

pushIssueChildCase('AD-I05', "issue_child: parent R, body C1 issued at the parent's expiry", R,
  mutate(BODY_C1, (b) => {
    b.issued_at = '2026-07-19T22:00:00.000Z'
    b.authority.time = { not_before: '2026-07-19T22:00:00.000Z', not_after: '2026-07-19T23:00:00.000Z' }
  }), 'agent-a', { keys: 'default', revocation_parent: 'active' }, false, 'draft-derived',
  'L698-701', 'The parent has already expired at the moment of issuance.')

pushIssueChildCase('AD-I06', 'issue_child: parent R, body C1 issued before the parent starts', R,
  mutate(BODY_C1, (b) => {
    b.issued_at = '2026-07-18T21:59:00.000Z'
    b.authority.time.not_before = '2026-07-18T22:00:00.000Z'
  }), 'agent-a', { keys: 'default', revocation_parent: 'active' }, false, 'draft-derived',
  'L698-699', 'The parent is not yet valid at the moment of issuance.')

pushIssueChildCase('AD-I07', 'issue_child: parent R revoked', R, clone(BODY_C1), 'agent-a',
  { keys: 'default', revocation_parent: 'revoked' }, false, 'draft-derived',
  'L698-699', 'issueSubAuthorityDelegation takes no revocation input, so TypeScript cannot refuse on this ground; its actual behaviour is recorded without changing the draft-derived expectation.',
  { stopOnMismatch: false })

pushIssueChildCase('AD-I08', "issue_child: parent R with its signature corrupted", { ...R, signature: flipLastHexChar(R.signature) }, clone(BODY_C1), 'agent-a',
  { keys: 'default', revocation_parent: 'active' }, false, 'draft-derived',
  'L696-698', 'The issuer MUST verify the parent signature; issueSubAuthorityDelegation does not, so TypeScript actually issues. The draft-derived expectation is left as refuse.',
  { stopOnMismatch: false })

pushIssueChildCase('AD-I09', 'issue_child: parent R, revocation unknown', R, clone(BODY_C1), 'agent-a',
  { keys: 'default', revocation_parent: 'unknown' }, false, 'draft-derived',
  'L589-592', 'An unknown revocation result MUST NOT be collapsed into valid; issueSubAuthorityDelegation takes no revocation input, so TypeScript actually issues.',
  { stopOnMismatch: false })

pushIssueChildCase('AD-I10', 'issue_child: parent R, key resolver missing the principal entry', R, clone(BODY_C1), 'agent-a',
  { keys: 'without_principal', revocation_parent: 'active' }, false, 'draft-derived',
  'L696-698', "The issuer MUST verify the parent's signature, which requires resolving its key; issueSubAuthorityDelegation takes no key resolver, so TypeScript actually issues.",
  { stopOnMismatch: false })

{
  const parentDepth0 = issue(mutate(BODY_R, (b) => { b.authority.depth = { remaining: 0 } }), 'principal')
  pushIssueChildCase('AD-I11', 'issue_child: parent depth 0, body depth 0', parentDepth0,
    mutate(BODY_C1, (b) => { b.parent_delegation_id = parentDepth0.delegation_id; b.authority.depth = { remaining: 0 } }),
    'agent-a', { keys: 'default', revocation_parent: 'active' }, false, 'draft-derived',
    'L531-532', 'The parent has no remaining delegation hop.')
}

pushIssueChildCase('AD-I12', 'issue_child: body parent_delegation_id names a different record', R,
  mutate(BODY_C1, (b) => { b.parent_delegation_id = flipLastHexChar(R.delegation_id) }), 'agent-a',
  { keys: 'default', revocation_parent: 'active' }, false, 'draft-derived',
  'L583', 'The body does not name the actual parent as its parent_delegation_id.')

pushIssueChildCase('AD-I13', 'issue_child: body issuer is the parent, not the parent subject', R,
  mutate(BODY_C1, (b) => { b.issuer = 'did:example:principal'; b.verification_method = 'did:example:principal#key-1' }),
  'principal', { keys: 'default', revocation_parent: 'active' }, false, 'draft-derived',
  'L583', "The body's issuer must equal the parent's subject.")

pushIssueChildCase('AD-I14', 'issue_child: body nonce uppercased', R,
  mutate(BODY_C1, (b) => { b.nonce = b.nonce.toUpperCase() }), 'agent-a',
  { keys: 'default', revocation_parent: 'active' }, false, 'draft-derived',
  'L481, L462', 'nonce must be 32 lowercase hex characters even at issuance time.')

pushIssueChildCase('AD-I15', "issue_child: parent R, body C1 unchanged, now at the parent's expiry", R, clone(BODY_C1), 'agent-a',
  { keys: 'default', revocation_parent: 'active', now: '2026-07-19T22:00:00.000Z' }, false, 'draft-derived',
  'L697-701', "now is R's not_after, so the parent has expired at issuance while the child's own issued_at is still inside its window; TypeScript's issuer takes no now, so TypeScript actually issues.",
  { stopOnMismatch: false })

pushIssueChildCase('AD-I16', 'issue_child: parent R, body C1 unchanged, now before the parent starts', R, clone(BODY_C1), 'agent-a',
  { keys: 'default', revocation_parent: 'active', now: '2026-07-18T21:00:00.000Z' }, false, 'draft-derived',
  'L696-699', "now is before R's not_before, so the parent is not yet valid at issuance; TypeScript's issuer takes no now, so TypeScript actually issues.",
  { stopOnMismatch: false })

// -------------------------------------------------------------------------
// Budget cases: InMemoryAuthorityBudgetLedger reserve/dispatch/commit/cancel
// -------------------------------------------------------------------------

const P_BUDGET = issue(mutate(BODY_R, (b) => {
  b.authority.spend = { mode: 'bounded', unit: 'iso4217:USD:minor', per_action: '1000', cumulative: '1000' }
}), 'principal')
const S1_BUDGET = issue(mutate(BODY_C1, (b) => {
  b.parent_delegation_id = P_BUDGET.delegation_id
  b.subject = 'did:example:agent-b'
  b.nonce = '11111111111111111111111111111111'
  b.authority.spend = { mode: 'bounded', unit: 'iso4217:USD:minor', per_action: '1000', cumulative: '1000' }
}), 'agent-a')
const S2_BUDGET = issue(mutate(BODY_C1, (b) => {
  b.parent_delegation_id = P_BUDGET.delegation_id
  b.subject = 'did:example:agent-c'
  b.nonce = '22222222222222222222222222222222'
  b.authority.spend = { mode: 'bounded', unit: 'iso4217:USD:minor', per_action: '1000', cumulative: '1000' }
}), 'agent-a')
const CB_BUDGET = issue(mutate(BODY_C1, (b) => {
  b.parent_delegation_id = RU_REC.delegation_id
  b.authority.spend = { mode: 'bounded', unit: 'iso4217:USD:minor', per_action: '100', cumulative: '100' }
}), 'agent-a')

const ACTION_REF_A = 'a'.repeat(64)
const ACTION_REF_B = 'b'.repeat(64)
const ACTION_REF_C = 'c'.repeat(64)
const ACTION_REF_D = 'd'.repeat(64)
const USD = 'iso4217:USD:minor'

type BudgetStepOp = 'reserve' | 'mark_dispatched' | 'commit' | 'cancel'
interface BudgetStepSpec {
  op: BudgetStepOp
  chain?: string
  action_ref: string
  unit?: string
  amount?: string
  expectedOk: boolean
  expectedCode: string
  expectedState?: string
  countersAfter: Record<string, { reserved: string; committed: string }>
}

function runBudgetCase(
  id: string, title: string, chains: Record<string, any[]>, steps: BudgetStepSpec[], lines: string, note: string,
): void {
  const ledger = new AD.InMemoryAuthorityBudgetLedger()
  const labelToId = new Map<string, string>()
  for (const chain of Object.values(chains)) {
    for (const rec of chain) {
      for (const [label, byLabel] of Object.entries(RECORD_LABELS)) {
        if (byLabel === rec) labelToId.set(label, rec.delegation_id)
      }
    }
  }
  const outSteps: Record<string, unknown>[] = []
  const tsSteps: Record<string, unknown>[] = []
  for (const step of steps) {
    let result: any
    if (step.op === 'reserve') {
      const chain = chains[step.chain as string]
      if (!chain) fail(`${id}: unknown chain name ${step.chain}`)
      result = ledger.reserve(chain, step.action_ref, step.unit as string, step.amount as string)
    } else if (step.op === 'mark_dispatched') {
      result = ledger.markDispatched(step.action_ref)
    } else if (step.op === 'commit') {
      result = ledger.commit(step.action_ref)
    } else if (step.op === 'cancel') {
      result = ledger.cancel(step.action_ref)
    } else {
      fail(`${id}: unknown budget op ${step.op}`)
    }
    if (result.ok !== step.expectedOk || result.code !== step.expectedCode || (step.expectedState !== undefined && result.state !== step.expectedState)) {
      fail(`${id}: step ${step.op} ${step.action_ref} expected ok=${step.expectedOk} code=${step.expectedCode} state=${step.expectedState}, got ${JSON.stringify(result)}`)
    }
    if (step.expectedState === undefined && result.state !== undefined) {
      fail(`${id}: step ${step.op} ${step.action_ref} expected no state, got ${result.state}`)
    }
    const actualCounters: Record<string, { reserved: string; committed: string }> = {}
    for (const label of Object.keys(step.countersAfter)) {
      const delegationId = labelToId.get(label)
      if (!delegationId) fail(`${id}: unknown record label ${label} in countersAfter`)
      actualCounters[label] = ledger.counter(delegationId)
    }
    for (const label of Object.keys(step.countersAfter)) {
      const expectedCounter = step.countersAfter[label]
      const actualCounter = actualCounters[label]
      if (actualCounter.reserved !== expectedCounter.reserved || actualCounter.committed !== expectedCounter.committed) {
        fail(`${id}: step ${step.op} ${step.action_ref} counters for ${label} expected ${JSON.stringify(expectedCounter)}, got ${JSON.stringify(actualCounter)}`)
      }
    }
    const expectedOut: Record<string, unknown> = { ok: step.expectedOk, sdk_code: step.expectedCode }
    if (step.expectedState !== undefined) expectedOut.state = step.expectedState
    outSteps.push({
      op: step.op,
      ...(step.chain ? { chain: step.chain } : {}),
      action_ref: step.action_ref,
      ...(step.unit ? { unit: step.unit } : {}),
      ...(step.amount ? { amount: step.amount } : {}),
      expected: expectedOut,
      counters_after: actualCounters,
    })
    const tsStepOut: Record<string, unknown> = { ok: result.ok, code: result.code }
    if (result.state !== undefined) tsStepOut.state = result.state
    tsSteps.push(tsStepOut)
  }
  record('budget', 'draft-derived')
  const record_labels = Object.fromEntries(labelToId)
  cases.push({
    id, kind: 'budget', title,
    expected_provenance: 'draft-derived',
    derivation: { lines, note },
    chains,
    record_labels,
    steps: outSteps,
    expected: { steps: outSteps.map((s) => s.expected) },
    ts_behaviour: { steps: tsSteps },
  })
}

// Record-label maps used only to resolve counters_after label -> delegation_id.
const RECORD_LABELS: Record<string, any> = {
  R, C1, C2, P: P_BUDGET, S1: S1_BUDGET, S2: S2_BUDGET, RU: RU_REC, CB: CB_BUDGET,
}

runBudgetCase('AD-B01', 'Idempotent reserve, then a conflicting amount', { main: [R, C1, C2] }, [
  { op: 'reserve', chain: 'main', action_ref: ACTION_REF_A, unit: USD, amount: '1000', expectedOk: true, expectedCode: 'RESERVED', expectedState: 'reserved',
    countersAfter: { R: { reserved: '1000', committed: '0' }, C1: { reserved: '1000', committed: '0' }, C2: { reserved: '1000', committed: '0' } } },
  { op: 'reserve', chain: 'main', action_ref: ACTION_REF_A, unit: USD, amount: '1000', expectedOk: true, expectedCode: 'IDEMPOTENT', expectedState: 'reserved',
    countersAfter: { R: { reserved: '1000', committed: '0' }, C1: { reserved: '1000', committed: '0' }, C2: { reserved: '1000', committed: '0' } } },
  { op: 'reserve', chain: 'main', action_ref: ACTION_REF_A, unit: USD, amount: '999', expectedOk: false, expectedCode: 'CONFLICT', expectedState: 'reserved',
    countersAfter: { R: { reserved: '1000', committed: '0' }, C1: { reserved: '1000', committed: '0' }, C2: { reserved: '1000', committed: '0' } } },
], 'L621-622', 'A second reserve with the same actionRef and amount is idempotent; a different amount conflicts.')

runBudgetCase('AD-B02', 'per_action exceeded leaves all counters untouched', { main: [R, C1, C2] }, [
  { op: 'reserve', chain: 'main', action_ref: ACTION_REF_A, unit: USD, amount: '1001', expectedOk: false, expectedCode: 'PER_ACTION_EXCEEDED',
    countersAfter: { R: { reserved: '0', committed: '0' }, C1: { reserved: '0', committed: '0' }, C2: { reserved: '0', committed: '0' } } },
], 'L604-607', "C2's per_action is 1000; all-or-none means no counter changes on failure.")

runBudgetCase('AD-B03', 'cumulative exceeded at the tightest ancestor', { main: [R, C1, C2] }, [
  { op: 'reserve', chain: 'main', action_ref: ACTION_REF_A, unit: USD, amount: '1000', expectedOk: true, expectedCode: 'RESERVED', expectedState: 'reserved',
    countersAfter: { R: { reserved: '1000', committed: '0' }, C1: { reserved: '1000', committed: '0' }, C2: { reserved: '1000', committed: '0' } } },
  { op: 'reserve', chain: 'main', action_ref: ACTION_REF_B, unit: USD, amount: '1000', expectedOk: true, expectedCode: 'RESERVED', expectedState: 'reserved',
    countersAfter: { R: { reserved: '2000', committed: '0' }, C1: { reserved: '2000', committed: '0' }, C2: { reserved: '2000', committed: '0' } } },
  { op: 'reserve', chain: 'main', action_ref: ACTION_REF_C, unit: USD, amount: '1', expectedOk: false, expectedCode: 'CUMULATIVE_EXCEEDED',
    countersAfter: { R: { reserved: '2000', committed: '0' }, C1: { reserved: '2000', committed: '0' }, C2: { reserved: '2000', committed: '0' } } },
], 'L605-606', "C2's cumulative 2000 is exhausted by the first two reservations.")

runBudgetCase('AD-B04', 'Two siblings cannot each spend the whole parent cumulative', { pair1: [P_BUDGET, S1_BUDGET], pair2: [P_BUDGET, S2_BUDGET] }, [
  { op: 'reserve', chain: 'pair1', action_ref: ACTION_REF_A, unit: USD, amount: '1000', expectedOk: true, expectedCode: 'RESERVED', expectedState: 'reserved',
    countersAfter: { P: { reserved: '1000', committed: '0' }, S1: { reserved: '1000', committed: '0' } } },
  { op: 'reserve', chain: 'pair2', action_ref: ACTION_REF_B, unit: USD, amount: '1', expectedOk: false, expectedCode: 'CUMULATIVE_EXCEEDED',
    countersAfter: { P: { reserved: '1000', committed: '0' }, S1: { reserved: '1000', committed: '0' }, S2: { reserved: '0', committed: '0' } } },
], 'L600-601, L625-626', "P's cumulative 1000 is already exhausted by S1's sibling reservation.")

runBudgetCase('AD-B05', 'Unit mismatch', { main: [R, C1, C2] }, [
  { op: 'reserve', chain: 'main', action_ref: ACTION_REF_A, unit: 'iso4217:EUR:minor', amount: '1', expectedOk: false, expectedCode: 'UNIT_MISMATCH',
    countersAfter: { R: { reserved: '0', committed: '0' }, C1: { reserved: '0', committed: '0' }, C2: { reserved: '0', committed: '0' } } },
], 'L720-723', "The root's spend unit is iso4217:USD:minor.")

runBudgetCase('AD-B06', 'Reserve, dispatch, commit, idempotent re-commit', { main: [R, C1, C2] }, [
  { op: 'reserve', chain: 'main', action_ref: ACTION_REF_A, unit: USD, amount: '1000', expectedOk: true, expectedCode: 'RESERVED', expectedState: 'reserved',
    countersAfter: { R: { reserved: '1000', committed: '0' }, C1: { reserved: '1000', committed: '0' }, C2: { reserved: '1000', committed: '0' } } },
  { op: 'mark_dispatched', action_ref: ACTION_REF_A, expectedOk: true, expectedCode: 'DISPATCHED', expectedState: 'dispatched',
    countersAfter: { R: { reserved: '1000', committed: '0' }, C1: { reserved: '1000', committed: '0' }, C2: { reserved: '1000', committed: '0' } } },
  { op: 'commit', action_ref: ACTION_REF_A, expectedOk: true, expectedCode: 'COMMITTED', expectedState: 'committed',
    countersAfter: { R: { reserved: '0', committed: '1000' }, C1: { reserved: '0', committed: '1000' }, C2: { reserved: '0', committed: '1000' } } },
  { op: 'commit', action_ref: ACTION_REF_A, expectedOk: true, expectedCode: 'IDEMPOTENT', expectedState: 'committed',
    countersAfter: { R: { reserved: '0', committed: '1000' }, C1: { reserved: '0', committed: '1000' }, C2: { reserved: '0', committed: '1000' } } },
], 'L622-623, L745-746', 'Dispatch does not move counters; commit moves reserved to committed; re-commit is idempotent.')

runBudgetCase('AD-B07', 'Reserve, cancel, idempotent re-cancel', { main: [R, C1, C2] }, [
  { op: 'reserve', chain: 'main', action_ref: ACTION_REF_A, unit: USD, amount: '500', expectedOk: true, expectedCode: 'RESERVED', expectedState: 'reserved',
    countersAfter: { R: { reserved: '500', committed: '0' }, C1: { reserved: '500', committed: '0' }, C2: { reserved: '500', committed: '0' } } },
  { op: 'cancel', action_ref: ACTION_REF_A, expectedOk: true, expectedCode: 'CANCELLED', expectedState: 'cancelled',
    countersAfter: { R: { reserved: '0', committed: '0' }, C1: { reserved: '0', committed: '0' }, C2: { reserved: '0', committed: '0' } } },
  { op: 'cancel', action_ref: ACTION_REF_A, expectedOk: true, expectedCode: 'IDEMPOTENT', expectedState: 'cancelled',
    countersAfter: { R: { reserved: '0', committed: '0' }, C1: { reserved: '0', committed: '0' }, C2: { reserved: '0', committed: '0' } } },
], 'L624-625', 'Cancellation before dispatch releases the reservation; re-cancel is idempotent.')

runBudgetCase('AD-B08', 'Cancel after dispatch is refused', { main: [R, C1, C2] }, [
  { op: 'reserve', chain: 'main', action_ref: ACTION_REF_A, unit: USD, amount: '500', expectedOk: true, expectedCode: 'RESERVED', expectedState: 'reserved',
    countersAfter: { R: { reserved: '500', committed: '0' }, C1: { reserved: '500', committed: '0' }, C2: { reserved: '500', committed: '0' } } },
  { op: 'mark_dispatched', action_ref: ACTION_REF_A, expectedOk: true, expectedCode: 'DISPATCHED', expectedState: 'dispatched',
    countersAfter: { R: { reserved: '500', committed: '0' }, C1: { reserved: '500', committed: '0' }, C2: { reserved: '500', committed: '0' } } },
  { op: 'cancel', action_ref: ACTION_REF_A, expectedOk: false, expectedCode: 'INVALID_STATE', expectedState: 'dispatched',
    countersAfter: { R: { reserved: '500', committed: '0' }, C1: { reserved: '500', committed: '0' }, C2: { reserved: '500', committed: '0' } } },
], 'L624-625', 'After dispatch, a reservation is released only on trusted evidence that dispatch did not occur; this interface takes no such evidence.')

runBudgetCase('AD-B09', 'Commit after cancel is refused', { main: [R, C1, C2] }, [
  { op: 'reserve', chain: 'main', action_ref: ACTION_REF_A, unit: USD, amount: '500', expectedOk: true, expectedCode: 'RESERVED', expectedState: 'reserved',
    countersAfter: { R: { reserved: '500', committed: '0' }, C1: { reserved: '500', committed: '0' }, C2: { reserved: '500', committed: '0' } } },
  { op: 'cancel', action_ref: ACTION_REF_A, expectedOk: true, expectedCode: 'CANCELLED', expectedState: 'cancelled',
    countersAfter: { R: { reserved: '0', committed: '0' }, C1: { reserved: '0', committed: '0' }, C2: { reserved: '0', committed: '0' } } },
  { op: 'commit', action_ref: ACTION_REF_A, expectedOk: false, expectedCode: 'INVALID_STATE', expectedState: 'cancelled',
    countersAfter: { R: { reserved: '0', committed: '0' }, C1: { reserved: '0', committed: '0' }, C2: { reserved: '0', committed: '0' } } },
], 'L624-625', 'A cancelled reservation cannot be committed.')

runBudgetCase('AD-B10', 'Unbounded parent has no counter to reserve against', { unb: [RU_REC, CB_BUDGET] }, [
  { op: 'reserve', chain: 'unb', action_ref: ACTION_REF_A, unit: USD, amount: '100', expectedOk: true, expectedCode: 'RESERVED', expectedState: 'reserved',
    countersAfter: { RU: { reserved: '0', committed: '0' }, CB: { reserved: '100', committed: '0' } } },
], 'L602-604', 'Every BOUNDED delegation is checked; an unbounded one has no limit to reserve against and gets no counter entry.')

runBudgetCase('AD-B11', 'Malformed action_ref and amount are rejected before any state change', { main: [R, C1, C2] }, [
  { op: 'reserve', chain: 'main', action_ref: 'A'.repeat(64), unit: USD, amount: '1000', expectedOk: false, expectedCode: 'CONFLICT',
    countersAfter: { R: { reserved: '0', committed: '0' }, C1: { reserved: '0', committed: '0' }, C2: { reserved: '0', committed: '0' } } },
  { op: 'reserve', chain: 'main', action_ref: ACTION_REF_A, unit: USD, amount: '1.5', expectedOk: false, expectedCode: 'CONFLICT',
    countersAfter: { R: { reserved: '0', committed: '0' }, C1: { reserved: '0', committed: '0' }, C2: { reserved: '0', committed: '0' } } },
  { op: 'reserve', chain: 'main', action_ref: ACTION_REF_A, unit: USD, amount: '01', expectedOk: false, expectedCode: 'CONFLICT',
    countersAfter: { R: { reserved: '0', committed: '0' }, C1: { reserved: '0', committed: '0' }, C2: { reserved: '0', committed: '0' } } },
], 'L807-808, L524-525', 'action_ref must be 64 lowercase hex characters and amounts must be canonical decimal integers; CONFLICT is SDK vocabulary for malformed input.')

{
  const rootChildChain = [R, C1]
  runBudgetCase('AD-B12', 'committed plus reserved plus the new amount, against a two-record chain', { root_child: rootChildChain }, [
    { op: 'reserve', chain: 'root_child', action_ref: ACTION_REF_A, unit: USD, amount: '1500', expectedOk: true, expectedCode: 'RESERVED', expectedState: 'reserved',
      countersAfter: { R: { reserved: '1500', committed: '0' }, C1: { reserved: '1500', committed: '0' } } },
    { op: 'commit', action_ref: ACTION_REF_A, expectedOk: true, expectedCode: 'COMMITTED', expectedState: 'committed',
      countersAfter: { R: { reserved: '0', committed: '1500' }, C1: { reserved: '0', committed: '1500' } } },
    { op: 'reserve', chain: 'root_child', action_ref: ACTION_REF_B, unit: USD, amount: '2500', expectedOk: true, expectedCode: 'RESERVED', expectedState: 'reserved',
      countersAfter: { R: { reserved: '2500', committed: '1500' }, C1: { reserved: '2500', committed: '1500' } } },
    { op: 'reserve', chain: 'root_child', action_ref: ACTION_REF_C, unit: USD, amount: '1001', expectedOk: false, expectedCode: 'CUMULATIVE_EXCEEDED',
      countersAfter: { R: { reserved: '2500', committed: '1500' }, C1: { reserved: '2500', committed: '1500' } } },
  ], 'L605-606', "1500 committed + 2500 reserved + 1001 new exceeds C1's cumulative of 5000.")
}

runBudgetCase('AD-B13', 'Operations on an unknown action_ref', { main: [R, C1, C2] }, [
  { op: 'mark_dispatched', action_ref: ACTION_REF_D, expectedOk: false, expectedCode: 'NOT_FOUND', countersAfter: {} },
  { op: 'commit', action_ref: ACTION_REF_D, expectedOk: false, expectedCode: 'NOT_FOUND', countersAfter: {} },
  { op: 'cancel', action_ref: ACTION_REF_D, expectedOk: false, expectedCode: 'NOT_FOUND', countersAfter: {} },
], 'section 3.4', 'There was never a reservation under this actionRef.')

runBudgetCase('AD-B14', 'action_ref with a trailing line feed is rejected, the clean one is not', { main: [R, C1, C2] }, [
  { op: 'reserve', chain: 'main', action_ref: ACTION_REF_A + '\n', unit: USD, amount: '1', expectedOk: false, expectedCode: 'CONFLICT',
    countersAfter: { R: { reserved: '0', committed: '0' }, C1: { reserved: '0', committed: '0' }, C2: { reserved: '0', committed: '0' } } },
  { op: 'reserve', chain: 'main', action_ref: ACTION_REF_A, unit: USD, amount: '1', expectedOk: true, expectedCode: 'RESERVED', expectedState: 'reserved',
    countersAfter: { R: { reserved: '1', committed: '0' }, C1: { reserved: '1', committed: '0' }, C2: { reserved: '1', committed: '0' } } },
], 'L807-808', 'action_ref must be exactly 64 lowercase hex characters, with nothing appended; the two actionRefs are distinct reservation keys, so the second reserve is unaffected by the first.')

// -------------------------------------------------------------------------
// Assemble the output document and write it
// -------------------------------------------------------------------------

const description =
  'Cross-implementation vectors for AuthorityDelegationV1 (draft-pidlisnyi-aps-03 sections 3.1, 3.2, 3.3, 3.4 ' +
  'and 3.6). Expected states, outcomes and rejections come from the draft text, RFC 3339 and RFC 7493, as cited ' +
  'per case, not from TypeScript output; sdk_codes are the TypeScript SDK\'s own failure-code vocabulary ' +
  '(AuthorityFailureCode in src/v2/authority-delegation/types.ts, and BudgetOperationResult.code), which the ' +
  'draft does not name, and the Python port shares the same strings as SDK parity, not a protocol claim. Every ' +
  'record\'s delegation_id and signature were computed by the TypeScript reference\'s canonical.ts ' +
  '(computeAuthorityDelegationId and signAuthorityDelegation, or issueAuthorityDelegation for records this file ' +
  'names as valid), except the all-zero placeholder in AD-N-S13 (which cannot be canonicalized at all) and the ' +
  'records a case edits after signing, as its own title says; tests/cross_impl/crosscheck_authority_delegation_v1_vectors.py ' +
  'recomputes every one of them independently with the rfc8785 package and PyNaCl. This file is not "TS verified" ' +
  'and no case in it should be described that way: TypeScript output was consulted only for the bytes and ' +
  'behaviour any implementation must reproduce, not for what the expected state or result should be.'

const provenance_definitions = {
  'draft-derived':
    'the expected state, outcome or rejection follows from the draft text (with RFC 3339 or RFC 7493 where ' +
    'cited); TypeScript output was not consulted to decide it.',
  'ts-conformant-regression':
    'the expected bytes were computed by the TypeScript reference for a construction whose TypeScript ' +
    'implementation was found to follow the draft (delegation_id and signature, draft section 3.1), and are recomputed ' +
    'independently by the cross-check script.',
}

const conventions = {
  key_resolution:
    'The key resolver in a chain case\'s context is called with (issuer, verification_method, issued_at) and ' +
    'returns the public_key_hex of the context.keys entry whose issuer and verification_method both match, else ' +
    'no key (TypeScript null, Python None).',
  trust:
    'context.trust of {"mode":"table","trusted_root_ids":[...]} accepts the chain head exactly when its ' +
    'delegation_id is listed; {"mode":"unavailable"} means the trust policy raises.',
  revocation:
    'context.revocation of {"default":..., "by_index":{"<i>":...}} means the revocation resolver returns the ' +
    'value for the chain member at index i when by_index names it, else the default; "unavailable" means the ' +
    'resolver raises.',
  default_context:
    "Unless a case overrides an item: now is 2026-07-18T23:00:00.000Z; keys carries all five labels; trust is " +
    "{\"mode\":\"table\",\"trusted_root_ids\":[<the chain's first record's delegation_id as written, even when a " +
    'case corrupts it>]}; revocation default is "active".',
  issue_child_now:
    'Every issue_child case carries context.now, default 2026-07-18T23:00:00.000Z. The Python issuer takes an ' +
    'explicit now and requires the parent to be valid at it (draft section 3.6, L696-701); the TypeScript issuer ' +
    'takes no now, so context.now is descriptive only against the TypeScript reference.',
}

const withheld = [
  { topic: 'Multi-fault chains', reason: 'The draft does not say which failure decides when several steps fail. Only single-fault chains are included; AD-N-H01, AD-N-H02 and AD-N-H10 carry an unavoidable later fault and each case explains why the order does not matter for it.' },
  { topic: "A root whose time.not_before predates its issued_at", reason: 'L536-537 states the rule for a child; whether it binds a root is an open question.' },
  { topic: 'Values the draft admits that the TypeScript schema rejects by a grammar the draft does not state', reason: 'A spend unit outside ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$, and JSON number spellings such as 2.0 or 1e2 in wire input; whether the draft admits them is an open question.' },
  { topic: 'A non-string record_type or version', reason: 'Whether that is unsupported or invalid is not determined by the draft.' },
  { topic: 'A facet profile that is not a string', reason: 'Whether that is invalid or unsupported is not determined by the draft.' },
  { topic: 'Facet content that breaks a section 3.2 value rule under an unsupported profile', reason: 'The draft does not say whether those rules bind a facet whose profile is not supported, so such a record may be two faults.' },
  { topic: 'Key-resolution outcome structure', reason: 'not found, ambiguous, malformed, unreachable, unsupported scheme (L360-369): an open question.' },
  { topic: 'Runtime reputation and unresolved action reversibility', reason: 'L542-545 and L566 are action-time rules, not chain verification.' },
  { topic: 'Revocation records and cascade completion', reason: 'Sections 3.5 and 3.5.1: no wire format is fixed and no implementation exists.' },
  { topic: 'Implementation limits that are not draft rules', reason: 'At most 256 records per chain, 1 MiB wire input, 1024 UTF-8 bytes per identifier, and the scope segment and values identifier grammars (aps-hierarchical-v1 and aps-values-identifiers-v1 treated as profile detail).' },
  { topic: "A child whose not_before is earlier than its parent's not_before, as a single fault", reason: "Impossible: the child's not_before is not before its issued_at, which is not before the parent's not_before." },
  { topic: "Issuer refusal when the parent's delegation_id does not match its content", reason: "The draft requires the issuer to verify the parent's signature and temporal validity (L696-698); it does not name the content address. The Python issuer checks it anyway; no vector." },
]

const document = {
  description,
  draft: 'draft-pidlisnyi-aps-03 sections 3.1, 3.2, 3.3, 3.4 and 3.6',
  generated_from: { repository: 'agent-passport-system', commit: tsCommit },
  provenance_definitions,
  keys: keysInfo,
  conventions,
  cases,
  withheld,
  counts,
}

writeFileSync(outPath, JSON.stringify(document, null, 2) + '\n', 'utf8')
console.log(`wrote ${cases.length} cases to ${outPath}`)
console.log(JSON.stringify(counts, null, 2))
