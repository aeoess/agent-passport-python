// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Generate tests/fixtures/*.json from the TypeScript reference SDK.
//
// The cross-language tests in tests/test_attribution_consent.py,
// tests/test_human_escalation.py and tests/test_provisional_statement.py
// load fixtures that were SIGNED BY THE TS SDK and verify them with the
// Python SDK — a genuine TS→Python verification loop. The fixtures are
// committed; re-run this script only when the TS signing surface changes:
//
//   cd <this repo root>
//   ../agent-passport-system/node_modules/.bin/tsx scripts/generate_ts_fixtures.mjs
//
// or, if the TS checkout is elsewhere:
//
//   APS_SYSTEM_CHECKOUT=/path/to/agent-passport-system \
//     "$APS_SYSTEM_CHECKOUT/node_modules/.bin/tsx" scripts/generate_ts_fixtures.mjs
//
// The private keys below are throwaway, fixture-only Ed25519 seeds committed
// on purpose so regeneration is deterministic where the TS API allows it.
// They authorize nothing outside these test fixtures.

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(__dirname, '..')
const sdkRoot = process.env.APS_SYSTEM_CHECKOUT
  ?? path.resolve(repoRoot, '..', 'agent-passport-system')
const fixturesDir = path.join(repoRoot, 'tests', 'fixtures')

if (!fs.existsSync(path.join(sdkRoot, 'src', 'index.ts'))) {
  console.error(`TS SDK not found at ${sdkRoot} — set APS_SYSTEM_CHECKOUT`)
  process.exit(1)
}

const mod = (p) => import(pathToFileURL(path.join(sdkRoot, 'src', p)).href)

const { sign, publicKeyFromPrivate } = await mod('crypto/keys.ts')
const { createHybridTimestamp } = await mod('core/time.ts')
const attribution = await mod('v2/attribution-consent/index.ts')
const escalation = await mod('v2/human-escalation.ts')
const provisional = await mod('v2/provisional-statement/index.ts')

// ── Fixture-only deterministic key seeds (see header note) ──
const CITER_PRIV = '1a'.repeat(32)
const PRINCIPAL_PRIV = '2b'.repeat(32)
const OWNER_PRIV = '3c'.repeat(32)
const AUTHOR_PRIV = '4d'.repeat(32)

const CITER_PUB = publicKeyFromPrivate(CITER_PRIV)
const PRINCIPAL_PUB = publicKeyFromPrivate(PRINCIPAL_PRIV)
const OWNER_PUB = publicKeyFromPrivate(OWNER_PRIV)
const AUTHOR_PUB = publicKeyFromPrivate(AUTHOR_PRIV)

// Committed fixtures must stay temporally valid for future test runs:
// expiries sit ~100 years out.
const HUNDRED_YEARS_MS = 100 * 365 * 24 * 60 * 60 * 1000

function write(name, obj) {
  const file = path.join(fixturesDir, name)
  fs.mkdirSync(fixturesDir, { recursive: true })
  fs.writeFileSync(file, JSON.stringify(obj, null, 2) + '\n')
  console.log(`wrote ${file}`)
}

// ══════════════════════════════════════════════════════════════════
// 1. Attribution consent receipt (citer-signed + principal consent)
// ══════════════════════════════════════════════════════════════════
{
  // Fixed timestamps → fully deterministic receipt (id, both signatures).
  const created_at = {
    logicalTime: 1,
    wallClockEarliest: 1751328000000 - 1000, // 2025-07-01T00:00:00Z ± 1s
    wallClockLatest: 1751328000000 + 1000,
    gatewayId: 'ts-fixture-gw',
  }
  const expires_at = {
    logicalTime: 2,
    wallClockEarliest: 1751328000000 + HUNDRED_YEARS_MS - 1000,
    wallClockLatest: 1751328000000 + HUNDRED_YEARS_MS + 1000,
    gatewayId: 'ts-fixture-gw',
  }

  const receipt = attribution.createAttributionReceipt({
    citer: 'agent:ts-fixture-citer',
    citer_public_key: CITER_PUB,
    citer_private_key: CITER_PRIV,
    cited_principal: 'principal:ts-fixture-cited',
    cited_principal_public_key: PRINCIPAL_PUB,
    citation_content: 'The cited principal endorsed narrowing scope, not widening it.',
    binding_context: 'charter:ts-fixture-abc',
    created_at,
    expires_at,
  })
  const signed = attribution.signAttributionConsent(receipt, PRINCIPAL_PRIV)

  const check = attribution.verifyAttributionConsent(signed)
  if (!check.valid) throw new Error(`TS self-verify failed (attribution): ${check.reason}`)

  write('attribution_receipt_from_ts.json', signed)
}

// ══════════════════════════════════════════════════════════════════
// 2. Owner confirmation (human escalation)
// ══════════════════════════════════════════════════════════════════
{
  const delegation = {
    id: 'del-ts-fixture-0001',
    delegator: OWNER_PUB,
    scope: {
      action_categories: ['org_creation', 'read'],
      escalation_requirements: [
        {
          action_class: 'org_creation',
          requires_owner_confirmation: true,
          // Long TTL so the committed confirmation stays valid for future runs.
          confirmation_ttl_ms: HUNDRED_YEARS_MS,
          confirmation_scope: 'per_action',
        },
      ],
    },
  }
  const action = {
    action_class: 'org_creation',
    action_details: { org_name: 'AEOESS Fixture Org' },
  }

  const request = escalation.requestOwnerConfirmation(delegation, action)
  const confirmation = escalation.recordOwnerConfirmation({
    request,
    delegation,
    owner_private_key: OWNER_PRIV,
  })

  const check = escalation.verifyOwnerConfirmation(confirmation, action, delegation)
  if (!check.valid) throw new Error(`TS self-verify failed (escalation): ${check.reason}`)

  // __-prefixed blocks carry the verification context; the confirmation
  // itself is every non-__ key (see tests/test_human_escalation.py).
  write('owner_confirmation_from_ts.json', {
    ...confirmation,
    __delegation__: delegation,
    __action__: action,
  })
}

// ══════════════════════════════════════════════════════════════════
// 3. Provisional statement, promoted via principal signature
// ══════════════════════════════════════════════════════════════════
{
  const statement = provisional.createProvisional({
    author: AUTHOR_PUB,
    author_principal: PRINCIPAL_PUB,
    content: 'Provisional: propose settlement terms v3 for review.',
    authorPrivateKey: AUTHOR_PRIV,
    gatewayId: 'ts-fixture-gw',
    id: 'ts-fixture-statement-0001',
  })

  const policy = {
    id: 'policy-ts-fixture',
    required_signers: [PRINCIPAL_PUB],
    threshold: 1,
    max_time_to_promote: 60_000,
  }

  const promoted_at = createHybridTimestamp('ts-fixture-gw')
  const payload = provisional.promotionSigningPayload({
    statement_id: statement.id,
    kind: 'principal_signature',
    promoted_at,
    promoter: PRINCIPAL_PUB,
    policy_reference: policy.id,
  })
  const promotionEvent = {
    kind: 'principal_signature',
    promoted_at,
    promoter: PRINCIPAL_PUB,
    promoter_signature: sign(payload, PRINCIPAL_PRIV),
    policy_reference: policy.id,
  }

  // promoteStatement runs TS verifyPromotion internally and throws on failure.
  const promoted = provisional.promoteStatement(statement, promotionEvent, policy)

  const check = provisional.verifyPromotion(promoted, policy)
  if (!check.valid) throw new Error(`TS self-verify failed (provisional): ${check.errors.join('; ')}`)

  write('provisional_statement_from_ts.json', {
    ...promoted,
    __policy__: policy,
  })
}

console.log('done')
