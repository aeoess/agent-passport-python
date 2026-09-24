# Changelog

## Unreleased

### New

- **`agent_passport.v2.activation`, activation conditions and condition attestation.
  PROPOSED and OPT-IN.** Python parity of the TypeScript SDK's `src/v2/activation/`, name for
  name with snake_case adapted to Python convention. A grant can be validly issued and still
  wait on a date or a recorded event. This module decides whether such a condition is
  established for one action at one instant, and reports the answer alongside a chain result
  rather than inside it.

  Nothing here is required by draft-pidlisnyi-aps-03. The published text states no
  activation-condition rule, no attestor role and no attestation-acceptance rule: a
  case-insensitive search of it for `activation`, `attestor` and `contingen` returns nothing.
  Its section 3.2 also says verbatim: "authority contains exactly seven required facets:
  scope, spend, depth, time, reputation, values, and reversibility. A missing facet is
  invalid rather than an implicit unconstrained value." That closes the authority vector, so
  an activation condition can never be a facet, and this module models it as a SEPARATE
  artifact referencing a `delegation_id`. `AuthorityValidationResult` and everything
  `verify_authority_delegation_chain` returns are unchanged, and a caller that does not import
  the new module sees no change at all.

  Concept source: the aeoess/agent-authority-lifecycle concept document, which carries
  "Activation condition" as proposed with no case testing it, and its invariant candidates
  CAND-04 (activation is established, not yet effective, or not established), CAND-13
  (replacement authority may be pre-committed at issuance) and BROAD-L7. All proposed, with
  no published specification text behind them, and every exported symbol says so in its
  docstring.

  New public surface:

  - `verify_activation(...)`, returning `valid`, `not_yet_effective` or `not_established` in
    the `agent_passport.v2.lifecycle_state` vocabulary, and NEVER `invalid`. An unmet
    activation condition does not make a grant invalid, and whether the grant is valid at all
    is chain verification's answer rather than this module's.
  - The split the module exists for. `not_yet_effective` is an established negative: an
    accepted record says the condition had not occurred, or puts its first occurrence after
    the action, and the remedy is to wait. `not_established` is ignorance, names which of
    `source` and `coverage` was missing, and its remedy is a better source. A rejected
    attestation is not evidence in either direction, so a record from a source the model does
    not accept leaves the condition unestablished rather than unmet.
  - No retroactive activation, keyed on the CONDITION's own instant rather than on the instant
    someone wrote the record. A record putting the first occurrence after the action leaves
    that action `not_yet_effective`, and the same record establishes the condition for any
    later action.
  - `compose_activation(chain, activation, mapping=None)`, which returns the chain result
    untouched and asks activation only when the chain is valid. That ordering keeps invariant
    L1 intact for CAND-13's pre-committed replacement grant: a revoked pre-committing
    instrument leaves the replacement's chain invalid, and no activation evidence can make it
    exercisable.
  - Two condition kinds. A `date` condition needs no evidence at all, so an unreached date is
    always a known negative. A `recorded_event` condition names `required_attestor_roles`,
    which are ROLES and never principals.
  - `AttestorRoleResolver`, a caller-supplied callable returning `holds`, `does_not_hold` or
    `unknown`. Three values, not a boolean: "this registry does not know" is a distinct answer
    from "this party does not hold that role", and collapsing the first into the second turns
    ignorance into a denial. Role standing is resolved OUTSIDE the record, always. An
    attestation's `attestor_role` is the attestor's claim about itself, and the module checks
    that claim against the resolver rather than believing it.
  - `validate_activation_condition`, the canonical-bytes helpers
    (`activation_attestation_body`, `activation_attestation_signature_input`,
    `compute_activation_attestation_id`, `activation_condition_signature_input`), three
    distinct domain tags that each carry `PROPOSED` so nothing signed under them can be
    replayed as a specified record, and `ActivationError` for shape rules broken at the call
    site.

  THREE PARAMETERS ARE DELIBERATELY UNDEFAULTED, because the concept text has not decided
  them and a default in an SDK is a ruling made by whoever wrote the SDK: `instant_basis`,
  `threshold`, and role standing. Vector `AC-14` is the pair that proves the first is load
  bearing: one record, one action instant, and opposite verdicts under the two readings.

  `conformance/activation/v0/vectors.json` is vendored byte for byte from the TypeScript SDK,
  where it is authored, with its provenance and SHA-256 recorded beside it. Both repositories
  pin that digest inside their own test, so a one-sided edit fails on the side that was
  edited. Both ports run the same 12 condition-shape cases, 34 verify cases and 7 composition
  cases. Byte parity is checked directly as well: every attestation in the shared vectors was
  signed by the TypeScript module over its own domain-tagged RFC 8785 preimage, and this
  port's tests verify each of those signatures and recompute each content-bound identifier.
- **`agent_passport.v2.bounds`, non-time bounds on a grant. PROPOSED and OPT-IN.**
  Python parity of the TypeScript SDK's `src/v2/bounds/`, name for name with snake_case
  adapted to Python convention. Purpose, use-count and budget bounds, and the state "this
  bound has been reached". Nothing here is required by draft-pidlisnyi-aps-03 and nothing
  existing changed. Two of that document's sentences constrain the whole module. Section
  3.2, verbatim: "authority contains exactly seven required facets: scope, spend, depth,
  time, reputation, values, and reversibility.  A missing facet is invalid rather than an
  implicit unconstrained value." The facet set is closed, so a purpose bound or a use-count
  bound cannot live inside a signed authority delegation, and this module declares a
  separate artifact that references a delegation by its content address. Section 3.3,
  verbatim: "Verification returns one of valid, invalid, indeterminate, or unsupported with
  a stable failure code." That set is closed too and this change does not touch it: a bound
  evaluation is reported alongside a chain result, in the vocabulary
  `agent_passport.v2.lifecycle_state` owns. A caller that does not import the new module
  sees no change at all.

  draft-03 has zero occurrences of `exhaust` and zero of `use_count`. It uses "single-use"
  only of an approval in section 4.3, never of a grant. The concept source is the
  aeoess/agent-authority-lifecycle concept document: invariant L10 (expiry is not
  revocation), whose "Expiry or exhaustion" concept entry names a use count, a budget and a
  purpose as bounds whose being reached ends authority, and invariant candidates CAND-01 (an
  external event is authority-changing only when established) and CAND-02 (later evidence
  does not rewrite earlier evidence). All three are proposed, with no published
  specification text behind them, and every exported symbol says so in its docstring.

  New public surface, all re-exported from the package root:

  - `AuthorityBound`, a bound declared on one delegation: a kind, a value, and the
    fulfilment-attestor ROLES who may say it was reached. Roles rather than principals,
    because whoever may attest that a compressor was installed is whoever holds the role
    now, not whoever held it when the grant was signed. The module does not authenticate
    the bound declaration itself and says so: that is the caller's step, by whatever means
    its authority model provides.
  - `issue_authority_bound_fulfilment`, a signed attestation that a purpose bound was
    reached. Modelled on what section 3.5.1 requires of a revocation record, which is the
    nearest published shape for "a party with standing recorded that an authority
    artifact's state changed".
  - `assess_fulfilment`, which assesses ONE record. Standing is asked BEFORE authenticity,
    and each produces its own reason code, because "authenticated by somebody who may not
    say this" and "not authenticated at all" are different failures. A record from a party
    with standing saying the purpose was NOT met is the one rejection that carries no
    missing limbs: the verifier reached a conclusion, so there is no gap to name.
  - `evaluate_bound`, which answers `not_reached`, `exhausted` or `not_established` at an
    instant, alongside the same conclusion in the lifecycle vocabulary and an `ending` field
    that is `exhaustion` or `None` and never `expiry` or `revocation`. An unauthenticated
    fulfilment claim gives `not_established`, never `exhausted` and never `not_reached`. An
    exhaustion that was established is not downgraded by a later claim nobody could
    authenticate, and the verdict does not depend on the order the records arrive in.
  - `issue_authority_exhaustion` and `verify_authority_exhaustion`, the OPTIONAL signed
    exhaustion record, shaped like the section 3.5.1 revocation record so the two endings
    are comparable evidence. It attests the enforcement boundary's own finding and not the
    state of the world, on the model section 5.3.3 uses for an action result, verbatim: "An
    action-result record attests to what the enforcement boundary observed after dispatch.
    External occurrence or settlement requires separately resolved evidence." Issuance
    REFUSES for any state other than `exhausted`, with no override.
  - `is_purpose_permitted` and `purpose_category`, the Python port of the TypeScript SDK's
    long-standing functions of the same name, which that SDK now also re-exports from its
    own bounds module. This SDK had no port of either, and putting the same primitive at
    two unrelated paths in the two languages would become a cross-language annoyance the
    first time a vector referenced it. Purpose membership is not purpose exhaustion: it
    answers the same for the second purchase as for the first, which is why it can never
    decide exhaustion.
  - The `budget` kind delegates to `InMemoryAuthorityBudgetLedger` and never reimplements
    it. It reads the `{"committed", "reserved"}` shape `counter()` already returns.
    draft-03 section 3.4 already states the rule, verbatim: "Signatures establish static
    limits; they do not establish the current cumulative total."

  Cross-language parity: `conformance/authority-bounds/v0/vectors.json`, 53 cases, is the
  shared fixture, authored in the TypeScript SDK and vendored here byte for byte. Both
  repositories pin the file's SHA-256 inside their own test, so a one-sided edit fails on
  the side that was edited. Every verdict, reason code and refusal code in it is hand
  specified, and the signature and identifier byte values are there so the two ports can be
  shown to emit the same characters. Tests live at `tests/test_bounds.py`.
- **`agent_passport.v2.capability_binding`, capability pins and identifier binding.
  PROPOSED and OPT-IN.** Python parity of the TypeScript SDK's
  `src/v2/capability-binding/`, name for name with snake_case adapted to Python
  convention. Whether an action through a named tool is established under a grant that pins
  that tool, and whether an authority path that depends on an off-chain identifier still
  depends on the same party. Nothing here is required by draft-pidlisnyi-aps-03, which
  defines no pin syntax and states no rule pinning a tool to an implementation digest or a
  schema. Its nearest text is the section 4.1 action reference, verbatim: "target is the
  exact resource, tool, or endpoint against which the action will be dispatched; a profile
  MUST define its target string construction." A target carries no digest, so it cannot
  tell two revisions of one tool behind one endpoint apart. Proposed -04 excludes
  capability binding by name.

  `AuthorityValidationResult` is unchanged, `verify_authority_delegation_chain` returns
  exactly what it returned, and the authority vector gains no eighth facet (section 3.2
  closes it at seven and makes a missing facet invalid). Every result here is a boundary
  outcome from the lifecycle state vocabulary, reported alongside a chain result and never
  merged into it. Nothing in this module makes any delegation invalid. A caller that does
  not import it sees exactly today's behaviour.

  The concept source is the aeoess/agent-authority-lifecycle concept document, invariant
  candidate CAND-07 as rewritten, whose statement is a verdict rule: where nothing pins a
  referent, the verdict records that referent continuity was not established rather than
  admitting silently, and where something pins it and the pin does not match, the action is
  denied with a mismatch reason rather than reported as not established. Also the
  `AUTHORITY-LIFECYCLE.md` concepts "Action or capability binding", "Target binding" and
  "Authority path and dependency". All proposed, with no published specification text
  behind them, and every exported symbol says so in its doc comment.

  New public surface: `evaluate_capability_binding`, `evaluate_identifier_continuity`,
  `observe_tool_attestation`, `capability_implementation_digest`,
  `capability_metadata_digest`, `parse_capability_pin_from_scope_grants`,
  `capability_pin_scope_grants`, `capability_pin_is_empty`, `tool_scope_grant`,
  `implementation_pin_prefix`, `metadata_pin_prefix`, `identifier_record_signed_bytes`,
  `identifier_dependency_scope_grant`, `identifier_controller_pin_scope_grant`,
  `parse_identifier_controller_pins`, `referent_binding_result`,
  `identifier_continuity_result`, `project_boundary_outcome_to_candidate_v0`, the
  `CapabilityPin`, `ReferentBindingResult`, `IdentifierContinuityResult` and
  `ToolAttestationObservation` dataclasses, `CapabilityBindingError`, and the two
  reason-code tuples.

  `ReferentBindingResult` carries no `valid` property, on the same reasoning as
  `LifecycleStateResult`: `not_established` is not a boolean's false branch.

  `capability_metadata_digest` is over `domain || 0x00 || JCS(metadata)` with a REQUIRED
  domain and no default. It uses `canonicalize_jcs`, which keeps `None` members, not the
  legacy `canonicalize`, which strips them. The two are not interchangeable for this
  preimage.

  `conformance/capability-binding/v0/vectors.json` is a byte-for-byte copy of the
  TypeScript SDK's file, which is where it is authored, with its SHA-256 pinned in both
  repositories' own tests. 18 capability cases, 15 identifier cases and the digest,
  scope-grant and canonical-byte known answers. The identifier records are stored unsigned
  and signed by each runner over its own canonical bytes, so a canonical-byte divergence
  shows up as a failed signature check rather than as two runners agreeing on a blob
  neither produced. Tests live at `tests/test_capability_binding.py`.

- **`agent_passport.tool_integrity`, the tool registry-entry layer. EXPERIMENTAL.** An
  attestor signs that a named tool's implementation bytes are the ones it approved, and a
  verifier later checks that the tool reachable now still hashes to the same value. Ported
  from the TypeScript SDK's `src/core/tool-integrity.ts` at byte parity, including the
  optional `verified_at` override for deterministic fixtures. The Python SDK had no
  tool-integrity surface at all before this, and the capability-binding module above needs
  an attested implementation digest to compare a pin against.

  `create_tool_registry_entry` and `verify_tool_integrity`, with the `ToolRegistryEntry`,
  `ToolRequirements`, `AgentCapabilities` and `ToolIntegrityResult` dataclasses.
  `ToolRegistryEntry` keeps the TypeScript SDK's camelCase field names verbatim, because
  those names are signed: the attestor signature is taken over the canonical JSON of
  `{toolName, implementationHash, attestorId, verifiedAt}`, and renaming any of them would
  produce bytes neither SDK could check.

  draft-pidlisnyi-aps-03 defines no tool registry entry and no tool-integrity check, so
  treat these names as subject to change. NOT PORTED, and stated so no caller assumes
  parity: the TypeScript SDK's file also carries a signed tool manifest layer
  (`createToolManifest`, `verifyToolManifest`, `reviseToolManifest`,
  `reapproveToolManifest`) and a namespace-claim layer (`createNamespaceClaim`,
  `verifyNamespaceClaim`), with publisher identity, `did:web` trust-root resolution and
  metadata-change re-approval. Those are a larger job with their own resolution behaviour,
  and a partial port would be the behavioural drift `AGENTS.md` calls a bug.

- **`agent_passport.v2.lifecycle_state`, the lifecycle state vocabulary. PROPOSED and
  OPT-IN.** Python parity of the TypeScript SDK's `src/v2/lifecycle-state/`, name for name
  with snake_case adapted to Python convention. A second verdict vocabulary, reported
  alongside chain verification and never merged into it. Nothing here is required by
  draft-pidlisnyi-aps-03, whose section 3.3 says verbatim: "Verification returns one of
  valid, invalid, indeterminate, or unsupported with a stable failure code." That
  enumeration is closed and this change does not touch it. `AuthorityValidationResult` and
  everything `verify_authority_delegation_chain` and `verify_authority_delegation` return
  are exactly what they were, and a caller that does not import the new module sees no
  change at all.

  Concept source: the aeoess/agent-authority-lifecycle concept document, invariant L8
  (suspension is not revocation) and invariant candidates BROAD-L7, CAND-04 and CAND-05.
  Each is proposed, with no published specification text behind it, and every exported
  symbol says so in its docstring.

  New public surface, all re-exported from the package root: `LIFECYCLE_VERDICTS` (the six
  artifact verdicts `valid`, `invalid`, `not_established`, `not_yet_effective`,
  `suspended`, `restricted`), `BOUNDARY_OUTCOMES` (the separate subject: what an
  enforcement point decides about one action at one authorization boundary),
  `ESTABLISHMENT_GAPS` (`source`, `freshness`, `coverage`, at least one of which a
  `not_established` verdict must name), `ESTABLISHED_NEGATIVE_SHAPES` with
  `resolve_established_negative()` (the split between the two uses of "not established":
  the evidential sense keeps the name, an established negative resolves to
  `not_yet_effective` or to a denial at a boundary and never to `not_established`),
  `LifecycleStateResult`, `OutstandingCause`, `EstablishedNegativeResolution`,
  `CompositeAuthorityResult`, `LifecycleStateError`, `lifecycle_state()`,
  `not_established()`, the four vocabulary predicates, and
  `map_authority_validation_to_lifecycle()`, the opt-in read-only view of an existing
  `AuthorityValidationResult` in the new vocabulary.

  `LifecycleStateResult` deliberately carries no `valid` property.
  `AuthorityValidationResult` has one and it is correct there, but here `not_established`
  is not a boolean's false branch and a truthiness shortcut invites exactly the collapse
  the vocabulary exists to prevent.

  One reading in the mapping is worth naming: a result whose only failure is
  `NOT_YET_VALID` stays `invalid` by default, because the concept document has not decided
  whether a waiting grant is invalid or not yet effective, and a base module several other
  surfaces build on should not embed a contested reading as a default.
  `not_yet_valid_as_not_yet_effective=True` takes CAND-04's reading, under which such a
  grant is `not_yet_effective`.

  Cross-language parity: `conformance/lifecycle-state/v0/vectors.json`, 38 hand-specified
  cases, is vendored byte for byte from the TypeScript SDK where it is authored, with its
  provenance and SHA-256 recorded beside it. Both repositories pin that digest inside their
  own test, so a one-sided edit fails on the side that was edited. Tests live at
  `tests/test_lifecycle_state.py`, and both ports run the same 47 assertions.
- **`agent_passport.v2.chain_selection`**: Python parity of the TypeScript SDK's
  `src/v2/chain-selection`, the draft-03 section 3.3 rule that every other authority entry
  point in this SDK had no surface for. Section 3.3 states it: "Each action selects one
  root-to-leaf authority chain.  A verifier MUST NOT union scopes or budgets from multiple
  chains.  Cross-principal composition requires a separate profile."
  `verify_authority_delegation_chain` and `InMemoryAuthorityBudgetLedger.reserve` each take
  exactly one chain, so an implementation that evaluated an action against three chains and
  pooled the answers, and one that selected a single chain, were indistinguishable through
  this SDK. `select_chain_for_action()` and `select_with_fallback()` take the whole set of
  chains an agent holds and return the name of the ONE chain the action was decided against.

  New public surface, importable from `agent_passport` and from
  `agent_passport.v2.chain_selection`: `select_chain_for_action`, `select_with_fallback`,
  the dataclasses `HeldChain`, `RequiredSpendV1`, `ChainEvaluation`,
  `FallbackAuthorizationV0` and `SelectionOutcome`, the `AuthorityBudgetReserver` protocol,
  and the constants `CHAIN_SELECTION_EVALUATION_CODES`, `CHAIN_SELECTION_FAILURE_CODES` and
  `HELD_SET_CEILING`.

  **Additive and opt-in. Nothing existing changed.** The four-valued chain result is
  unchanged, the authority vector is unchanged, `verify_authority_delegation_chain` returns
  exactly what it returned before for every draft-03 record, and a consumer that never
  imports the module sees today's behaviour. There is no wall clock anywhere in it. `now`
  and the three resolvers are the caller's keyword arguments, the budget reserver is
  injected, and neither entry point raises.

  **No union, held by construction rather than by a check.** One private function judges one
  chain and is the only place a chain is judged, so no code path lets two chains' scope
  grants or spend ceilings meet in one comparison. A result names one `chain_id`, never a
  set. A held entry that is two or more chains concatenated into one list, the shape a
  caller reaches for to have two chains evaluated together, is refused by name as
  `chain_set_presented_as_one` before verification rather than being reported as the broken
  parent link chain verification would otherwise call it.

  **Selection rule, this implementation's own, identical to the TypeScript SDK's.** draft-03
  states that an action selects one chain and does not state how. Candidates are evaluated
  in held order, the first that verifies `valid` and covers every needed scope grant is
  selected, the action's spend is then reserved against that chain and no other, and a spend
  refusal is that chain's refusal and ends the call. Continuing past a spend refusal to a
  chain with a larger ceiling would be a fallback in everything but name.

  **Not established is kept apart from refused.** A candidate whose revocation answer is
  unknown, whose facet profile is unsupported, or whose spend could not be checked because
  no ledger was supplied, is `undecided`, never `refuses`, and one undecided candidate makes
  the whole outcome `selection_undecided` rather than "no chain covers the action". Section
  3.3 forbids collapsing indeterminate or unsupported into valid, and collapsing them into a
  denial reason would be the opposite error.

- **PROPOSED, not draft-03: the fallback surface.** `select_with_fallback`'s `fallback`
  argument and the `switched_from`, `fallback_ref` and `fallback_considered` members of
  `SelectionOutcome` serve invariant candidate L11, "No silent authority resurrection", in
  `AUTHORITY-LIFECYCLE.md` of the aeoess/agent-authority-lifecycle concept document, whose
  own status there is `proposed`. draft-03 says nothing about what an implementation does
  after the chain it selected turns out to be unusable. `fallback=None` reads no held chain
  other than the preferred one, so a refusal cannot hide a switch. An authorization object
  permits the switch and the result then names the chain switched away from. That document
  does not define what makes a fallback explicitly authorized, so `authorization_ref` is an
  opaque reference this SDK records and never interprets, and its presence is not a claim
  that anything authorized anything. Every symbol carrying this half says so in its
  docstring.

- **Cross-language parity.** `tests/cross_impl/chain-selection-v0-vectors.json` is the
  TypeScript SDK's own vector file, vendored byte for byte with its provenance and SHA-256
  recorded beside it. 19 cases over three single-hop chains from three roots to one leaf.
  From the file's inputs alone, Python reproduces every recorded outcome member for member:
  which chain was selected, the chain's own verification state, every candidate's outcome
  and code, and the fallback members. No Node runs and nothing calls into the TypeScript SDK.

- **`agent_passport.v2.status_coverage`, multiple trusted status sources with freshness
  bounds. PROPOSED, EXPERIMENTAL and OPT-IN.** Python parity of the TypeScript SDK's
  `src/v2/status-coverage/`, name for name with snake_case adapted to Python convention.
  Decides what one authorization boundary can establish about one `authority_ref` from a SET
  of status answers, each measured against the freshness bound declared for its own source.
  Conflict between accepted sources, or staleness past a declared bound, gives not
  established. An offline verifier holding a snapshot inside a bound it declared in advance
  may admit, and the record names the snapshot and the age it admitted at.

  Nothing here is required by draft-pidlisnyi-aps-03. Section 3.3 rules one revocation
  result per chain member and closes verification at, verbatim: "Verification returns one of
  valid, invalid, indeterminate, or unsupported with a stable failure code." It says nothing
  about two sources answering about the same member, nothing about a per-source freshness
  bound, nothing about coverage over a declared source set, and nothing about an offline
  admission on a snapshot. `AuthorityValidationResult` and everything
  `verify_authority_delegation_chain` returns are exactly what they were. This decision is
  reported alongside a chain result, never merged into it, and a caller that does not import
  the new module sees no change at all.

  Concept source: the aeoess/agent-authority-lifecycle concept document, invariant L7
  (unknown revocation state is not active), which is the published-text half, and invariant
  candidate BROAD-L7, all three limbs, which broadens L7 to any current lifecycle state
  claim. BROAD-L7 is proposed, and every exported symbol says so in its docstring.

  New public surface: `decide_multi_source_status`, `StatusTrustPolicy`,
  `RequiredSourceSet`, `DeclaredStatusSource`, `SnapshotSource`, `StaleAnswerPolicy`,
  `StatusAnswerInput`, `StatusSourceLine`, `StatusConflict`, `StatusCoverage`,
  `AdmittedSnapshot`, `MultiSourceStatusBasis`, `MultiSourceStatusDecision`,
  `StatusCoverageError`, and the vocabulary tuples `STATUS_ANSWERS`,
  `DETERMINATE_STATUS_ANSWERS`, `STATUS_USE_BASES`, `STATUS_COVERAGE_REASON_CODES`,
  `SILENCE_POLICIES`, `CONFLICT_POLICIES`, `VERIFIER_MODES` and `COVERAGE_DENOMINATORS`.

  `conflict_policy`, `stale_policy` and `RequiredSourceSet.silence_is` are required with no
  defaults. That is unusual for an SDK and it is deliberate: each has two defensible
  readings of the proposed text, the readings give opposite verdicts on the
  deployment-relevant case, and a default would be this SDK making a specification decision
  in code.

  `StatusCoverage` reports coverage over a DECLARED required-source set. It is NOT a
  completeness claim. Invariant L12 is open, and a `complete=True` block must not be read as
  a statement that the declared set was every source that mattered.

  Cross-language parity: `conformance/status-coverage/v0/vectors.json`, 24 hand-specified
  decision cases and 16 refusal cases, is a byte-identical copy of the TypeScript SDK's
  authoring file. Both repositories pin its SHA-256 inside their own test, so a one-sided
  edit fails on the side that was edited. Tests live at `tests/test_status_coverage.py`.

## 4.1.0 (2026-09-22)

### New

- **`agent_passport.v2.authority_revocation`**: Python parity of the draft-03 section 3.5.1
  DIRECT revocation of an `AuthorityDelegationV1` (`aps:authority-revocation:v1`), ported
  from the TypeScript SDK's `src/v2/authority-revocation/`. The closed schema; the three
  frozen domain tags, each byte exact with its trailing NUL; issuance under a
  caller-supplied `now` and `nonce`, with no clock and no random source anywhere in it;
  verification with issuer-bound historical key resolution at the record's own `revoked_at`;
  the first-wins store; `record_authority_revocation()`, the verifying mutation path that is
  the one supported way a record enters a store; and the fail-closed
  active / revoked / unknown resolver the Python authority delegation chain verifier already
  takes. Until now a Python consumer could verify a delegation chain but had no way to
  produce or check the record that revokes one.
- The wire format is checked against the TypeScript SDK's own committed vector, vendored byte
  for byte as `tests/cross_impl/authority-revocation-v1-vectors.json` with its provenance and
  SHA-256 recorded beside it. From the vector's seeds and inputs alone, Python issuance
  reproduces the valid record byte for byte under JCS, all three preimages hex for hex, and
  `revocation_id`, `cascade_transaction_id` and `signature`; Python verification returns the
  recorded state and first failure code for each of the nine negative cases. No Node runs and
  nothing calls into the TypeScript SDK.
- **Scope**: the direct revocation path only. No cascade-derived record for a descendant of a
  revoked delegation (0B) and no cascade-completion evidence (0C). Enforcement against
  descendants comes from chain verification, which already rejects a chain carrying a revoked
  ancestor, not from a derived record. Section 3.5.1 makes completion depend on a
  descendant's revocation being persistent, and no store interface here establishes
  persistence.
- **`verify_receipt_with_decision_v1`** (`src/agent_passport/receipt_core/composite.py`): the
  section 5.6 composite check of a receipt together with the decision it references. Parity
  with the TypeScript reference `verifyReceiptWithDecisionV1`: same stage order and
  short-circuit, same per-axis result members, same error code strings, same status
  dominance. Until now the Python SDK had no counterpart to it, so a Python consumer holding
  a receipt and a decision had no way to establish that the two belonged together.
- **`verify_receipt_predecessor_v1`** (`src/agent_passport/receipt_core/predecessor.py`): the
  section 5.3.3 prev binding for an action-result record, against the policy-decision record
  it names. The predecessor's `receipt_id` is RECOMPUTED from its body, never read from the
  claimed field, which sits outside its own preimage (lines 1003-1009). The predecessor's own
  signatures are not verified here; callers verify the predecessor separately.
- The predecessor axis of the composite is **opt-in verifier hardening, off by default**.
  draft-pidlisnyi-aps-03 section 5.3.3 lines 1104-1105 STATES the prev relation and section
  5.6 line 1219 lists prev validation among a verifier's checks, neither with a BCP 14
  keyword, so neither statement requires a verifier to make the comparison. With the
  `predecessor` argument not passed, `predecessor_bound` is `not_checked` and every other
  field of the composite result is what it would be without the axis. Passed as `None`, the
  caller asked for a binding it could not supply the record for: the axis is
  `not_established`, the composite is `indeterminate`, and `predecessor_not_supplied` is in
  the errors.
- `tests/cross_impl/receipt-decision-composite-vectors.json` and its generator: 126 cases
  built from the pinned action-result-binding conformance chain, each carrying the TypeScript
  reference's own result object, replayed field for field against this implementation.

Both entry points are reachable under `agent_passport.receipt_core`, alongside the existing
ReceiptV1 surface, and not from the package root. The 4.0.0 reachability note below says
"there is no composite verifier here, so the decision-binding check exists in TypeScript
alone". That was true of 4.0.0 and is superseded by this section.

## 4.0.0 (2026-09-20)

Reconciles three surfaces against draft-pidlisnyi-aps-03: action references,
AuthorityDelegationV1 and ReceiptV1. Major, because previously accepted inputs can now
return `invalid`, `unsupported` or `indeterminate`, so a caller that branches on
verification state can observe different behaviour without changing its own code. This is
not a claim of complete draft-03 implementation, and it does not close the surface gap with
the TypeScript SDK. See the reachability section below.

### New

- **`compute_action_ref_v2`, `compute_payload_ref_v1` and the other entry points in `src/agent_passport/v2/action_reference/v2.py`** (profile `aps-action-ref-v2`): the draft-pidlisnyi-aps-03 section 4.1 native action reference. The existing `compute_action_ref` stays the pre-draft compatibility digest over a different preimage and is not relabelled as either draft-03 construction.
- **`compute_external_action_ref_v1`** (`src/agent_passport/external_action_ref.py`, label `action-ref-v1-jcs-sha256`): the section 4.2 external correlation form.
- **`verify_authority_delegation_chain`, `issue_authority_delegation`, `issue_sub_authority_delegation` and the rest of `src/agent_passport/v2/authority_delegation/`**: AuthorityDelegationV1, the draft-pidlisnyi-aps-03 section 3 delegated authority record, with chain verification, issuance that checks the parent before signing a child, strict wire parsing and an in-memory spend ledger. Distinct from the legacy delegation functions, which are unchanged.
- `verify_receipt_v1_serialized`, which rejects duplicate object members. `json.loads`
  followed by `verify_receipt_v1` cannot detect them, because by then the later member has
  already overwritten the earlier one.

### Corrected

- The 2.8.0 entry below described `compute_action_ref` as the native APS `action_ref` of draft-pidlisnyi-aps-03 section 4.1. That was wrong: `compute_action_ref` is a pre-draft-03 compatibility digest, unchanged by this release, and must not be presented as an `action_ref` or as `action-ref-v1-jcs-sha256`.

### Breaking

- Receipt verification applies the section 5.3 stage rules. `verify_receipt_v1` and
  `verify_receipt_v1_serialized` return `invalid` for a record that breaks its own stage and
  `unsupported` for a `receipt_type` outside section 5.3.
- `delegation_ref` must be `sha256:` followed by 64 lowercase hex. A bare digest, accepted
  before by both the envelope validator and the issuer, is refused.
- Only required signatures decide the aggregate receipt state. A non-required signature
  appended by a third party can no longer flip a conforming receipt. Because signatures sit
  outside the `receipt_id` preimage, such an append does not change `receipt_id`. A
  malformed signature descriptor still makes the envelope invalid.
- Key resolution is reported on its own axis, with unsupported scheme as `unsupported` and
  not found, ambiguous, malformed key material and unreachable resolution as distinct
  `indeterminate` outcomes. Malformed key material no longer falls through to
  `signature_invalid`.
- The serialized verifier's own nesting-depth and wire-size ceilings return `indeterminate`
  with the code `RESOURCE_LIMIT` rather than `invalid` with `parse_error`. Malformed input
  stays `invalid` with `parse_error`, and an unusable limit argument remains an argument
  error.
- An artifact under another envelope profile is `unsupported`.
- A receipt string containing a Unicode noncharacter is refused. Section 4.1 also rejects
  Unicode noncharacters, and an empty `scope_required` is refused unless applicable profile
  context permits it.
- Trust and revocation callbacks receive a copy of the record rather than the caller's own
  dict, so a callback cannot mutate what later steps inspect and cannot identity-compare
  against what it passed in.
- A reservation made again after cancellation is a fresh reservation and rechecks its
  limits. Container subclasses, inexact types, cycles and integers beyond binary64 range are
  `SCHEMA_INVALID` on the verifier and issuer paths, and the ledger rejects invalid
  reservation input with `CONFLICT`.

### Fixed

- Year 0000 is accepted and the timestamp check no longer depends on the platform's
  `strftime` zero-padding, which closes a silent divergence from the TypeScript SDK.
- The SDK's own recursive walks over receipt content, strict I-JSON validation,
  canonicalization, the snapshot copy and the depth walk, are iterative, so deep input no
  longer escapes as `RecursionError`. On interpreters whose JSON decoder still recurses,
  decoder recursion exhaustion is reported as `indeterminate` with `RESOURCE_LIMIT` rather
  than as malformed input. The decoder itself is not made iterative.

### Unchanged

Timestamp handling accepts second 60 only at 23:59 on the last calendar day of a month, and
no leap-second table is consulted. The new action-reference paths match the TypeScript
implementation byte for byte on the shared vectors.

### What a valid result does not establish

A structurally valid stage result does not bind `delegation_ref` to a supplied chain,
recompute `action_ref`, resolve `prev`, recompute `effect_ref`, or perform section 5.5
evidence resolution.

### Public reachability, and where this differs from the TypeScript SDK

`agent_passport.v2.authority_delegation` exports 36 names and the package root re-exports
21, including both issuers, the verifiers, the parser, the ledger and `compare_authority`.
The action-reference constructions are root-exported. The ReceiptV1 surface is not:
`verify_receipt_v1`, `verify_receipt_v1_serialized` and the stage validator are reachable
under `agent_passport.receipt_core` only. There is no composite verifier here, so the
decision-binding check exists in TypeScript alone.


## 3.0.1 (2026-09-04)

Documentation only. The README published with 3.0.0 still described the package as 2.11.0 and omitted the Rust SDK; the package page now states the current family. No code change.

## 3.0.0 (2026-09-04)

Security release. The full cross-SDK account, including the affected version
ranges and the severity assessment, is in the security advisory for this
release. [The verification boundary](https://github.com/aeoess/agent-passport-python/blob/main/docs/verification-boundary.md)
names the verification APIs that establish authority from caller-supplied trust,
and the trust input each takes.

Several exported verification functions returned a successful verification
result (`valid: true` or an equivalent) without establishing all of the trust,
linkage, context and temporal conditions the result implied. In the affected
paths the verification key came from the artifact itself, the claimed identity
was not bound to the key that signed, chained artifacts were not linked to the
artifacts they claimed to derive from, or an unreadable timestamp compared as
neither expired nor stale. A relying party that treated those results as
authorization could accept an artifact an attacker produced with keys the
attacker controls.

This release changes what the affected functions establish. Trust anchors and
the expected challenge are caller-supplied where the result claims authority;
the presentation domain is signed, and a caller that uses domain as a
relying-party boundary compares it through the expected-domain option.
Identities are bound to keys. Chains are linked. Invalid time fails closed.
Creators refuse to mint artifacts their own verifiers reject. The affected
verifiers return a rejection on a malformed timestamp or a missing chain
instead of raising; creators and `assign_role` raise.

### Affected surfaces

One row per exported surface and defect class; a surface with two defect classes
appears twice. Copied from the security advisory for this release.

| exported name | module path | defect class | consumer change |
|---|---|---|---|
| `verify_passport` | src/agent_passport/passport.py | authority false accept | Two keyword-only params with defaults, so positional calls still bind, but the answer changes: a self-signed passport now returns valid False. Callers establishing issuer authority pass trusted_issuers; allow_self_signed=True explicitly accepts a self-signed passport and is appropriate only where issuer authority is not being established.|
| `assign_role` | src/agent_passport/intent.py | authority false accept | Two keyword-only params added. A call that omits both now raises ValueError instead of returning a role assignment |
| `commerce_preflight` | src/agent_passport/commerce.py | authority false accept | Two keyword-only params added; positional calls still bind. Calls that previously reported permitted True on a self-signed passport now report permitted False until trust is supplied |
| `commerce_with_intent` | src/agent_passport/integration.py | authority false accept | Two keyword-only params added after evaluator_private_key; positional calls still bind but a self-signed passport no longer yields a permitted preflight |
| `verify_verifiable_credential` | src/agent_passport/vc_wrapper.py | artifact key used as trust root | Result gains key_authority (verified/rejected/unresolved), issuer_did (empty unless binding succeeded) and proof_of_possession. Non-self-certifying issuers such as did:web now return unresolved and valid False. Credentials issued under the old body-only preimage no longer verify |
| `verify_verifiable_presentation` | src/agent_passport/vc_wrapper.py | identity not bound to key | Signature widens to (vp, expected_challenge=None, expected_domain=None); a one-argument call now returns valid False. Result gains key_authority, holder_did, proof_of_possession, challenge and domain. Presentations made under the old preimage no longer verify |
| `create_verifiable_presentation` | src/agent_passport/vc_wrapper.py | identity not bound to key | Signature gains a required challenge and an optional domain; omitting challenge raises TypeError: omitting it raises TypeError instead of minting an artifact. Presentations it emits do not verify against a before the fixed version verifier and vice versa |
| `passport_to_verifiable_credential` | src/agent_passport/vc_wrapper.py | identity not bound to key | No signature change. The artifact changes: credentials it emits are a new preimage that before the fixed version verifiers reject, and credentials it produced before the fixed version no longer verify. The signed preimage is identical in the TypeScript and Python SDKs. |
| `fulfill_credential_request` | src/agent_passport/credential_request.py | identity not bound to key | No signature change. Responses it emits are a new preimage: before the fixed version verify_credential_response rejects them and responses produced before the fixed version no longer verify |
| `verify_credential_response` | src/agent_passport/credential_request.py | identity not bound to key | Signature unchanged, but a call that omits expected_challenge now returns valid False. Result gains holder_did, empty unless the binding held. Non-self-certifying holders and issuers now fail as unresolved |
| `verify_policy_receipt` | src/agent_passport/policy.py | chain not linked | Third parameter chain added. A two-argument call now returns valid False with chain_verified False, not an exception. Result gains envelope_signature_valid and chain_verified. Callers that only want envelope integrity should move to verify_policy_receipt_envelope |
| `verify_policy_receipt_envelope` | src/agent_passport/policy.py | chain not linked | New export added to src/agent_passport/__init__.py. A caller that does not need the chain checked must now name this function; it cannot get that answer by accident from verify_policy_receipt |
| `verify_policy_decision` | src/agent_passport/policy.py | invalid time fails open | An expiresAt outside strict RFC 3339 (zone-less, space separator, hour 24, leap second, lowercase t/z, sub-millisecond over 9 digits) now yields valid False with a stated reason instead of an exception or a silent pass |
| `verify_attestation` | src/agent_passport/values.py | invalid time fails open | Returns valid False with a reason instead of raising. Attestations carrying a non-RFC-3339 expiresAt no longer verify |
| `negotiate_common_ground` | src/agent_passport/values.py | invalid time fails open | Returns a refusal reason instead of raising. Two agents whose attestations carry non-RFC-3339 expiries no longer reach common ground |
| `FloorValidatorV1.evaluate` | src/agent_passport/policy.py | invalid time fails open | Delegations carrying a non-RFC-3339 expiresAt now fail Auditability under whatever enforcement mode is configured (inline, audit or warn). evaluate_intent and request_action, which call the validator, inherit the new verdict |
| `verify_attribution_consent` | src/agent_passport/v2/attribution_consent/verify.py | artifact key used as trust root | Signature unchanged. Behavioural break: receipts whose parties are named by opaque identifiers (agent:citer, did:web:...) no longer verify. Reissuance under did:key is the migration. The signed preimage did not move: both the did:key and the opaque-identifier fixtures still hash to the same id |
| `check_artifact_citations` | src/agent_passport/v2/attribution_consent/verify.py | artifact key used as trust root | Signature unchanged. Artifacts citing receipts with opaque party identifiers stop passing the gate; same reissuance migration as verify_attribution_consent |
| `compute_action_ref` | src/agent_passport/action_ref.py | invalid time fails open | The two spellings now raise ValueError instead of returning a hash. Every input that produced an address before still produces the same one: one instant written six ways still hashes to f00d48a5c11c16a535d93c4b2daeed15fefbb5943ac3b4ca58698d2c8bf918f5, and the shared cross-language vectors are unaffected. One divergence remains by decision: lowercase t/z, which TypeScript accepts and Python refuses |

### Migration

| package | old call shape | new call shape | unmigrated call | artifacts reissued |
|---|---|---|---|---|
| python | `verify_passport(signed_passport) returned valid True for a self-minted passport` | `verify_passport(signed_passport, trusted_issuers=[...]) or verify_passport(signed_passport, allow_self_signed=True)` | valid false: the additions are keyword-only with defaults so every positional call still binds; result carries issuer_trust_checked and self_signed_accepted | no: no artifact shape changes; issuer_signature_preimage is exported so an issuer can countersign an existing passport |
| python | `assign_role(signed_passport, role, autonomy_level, scope, assigner_private_key, assigner_public_key, department=None)` | `same call plus trusted_issuers=[...] or allow_self_signed=True` | exception: raises ValueError, as it already did for an invalid passport | no: no artifact changes |
| python | `commerce_preflight(signed_passport, delegation, merchant_name, estimated_total)` | `same call plus trusted_issuers=[...] or allow_self_signed=True` | valid false: Gate 1 reports passed False, which makes permitted False | no: no artifact changes |
| python | `commerce_with_intent(..., evaluator_private_key) with no trust input` | `same call plus trusted_issuers=[...] or allow_self_signed=True` | valid false: it threads the trust input to the preflight, so permitted is False without one | no: no artifact changes |
| python | `verify_attribution_consent(receipt) accepted citer and cited_principal as opaque identifiers with any key beside them` | `same call, with each party named by a did:key or a multibase did:aps that commits to the key beside it` | valid false: reason is 'unresolved' or 'rejected'; check_artifact_citations inherits it | yes: receipts naming parties by opaque identifiers must be reissued under did:key; both fixtures still hash to the same id, so the signed preimage did not move |
| python | `compute_action_ref(..., timestamp) accepted the space separator '2026-04-05 03:39:31Z' and rolled '2026-04-05T24:00:00Z' into the next day` | `compute_action_ref(..., timestamp) with the uppercase T separator and an hour of 23 or less` | exception: ValueError naming the rule, raised from _normalize_timestamp | no: every input that produced an address still produces the same one, and one instant written six ways still hashes to f00d48a5c11c16a535d93c4b2daeed15fefbb5943ac3b4ca58698d2c8bf918f5 |
| python | `verify_verifiable_credential(vc) and verify_verifiable_presentation(vp) over a proof signed on the body only, with created written by datetime.isoformat` | `same calls; the proof configuration is inside the signed bytes and created is written by format_rfc3339` | valid false: there is no dual-verification path, so a before the fixed version artifact does not verify | yes: every Python-minted VC and VP issued before the fixed version must be reissued |
| python | `verify_verifiable_presentation(vp) and verify_credential_response(vp) with no expected challenge (the comparison was skipped entirely)` | `verify_verifiable_presentation(vp, expected_challenge) and verify_credential_response(vp, expected_challenge)` | valid false: the parameters still default to None so the call binds, but a presentation verified against no challenge is refused | no reissue for the expected-challenge change itself; credential responses minted under the previous signed preimage must be reissued (see the fulfill_credential_request row) |
| python | `create_verifiable_presentation(credentials, holder_private_key) minted a presentation carrying no challenge` | `create_verifiable_presentation(credentials, holder_private_key, challenge, domain=None)` | exception: TypeError; creators raise where verifiers return | yes: a challenge-less presentation is one this package's own verifier always rejects |
| python | `verify_policy_receipt(policy_receipt, verifier_public_key) returned valid True with three fake inner signature strings` | `verify_policy_receipt(policy_receipt, verifier_public_key, chain: PolicyReceiptChainInputs), or verify_policy_receipt_envelope for the envelope-only check` | valid false: chain is still Optional with a None default so the call binds; the result carries chain_verified False and no exception is raised | no: receipts unchanged; the caller must present the intent, decision and action receipt plus an anchor for each |
| python | `FloorValidatorV1 swallowed an unreadable expiresAt and produced no Auditability finding; verify_policy_decision, verify_attestation, negotiate_common_ground, verify_verifiable_credential and verify_credential_response parsed with no guard at all` | `all six route through _time.parse_rfc3339 and report the refusal in the vocabulary the site already uses` | valid false: a present-but-unreadable expiresAt now produces a finding where it produced none; an absent or empty expiresAt still means no stated end | yes: artifacts whose expiresAt is present but unreadable; every spelling this package emits is inside the grammar, so conforming artifacts are unaffected |

## 2.11.0 (2026-08-20)

### Fixed / Security

- **`canonicalize_jcs` serializes `int` through the RFC 8785 number domain, so canonical bytes agree with the TypeScript and Go SDKs.** RFC 8785 section 3.2.2.3 defines the JCS number domain as IEEE 754 binary64 serialized under ECMAScript `Number::toString`. Python's `int` is arbitrary precision and the previous code emitted it verbatim, keeping a decimal spelling the double does not have: 2^60 emitted as `1152921504606846976` where the binary64 serialization is `1152921504606847000`. Where those two spellings differ, a digest or signature computed over `canonicalize_jcs` output disagreed with the same object canonicalized by the TypeScript or Go SDK, both of which already emitted the binary64 form, so such an artifact verified in this SDK and failed for a peer that recomputed the bytes through the RFC 8785 number domain. The `int` branch now widens to binary64 first and takes the same path a `float` takes. An integer beyond the binary64 range raises `JCSCanonicalizationError` with reason `number_out_of_double_range`, since RFC 8785 defines no representation for it. The generic `canonicalize` is untouched.

### Behavior change

- **Canonical JCS bytes move for integers whose decimal spelling differs from the binary64 serialization of the same value, which is why the minor version moves rather than the patch.** Not every large integer is affected. `9007199254740992` and `9007199254740994` are unchanged, while `9007199254740993` now emits `9007199254740992`, 2^60 emits `1152921504606847000` and 2^68 emits `295147905179352830000`. A signature made by 2.10.0 or earlier over an affected value does not verify against bytes recomputed by 2.11.0. Those artifacts were already unverifiable outside Python for the reason above, so this release makes the failure visible in one place instead of leaving it to the peer. The pinned canonicalization baselines are unchanged and the generic `canonicalize` keeps its previous output.
- **Signing and new-write boundaries refuse integer-valued numbers outside the interoperable IEEE 754 range.** RFC 7493 section 2.2 says an I-JSON sender cannot expect a receiver to treat an integer whose absolute value exceeds 9007199254740991 as an exact value, and recommends encoding such a value as a JSON string. A new-write value carrying such an integer now raises `UnsafeIntegerError`, a `ValueError` subclass carrying the JSON path of the offending member. Only integer-valued numbers are bounded. Verification and recompute paths keep calling the unrestricted canonicalizer, so this rule refuses nothing on the verification side: where a pre-2.11.0 artifact stops verifying, the cause is the canonicalization change above and not this rule. The guard is internal: no write-policy name is exported from `agent_passport`, and `write_policy.py` ships in the wheel for internal use. One limit worth knowing at the call site: a documented set of exported helpers both mint and re-derive a value through the same function and stay unrestricted, so that re-derivation of a value minted before the rule keeps working. Minting an unsafe integer through one of those helpers is not covered. Scope, the call-site inventory and the proofs are in #6.

## 2.10.0 (2026-07-26)

### Added
- **receipt-core v1 module.** The Python port of the receipt-core module lands with the same shapes and the same canonical bytes as the TypeScript SDK.

### Behavior change
- **`scope_required` now rejects duplicate elements after NFC normalization.** Section 4.1 defines `scope_required` as a duplicate-free array. The canonicalizer normalized and sorted but neither deduplicated nor rejected, so `["a","a"]` and `["a"]` produced different action references while the specification admits one form. `canonicalize_scope_required` now raises `DuplicateScopeRequiredError`, a `ValueError` subclass carrying category `invalid_scope_required` and reason `duplicate_scope_required`, before any identity is computed. Detection runs after NFC, so two spellings that collide only under normalization also reject. Input that previously produced an `action_ref` now raises, and only duplicated input is affected.

### Fixed
- **`decision_ref` construction now normalizes before hashing.** The decision reference was computed over unnormalized input on one path, so two byte-different encodings of the same decision could produce different references.
- **`valid_until` is now bound in `CoreDecisionOutputV1`.** The field was carried but not covered by the signed material, so a validity window could be altered without invalidating the signature.

## 2.9.0 (2026-07-13)

### Fixed / Security
- **JCS canonicalization now rejects lone surrogates (RFC 8785).** `canonicalize` and `canonicalize_jcs` previously accepted strings carrying an unpaired UTF-16 surrogate and let it reach the canonical output, so input that is not valid Unicode could be signed and could diverge across implementations. It is now rejected before hashing with a stable error, matching the TS and Go SDKs.

### Behavior change
- Input that was previously accepted is now rejected. A value carrying a lone surrogate on a canonicalization or signing path raises instead of producing a signature. Callers that never emit unpaired surrogates see no change. This is why the minor version moves rather than the patch.

## 2.8.1 (2026-07-10)

### Fixed / Security (audit 2026-07-10)
- **Expiry fail-open on Python < 3.11 (authority).** `verify_delegation`, `is_expired`, and `sub_delegate` parsed `expiresAt` with `datetime.fromisoformat`, which did not accept a trailing `Z` until 3.11, and swallowed the resulting error so the expiry check silently no-opped on the declared minimum interpreter. Added `_time.parse_iso_utc` (correct on 3.9+) and made an unparseable expiry fail closed (treated as expired), not open.
- **Canonical-byte divergence from RFC 8785 / the TS SDK (cross-language signatures).** `canonicalize` and `canonicalize_jcs` serialized floats with Python `repr`/`json.dumps` (e.g. `1e21`, `1e-07`, `1e-06`) and sorted object keys by code point. Both now use `_es_number` (ECMAScript `Number::toString`, validated byte-identical to Node over 20k values) and a UTF-16 code-unit key sort, matching the TS reference on floats and astral-plane keys. The JCS non-container fallback also now sets `ensure_ascii=False`.
- **action_ref naive-timestamp divergence.** `compute_action_ref` assumed UTC for offsetless timestamps while the TS reference parses them as local time; it now rejects naive timestamps (spec 4.1 requires an explicit `Z`/offset) and formats the year with explicit zero-padding.

## 2.8.0 (2026-07-10)

### Added
- **`compute_action_ref(agent_id, action_type, scope_required, timestamp)`** (`action_ref.py`): the native APS action_ref of draft-pidlisnyi-aps-03 section 4.1, SHA-256 over the strict RFC 8785 canonicalization of `{agentId, actionType, scopeRequired, timestamp}` with NFC per scope string and a Unicode code-point sort of the scope list on a copy. **Cross-language byte parity with the TS SDK (npm v3.3.0) and the Go implementation**, pinned by the shared vectors in `tests/cross_impl/actionref-canonical-vectors.json` (4 of 4 byte-identical hex). Distinct from `compute_attribution_action_ref` (attribution preimage with nonce and params); that function is untouched.

## 2.7.0 (2026-07-04)

- Release/version bump only: synced the package version and the description's cross-language parity line to the current TS SDK. No functional or byte-level changes to the protocol primitives (README.md, pyproject.toml).

## 2.6.0 (2026-07-04)

### Added
- **`trace_beneficiary(receipt, delegations, beneficiary_map)`** (`attribution.py`) and **`verify_action_receipt(receipt, agent_public_key)`** (`delegation.py`): parity with the TypeScript beneficiary-verified-honesty change. `verified` is a real cryptographic check (the receipt signature verifies at the chain tail via `verify_action_receipt`, and every delegation in the lineage verifies via `verify_delegation`), not a lookup; a new `resolved` field carries the lookup-only semantics (lineage maps to known records and a known beneficiary, no cryptographic claim). The reported lineage is deterministic (valid-first, then `delegationId`) with the tail hop tied to `receipt.delegationId`. A forged or tampered chain reports `resolved` true but `verified` false. Reuses the existing Ed25519 verifiers; no crypto reimplemented.
- **APS Composition Check Receipt v0** (`v2/composition_check/`): port of the carrier and stateless ANCHOR verifier `verify_composition_check`. Verifies the signature, the `(chain_hash, action_ref, context_hash)` binding, freshness (caller-supplied `now_ms`, fails closed on a non-finite value), well-formedness, and attestor trust for the opaque `policy_profile_ids`; surfaces `independence_is_second_anchor` corroborated from the trust context (`registered_by_operator` is False) and gated on `anchor_verified`. No policy grammar, no detection logic, no aggregate, and no `safe` boolean: detection stays in the private gateway. `result_per_check` is a fixed enum (`pass | fail | indeterminate | not_checked`). **Cross-language signature compatible with the TS SDK**: a receipt signed by either SDK verifies under the other (the canonical signing bytes are `f"APS-COMPCHECK-V0.{canonicalize_jcs(receipt-without-signature)}"`, byte-matching the TS `canonicalizeJCS`). Conformance vectors in `conformance/composition-check/v0/` are the TS-signed vectors, verified here. Additive: new functions and a new module, no existing type changed.

## 2.5.0

### Added
- **`record_spend(commerce_delegation, amount)`** (`commerce.py`): the stateless write primitive for
  commerce spend. It returns a new CommerceDelegation with `spentAmount` incremented, refusing a
  non-finite or negative amount and refusing a spend that would exceed `spendLimit`. It pairs with the
  spend gate: check before a purchase, record after, persist the returned object. The SDK does not
  persist spend between calls; cumulative enforcement across purchases is the caller's or the gateway's
  responsibility. This is the parity primitive for the TypeScript `recordSpend`.

### Fixed / Security
- **Spend-accumulation no-op closed.** `spentAmount` was read by the spend check but never written, so a
  single delegation passed unlimited purchases against its cap. `record_spend` is the write half; the
  signed core delegation's `spentAmount` is documented as an immutable spend-at-issue value (always 0),
  not a running total.
- **`sub_delegate` now verifies the parent and narrows correctly** (`delegation.py`). It verifies the
  parent before minting a child, caps the child's expiry to the parent's, rejects a child whose spend
  exceeds the parent's remaining budget, and computes depth-exceeded rather than hardcoding it false.
- **`commerce_preflight` spend gate denies a currency mismatch** (`commerce.py`). The gate compared
  amounts without checking currency, so a purchase in one currency passed a budget denominated in
  another (the SDK does no conversion). A declared currency mismatch is now denied; an absent currency
  on either side stays unconstrained.

### Behavior changes (operations previously permitted now fail closed)
- A cross-currency commerce spend (purchase currency differs from the budget currency) is now denied
  instead of passing.
- A sub-delegation that widens authority (spend above the parent remaining, expiry beyond the parent,
  or depth past the limit) or that derives from a parent that does not verify is now rejected instead of
  produced.
