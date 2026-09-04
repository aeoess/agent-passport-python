# Verification boundary

Verification APIs fall into two categories: authority-aware verification, where caller-supplied trust or expected context is part of the decision, and integrity verification, where an artifact is checked against information carried by that artifact. An integrity result does not authenticate the signer as authorized for a relying party. Applications making authorization decisions should use APIs that accept the required trust anchors or expected context.

## Authority-aware surfaces in this SDK

- **Passport verification.** `verify_passport` establishes issuer authority only with a trusted-issuer input: `trusted_issuers`. The self-signed opt-in `allow_self_signed` marks the result integrity-only and is not a substitute for issuer trust in an authorization gate. `assign_role`, `commerce_preflight` and `commerce_with_intent` take the same input and pass it through.
- **Credential and presentation verification.** `verify_verifiable_credential`, `verify_verifiable_presentation` and `verify_credential_response` bind the proof key to the identity the document claims. Presentations require a challenge at creation and the expected challenge at verification (`expected_challenge`); the domain is signed, and a caller that relies on domain separation supplies `expected_domain` to have it compared. The verifiers resolve `did:key` and the multibase `did:aps` form without an external resolver; other issuer or holder identifier methods are unresolved by this release and fail closed.
- **Policy receipt chain verification.** `verify_policy_receipt` takes the chain it verifies, `PolicyReceiptChainInputs`. `verify_policy_receipt_envelope` is the envelope-only integrity check and must be named to get that answer.
- **Attribution consent verification.** `verify_attribution_consent` and `check_artifact_citations` require each party to be named by a self-certifying identifier that commits to the key beside it.

Artifact timestamps at a verification boundary must be readable RFC 3339 instants with an explicit offset or `Z`.
