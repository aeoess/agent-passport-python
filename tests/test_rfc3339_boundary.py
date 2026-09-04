# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""A timestamp that arrives on an artifact is attacker-controlled input.

Three contracts.

FAIL CLOSED. ``_check_auditability`` wrapped its expiry parse in
``except (ValueError, TypeError): pass``. An expired delegation whose
``expiresAt`` is unparseable therefore reported Auditability as passing, so
writing garbage into the field was strictly better for an attacker than
writing an honest future date.

VERIFIERS RETURN, THEY DO NOT RAISE. The same parse elsewhere had no guard at
all, so a malformed ``expiresAt`` propagated a ValueError out of a function
whose contract is a result dict. A relying party that wraps a verifier in
``try/except`` to stay up converts every one of these into whatever its
handler decides, and a relying party that does not wrap it crashes on input an
attacker chooses.

The parser these sites are moved onto has its own contract tests in
test_rfc3339_parse.py; this file is about what the call sites do with a refusal.
"""

import pytest

from agent_passport.canonical import canonicalize_for_write
from agent_passport.crypto import generate_key_pair, sign
from agent_passport.policy import FloorValidatorV1, verify_policy_decision
from agent_passport.values import verify_attestation
from agent_passport.vc_wrapper import verify_verifiable_credential

# A value that is not a date, in several shapes an artifact can carry.
UNPARSEABLE = ["not-a-date", "2026-13-45T99:99:99Z", "tomorrow", "0", "2026-01-01T00:00:00"]


def _ctx(expires_at):
    """A delegation that is expired if its expiresAt can be read at all."""
    return {
        "agentRegistered": True,
        "agentAttestationValid": True,
        "delegation": {
            "scope": ["data:read"],
            "expiresAt": expires_at,
            "currentDepth": 0,
            "maxDepth": 3,
        },
    }


def _intent():
    return {"action": {"type": "read", "scopeRequired": "data:read"}}


def _finding(result, principle_id):
    for ev in result.get("principlesEvaluated", []):
        if ev.get("principleId") == principle_id:
            return ev
    raise AssertionError(f"{principle_id} not evaluated: {result}")


class TestAuditabilityFailsClosed:
    def test_an_honest_expired_delegation_fails_auditability(self):
        """The baseline the next test is measured against."""
        result = FloorValidatorV1().evaluate(_intent(), _ctx("2020-01-01T00:00:00Z"))
        assert _finding(result, "F-005")["status"] == "fail"

    @pytest.mark.parametrize("expires_at", UNPARSEABLE)
    def test_an_unreadable_expiry_does_not_pass_auditability(self, expires_at):
        """Garbage in expiresAt must not be worth more than an honest date."""
        result = FloorValidatorV1().evaluate(_intent(), _ctx(expires_at))
        assert _finding(result, "F-005")["status"] == "fail"

    @pytest.mark.parametrize("expires_at", [12345, 1.5, {"at": "2020-01-01T00:00:00Z"}, ["2020-01-01T00:00:00Z"]])
    def test_an_expiry_of_the_wrong_type_does_not_pass_auditability(self, expires_at):
        result = FloorValidatorV1().evaluate(_intent(), _ctx(expires_at))
        assert _finding(result, "F-005")["status"] == "fail"

    @pytest.mark.parametrize("expires_at", ["", None])
    def test_an_absent_expiry_is_unbounded_not_unreadable(self, expires_at):
        """Unchanged behavior, pinned so the repair cannot quietly reinterpret
        "no expiry" as "bad expiry". A delegation that states no end is a
        design the package already makes elsewhere (passport.is_expired);
        turning it into a failure here is a different decision than F-04."""
        result = FloorValidatorV1().evaluate(_intent(), _ctx(expires_at))
        assert _finding(result, "F-005")["status"] == "pass"

    def test_a_valid_future_expiry_still_passes(self):
        result = FloorValidatorV1().evaluate(_intent(), _ctx("2099-01-01T00:00:00Z"))
        assert _finding(result, "F-005")["status"] == "pass"


class TestVerifiersReturnRatherThanRaise:
    """Each of these is reached with a signature that is already wrong, so the
    only question under test is whether the function returns or throws."""

    @pytest.mark.parametrize("bad", UNPARSEABLE)
    def test_verify_policy_decision_returns_a_result(self, bad):
        result = verify_policy_decision({
            "decisionId": "pdec_x", "intentId": "int_x", "evaluatorId": "ev",
            "evaluatorPublicKey": "00" * 32, "verdict": "permit",
            "expiresAt": bad, "signature": "00" * 64,
        })
        assert result["valid"] is False
        assert result["errors"]

    @pytest.mark.parametrize("bad", UNPARSEABLE[:4])
    def test_verify_attestation_returns_a_result(self, bad):
        result = verify_attestation({
            "attestationId": "att_x", "publicKey": "00" * 32,
            "expiresAt": bad, "signature": "00" * 64,
        })
        assert result["valid"] is False

    @pytest.mark.parametrize("bad", UNPARSEABLE[:4])
    def test_verify_verifiable_credential_returns_a_result(self, bad):
        issuer = generate_key_pair()
        body = {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "id": "urn:aps:credential:expiry", "type": ["VerifiableCredential"],
            "issuer": "did:key:z6MkFake", "issuanceDate": "2026-01-01T00:00:00.000Z",
            "expirationDate": bad,
            "credentialSubject": {"id": "did:example:s"},
        }
        vc = {**body, "proof": {
            "type": "Ed25519Signature2020", "created": "2026-01-01T00:00:00.000Z",
            "verificationMethod": "did:key:z6MkFake#key-1",
            "proofPurpose": "assertionMethod",
            "proofValue": sign(canonicalize_for_write(body), issuer["privateKey"]),
        }}
        result = verify_verifiable_credential(vc)
        assert result["valid"] is False


class TestTheSdkOwnEmissionsStillParse:
    """The strict parse tightened the accept-set, so the question this answers
    is whether it tightened it past what this SDK itself writes.

    Every expiry field here is produced by the package's own creators, which
    emit ``datetime.isoformat()``: a ``+00:00`` offset and six fractional
    digits, or no fractional digits at all when the microsecond happens to be
    zero. All three spellings are inside the accepted grammar, so no artifact
    that verified before this change stops verifying because of it.
    """

    def test_a_freshly_created_attestation_is_not_expired(self):
        from agent_passport._time import parse_rfc3339
        from agent_passport.values import attest_floor, verify_attestation
        signer = generate_key_pair()
        att = attest_floor(
            agent_id="agent-emit", public_key=signer["publicKey"],
            floor_version="1.0", extensions=[], private_key=signer["privateKey"],
        )
        assert parse_rfc3339(att["expiresAt"]).ok is True
        result = verify_attestation(att)
        assert not [e for e in result["errors"] if "xpire" in e or "nreadable" in e]

    @pytest.mark.parametrize("emitted", [
        "2026-09-04T04:13:13.314159+00:00",  # isoformat with microseconds
        "2026-09-04T04:13:13+00:00",         # isoformat, microsecond exactly zero
        "2026-09-04T04:13:13.314159Z",       # isoformat with the +00:00 swapped for Z
        "2026-09-04T04:13:13Z",              # the same, microsecond exactly zero
        "2026-09-04T04:13:13.314Z",          # format_rfc3339, the TS spelling
    ])
    def test_every_spelling_the_package_emits_is_accepted(self, emitted):
        from agent_passport._time import parse_rfc3339
        assert parse_rfc3339(emitted).ok is True

    def test_the_two_isoformat_spellings_name_the_same_instant(self):
        from agent_passport._time import parse_rfc3339
        a = parse_rfc3339("2026-09-04T04:13:13.314000+00:00")
        b = parse_rfc3339("2026-09-04T04:13:13.314Z")
        assert a.ms == b.ms


class TestNegotiationReturnsRatherThanRaises:
    def test_an_unreadable_attestation_expiry_is_a_reason_not_an_exception(self):
        from agent_passport.values import negotiate_common_ground
        result = negotiate_common_ground(
            {"agentId": "a"}, {"expiresAt": "not-a-date", "floorVersion": "1.0"},
            {"agentId": "b"}, {"expiresAt": "2099-01-01T00:00:00Z", "floorVersion": "1.0"},
        )
        assert any("unreadable" in r for r in result["incompatibilityReasons"])
        assert result["compatible"] is False

    def test_two_live_attestations_still_negotiate(self):
        from agent_passport.values import negotiate_common_ground
        result = negotiate_common_ground(
            {"agentId": "a"}, {"expiresAt": "2099-01-01T00:00:00Z", "floorVersion": "1.0"},
            {"agentId": "b"}, {"expiresAt": "2099-01-01T00:00:00Z", "floorVersion": "1.0"},
        )
        assert result["incompatibilityReasons"] == []
        assert result["compatible"] is True
