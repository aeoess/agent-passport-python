# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""APS write-policy admissibility corpus, Python half.

The corpus is a SEPARATE fixture from the RFC 8785 canonical-bytes vectors on purpose:
one vector must never carry two meanings. These five cases state admissibility only,
and the identical file ships in the TypeScript SDK so both languages are driven by the
same bytes. The same five were run through the Go SDK's receiptcore validator and it
agreed on all five, including the nested path.
"""

import hashlib
import json
import pathlib

import pytest

from agent_passport.canonical import (
    canonicalize,
    canonicalize_for_write,
    canonicalize_jcs,
    canonicalize_jcs_for_write,
)
from agent_passport.write_policy import UnsafeIntegerError

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "write-policy-admissibility-v1.json"
#: Recorded so a drift in the corpus is a visible test failure, not a silent reinterpretation.
FIXTURE_SHA256 = "97db9ed8bfeab81ac50187c161ea80953f5878092530ff3fa1912d7eeb985f67"


def test_fixture_bytes_are_pinned():
    digest = hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
    assert digest == FIXTURE_SHA256, (
        "the admissibility corpus changed; the TypeScript copy and the recorded Go run "
        "must be updated together or the three languages stop meaning the same thing"
    )


def _cases():
    data = json.loads(FIXTURE.read_text())
    return [(c["name"], c["value"], c["verdict"], c["path"]) for c in data["cases"]]


CASES = _cases()


@pytest.mark.parametrize("name,value,verdict,path", CASES, ids=[c[0] for c in CASES])
@pytest.mark.parametrize("writer", [canonicalize_for_write, canonicalize_jcs_for_write],
                         ids=["legacy_write", "jcs_write"])
def test_admissibility(writer, name, value, verdict, path):
    if verdict == "ACCEPT":
        writer(value)
        return
    with pytest.raises(UnsafeIntegerError) as exc:
        writer(value)
    assert str(exc.value).startswith(path + ":"), str(exc.value)
    assert exc.value.category == "invalid_number"
    assert exc.value.reason == "integer_exceeds_interoperable_range"


@pytest.mark.parametrize("name,value,verdict,path", CASES, ids=[c[0] for c in CASES])
@pytest.mark.parametrize("reader", [canonicalize, canonicalize_jcs], ids=["legacy_read", "jcs_read"])
def test_the_read_canonicalizers_accept_every_case(reader, name, value, verdict, path):
    """The rule is a WRITE rule.

    Both unrestricted canonicalizers must keep serializing every case, including the
    rejected ones, because that is what lets a verifier rebuild the preimage of an
    artifact signed before the rule existed.
    """
    reader(value)


@pytest.mark.parametrize("name,value,verdict,path", [c for c in CASES if c[2] == "ACCEPT"],
                         ids=[c[0] for c in CASES if c[2] == "ACCEPT"])
def test_accepted_cases_are_byte_identical_across_read_and_write(name, value, verdict, path):
    assert canonicalize_for_write(value) == canonicalize(value)
    assert canonicalize_jcs_for_write(value) == canonicalize_jcs(value)


# ── Verification regression, permanent ──────────────────────────────────────
#
# The highest-risk failure mode in this whole change is guarding a verification path,
# which would refuse artifacts that were signed before the rule existed and that verify
# today. These tests reconstruct such an artifact the way the pre-rule code did, by
# signing through the UNRESTRICTED canonicalizer, and then assert the shipped verifier
# still accepts it.
#
# principal.verify_endorsement and principal.verify_disclosure are named explicitly
# because an earlier classification pass wrongly listed both as signing paths. Guarding
# them would have broken every endorsement and disclosure already published.

from agent_passport.crypto import generate_key_pair, sign  # noqa: E402
from agent_passport.principal import (  # noqa: E402
    create_principal_identity,
    verify_endorsement,
    verify_disclosure,
)

UNSAFE = 9007199254740992


def _pre_rule_endorsement():
    """An endorsement minted the way the code did BEFORE the rule existed."""
    created = create_principal_identity("Pre Rule Principal", "individual")
    principal, keys = created["principal"], created["keyPair"]
    agent = generate_key_pair()
    payload = {
        "endorsementId": "endorsement-prerule",
        "principalId": principal["principalId"],
        "principalPublicKey": principal["publicKey"],
        "agentId": "did:aps:agent-prerule",
        "agentPublicKey": agent["publicKey"],
        # An out-of-range integer that the rule refuses on a NEW write today.
        "scope": ["read", UNSAFE],
        "relationship": "employee",
        "endorsedAt": "2026-01-01T00:00:00Z",
        "expiresAt": "2099-01-01T00:00:00Z",
    }
    signature = sign(canonicalize(payload), keys["privateKey"])
    return {**payload, "revoked": False, "signature": signature}


def test_pre_rule_endorsement_still_verifies():
    """verify_endorsement must accept an endorsement signed before the rule existed."""
    result = verify_endorsement(_pre_rule_endorsement())
    assert result["valid"] is True, result


def test_verify_endorsement_never_raises_on_the_number_rule():
    """A tampered endorsement must fail on the SIGNATURE, never by refusing the number.

    If verify_endorsement were ever switched to the write canonicalizer this would
    raise UnsafeIntegerError instead of returning a verdict.
    """
    endorsement = _pre_rule_endorsement()
    endorsement["scope"] = ["read", UNSAFE, {"nested": UNSAFE}]
    result = verify_endorsement(endorsement)
    assert result["valid"] is False
    assert isinstance(result, dict)


def test_pre_rule_disclosure_still_verifies():
    """verify_disclosure must accept a disclosure signed before the rule existed."""
    keys = generate_key_pair()
    revealed = {
        "did": f"did:aps:{keys['publicKey']}",
        "employeeCount": UNSAFE,
    }
    disclosure = {
        "disclosureId": "disclosure-prerule",
        "principalId": "principal-prerule",
        "level": "verified",
        "revealedFields": revealed,
        "disclosedAt": "2026-01-01T00:00:00Z",
        "proof": sign(canonicalize(revealed), keys["privateKey"]),
    }
    result = verify_disclosure(disclosure)
    assert result["valid"] is True, result


# ── Tuple bypass, closed 2026-08-19 ─────────────────────────────────────────
#
# A tuple falls through every guarded branch of both write canonicalizers to the
# terminal json.dumps fallback. Before the fix it was emitted unchecked, so an
# out-of-range integer inside a tuple could be signed.
#
# The fix validates at that fallback but still EMITS through it, because the read twin
# serializes a tuple the same way. Recursing instead would have emitted "[1,2]" where
# the read twin emits "[1, 2]", and a signed artifact would then fail verification.

def test_tuple_cannot_smuggle_an_unsafe_integer_past_the_write_rule():
    for writer in (canonicalize_for_write, canonicalize_jcs_for_write):
        with pytest.raises(UnsafeIntegerError) as exc:
            writer({"v": (UNSAFE,)})
        assert str(exc.value).startswith("$.v[0]:"), str(exc.value)


def test_tuple_bytes_are_unchanged_between_the_read_and_write_twins():
    """The bypass fix must not move a byte for a tuple the rule accepts."""
    safe = {"v": (1, 2)}
    assert canonicalize_for_write(safe) == canonicalize(safe)
    assert canonicalize_jcs_for_write(safe) == canonicalize_jcs(safe)


def test_the_read_twins_still_accept_a_tuple_carrying_an_unsafe_integer():
    """Historical bytes stay reproducible: the rule is write-only, tuples included."""
    canonicalize({"v": (UNSAFE,)})
    canonicalize_jcs({"v": (UNSAFE,)})
