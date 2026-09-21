"""Verify a ReceiptV1 together with the decision it references, section 5.6.

Parity port of the TypeScript reference `src/v2/receipt-core/composite.ts`. Its own module
for the same reason: this is the only surface here that holds two artifacts at once, and
the stage layer judges one record against its own section 5.3 rules with no second artifact
in hand.

Nothing here recomputes a digest or canonicalizes anything of its own. The reference
binding runs through build_decision_ref_v1, the same builder that produced the value, and
the output comparison through strict_jcs, so a divergence between this module and the
issuing path is not possible.
"""

from __future__ import annotations

from .decision_ref import build_decision_ref_v1, validate_core_decision_output_v1
from .jcs import strict_jcs
from .predecessor import verify_receipt_predecessor_v1
from .receipt import _is_exact_utc_milliseconds, verify_receipt_v1
from .stage import _utc_ms_key

# The opt-in marker for the predecessor axis. The TypeScript reference reads own-property
# presence on its options object, which Python has no equivalent of for a keyword argument:
# there, `predecessor` absent and `predecessor: undefined` are two different states, and
# collapsing them is exactly what that reference refuses to do. A module-private sentinel
# as the default reproduces the distinction: the argument not passed leaves this object in
# place, and any value the caller writes, None included, displaces it.
#
# Private on purpose. A caller cannot name it, so the only way to reach the not-checked
# state is to omit the argument, which is the same thing as omitting the property.
_PREDECESSOR_NOT_PASSED = object()


def _is_later_utc_millisecond(later: str, earlier: str) -> bool:
    """Instant comparison of two already-validated exact-UTC-millisecond strings, through
    stage.py's own ordering key rather than a second implementation of it. Never a string
    comparison: the draft fixes instants, not lexical order."""
    return _utc_ms_key(later) > _utc_ms_key(earlier)


def verify_receipt_with_decision_v1(
    receipt,
    decision,
    resolve_key,
    *,
    expected_receipt_type=None,
    boundary_identity=None,
    predecessor=_PREDECESSOR_NOT_PASSED,
) -> dict:
    """Verify a receipt together with the decision it references.

    Receipt verification establishes the integrity and semantics represented by the
    receipt. It does not authorize dispatch, consume receipt_id, enforce single-use,
    recheck revocation or time at dispatch, or reserve spend. Those obligations belong to
    the enforcement boundary.

    `decision` is the decision material a verifier must hold to bind a decision to a
    receipt: a mapping with authority_state, policy_input, decision_context and
    decision_output. The decision OUTPUT alone is not enough, since that is the obvious
    expectation: receipt["decision_ref"] is a digest over the whole DecisionRefInputV1,
    which is the action reference plus the four component digests, and the output
    contributes only one of those components. action_ref is deliberately not a member: it
    is taken from the receipt, so a decision built for a different action cannot bind and
    the caller cannot quietly supply an action_ref that disagrees with the receipt it is
    checking.

    Seven stages, each with its own error code:

      1. `receipt_invalid`  structural and cryptographic verification, delegated unchanged
         to verify_receipt_v1. The full sub-result is returned under `receipt` so the caller
         keeps the per-signature detail. A sub-result that is unsupported or indeterminate
         rather than invalid carries its own status through, so an unresolvable signing key
         does not come back as a composite failure.
      2. `stage_invalid`  the section 5.3 rules for this record's own receipt_type, which
         verify_receipt_v1 runs itself and returns, so the two are not evaluated twice and
         cannot disagree. Which of the checks below apply is decided here and never by the
         caller.
      3. `decision_ref_absent`  decision_ref is conditional on a ReceiptV1, so a receipt
         that carries none cannot be checked against a decision. Passing a decision for such
         a receipt is an error, never a pass: silently succeeding would report a relation
         that was never examined.
      4. `decision_ref_mismatch`  the reference binding. The decision digest is recomputed
         through build_decision_ref_v1, the same builder that produced it, including the
         normalize-before-hash step, and must equal receipt["decision_ref"] exactly. Without
         this a receipt for decision A could be checked against an unrelated decision B
         chosen for its convenient valid_until. The supplied output is validated exactly as
         received first, under `decision_input_invalid`: the builder normalizes before
         hashing, which is right for an issuer building a value it is about to sign and
         wrong here, since it would let ["b","a","a"] bind to the digest of ["a","b"].
      5. `decision_output_mismatch`  for a policy-decision record, receipt["result"] must be
         the exact CoreDecisionOutputV1 the decision carries (section 5.4 lines 1183-1184),
         compared as canonical bytes. The digest binding alone did not establish this: the
         decision_ref commits to a digest of the output, and nothing compared that output
         with the result the receipt itself carries and signs.
      6. `predecessor_not_bound`  OPTIONAL and off by default. Only when the caller opts in,
         the section 5.3.3 prev binding for an action-result record, delegated unchanged to
         verify_receipt_predecessor_v1. This is OPT-IN HARDENING: the draft STATES that prev
         is the consumed policy-decision receipt_id (lines 1104-1105) and lists prev
         validation among a verifier's checks (line 1219) without a BCP 14 keyword on
         either, so it is not required of a verifier and is not enabled unless asked for.

         THE OPT-IN IS PASSING THE `predecessor` ARGUMENT, not the value it carries. The
         TypeScript reference reads own-property presence on its options object; this port
         reproduces that with the module-private sentinel `_PREDECESSOR_NOT_PASSED` as the
         default. With the argument omitted, `predecessor_bound` is "not_checked" and this
         function's valid, status and errors are exactly what they were before the argument
         existed. With the argument passed as None, which is what both TypeScript absent
         values, undefined and null, map to, the caller asked for a binding it could not
         supply the record for: the axis is "not_established" and the composite is
         "indeterminate", carrying the primitive's own `predecessor_not_supplied` code. The
         distinction is the whole point of reading passing rather than value.
         `predecessor=store.get(receipt["prev"])` puts a lookup miss in that argument, and
         treating it as an omitted argument would report valid for a check the caller
         requested and nobody ran.

         The predecessor's own signatures are NOT verified here; a caller that wants them
         checked runs this verifier over the predecessor as well.
      7. `valid_until_not_after_issued_at`  the temporal relation, checked only once the
         operands are known to belong together. Both timestamps are validated as exact UTC
         milliseconds and then compared as instants, never as strings. A deny decision
         carries a null valid_until by rule (line 1090), so there is no window to compare
         and its absence is not a failure. Reporting one made every correct deny decision
         fail this verifier.

    The binding checks run BEFORE the temporal one on purpose. A temporal result computed
    over an unbound pair is not evidence about this receipt at all. The predecessor check is
    a binding check, so it sits with the others and ahead of the temporal one for the same
    reason.

    The result members:

      valid                    True only when status is "valid".
      status                   Section 5.6 lines 1225-1228. Invalid dominates: a structural
                               failure anywhere makes the composite invalid. Otherwise an
                               unsupported or indeterminate sub-result carries through, so a
                               caller cannot read a valid composite out of an axis that was
                               never established.
      receipt                  The verify_receipt_v1 sub-result.
      stage                    The section 5.3 stage result for this record, which decides
                               which cross-document checks apply at all.
      decision_ref_present     Whether the receipt carries a decision_ref to bind.
      decision_ref_bound       Whether the recomputed digest equals it.
      decision_output_bound    For a policy-decision record, whether receipt["result"] is
                               byte-identical under JCS to the decision_output supplied.
                               "not_applicable" for the other stages.
      temporal_relation_valid  "not_applicable" on the stages where the comparison is
                               deliberately not made: the window belongs to the decision,
                               and the draft states no relation between it and the issuance
                               time of a later record. Reporting True there said a check had
                               passed that never ran.
      predecessor_bound        True, False, "not_checked", "not_applicable" or
                               "not_established". The three non-boolean states are kept
                               apart because they are three different things: nothing was
                               asked, nothing applies, and something was asked that could
                               not be established. Reporting False for any of them would say
                               a link had been refused when nothing was compared.
      errors                   Stages short-circuit, so this names the first thing that
                               actually failed rather than a cascade.
    """
    errors: list[str] = []
    not_run = {
        "status": "invalid",
        "receipt_type": None,
        "stage": None,
        "boundary_identity": "not_applicable",
        "failures": [],
    }

    def base(receipt_result: dict, status: str, stage) -> dict:
        return {
            "valid": False,
            "status": status,
            "receipt": receipt_result,
            "stage": stage,
            "decision_ref_present": False,
            "decision_ref_bound": False,
            "decision_output_bound": "not_applicable",
            "temporal_relation_valid": False,
            "predecessor_bound": "not_checked",
            "errors": errors,
        }

    # A sub-result that is not valid is named for what it is. Calling an indeterminate
    # receipt "receipt_invalid" would tell a caller the record was wrong when the verifier
    # could not establish one of its axes, which is the collapse section 5.6 line 1227
    # forbids, just pointed the other way.
    def code(prefix: str, status: str) -> str:
        return f"{prefix}_{status}"

    # Stages 1 and 2 together: structural, cryptographic and the section 5.3 rules for this
    # record's own receipt_type.
    receipt_result = verify_receipt_v1(
        receipt,
        resolve_key,
        expected_receipt_type=expected_receipt_type,
        boundary_identity=boundary_identity,
    )
    stage = not_run if receipt_result["stage"] == "not_checked" else receipt_result["stage"]
    if not receipt_result["valid"]:
        errors.append(code("receipt", receipt_result["status"]))
        errors.extend(receipt_result["errors"])
        return base(receipt_result, receipt_result["status"], stage)

    # Stage 3: the reference must be there to be bound.
    if not isinstance(receipt.get("decision_ref"), str):
        errors.append("decision_ref_absent")
        return base(receipt_result, "invalid", stage)

    # Stage 4: reference binding, through the builder rather than a reimplementation.
    #
    # Draft lines 1145 to 1147 compute each component reference over the EXACT value
    # evaluated, and lines 1183 to 1184 say decision_output is the exact object the receipt
    # carries, so the supplied output is validated as received before the builder is allowed
    # to normalize anything.
    try:
        validate_core_decision_output_v1(decision["decision_output"])
        recomputed = build_decision_ref_v1(
            action_ref=receipt["action_ref"],
            authority_state=decision["authority_state"],
            policy_input=decision["policy_input"],
            decision_context=decision["decision_context"],
            decision_output=decision["decision_output"],
        )["decision_ref"]
    except (TypeError, ValueError, KeyError) as exc:
        errors.extend(("decision_input_invalid", str(exc)))
        return {**base(receipt_result, "invalid", stage), "decision_ref_present": True}
    if recomputed != receipt["decision_ref"]:
        errors.append("decision_ref_mismatch")
        return {**base(receipt_result, "invalid", stage), "decision_ref_present": True}

    bound = {
        **base(receipt_result, "invalid", stage),
        "decision_ref_present": True,
        "decision_ref_bound": True,
    }

    # Stage 5: for a policy-decision record, the decision's output is the result this
    # receipt carries. Canonical bytes, so member order cannot make two different objects
    # compare equal or two equal objects compare different.
    is_policy_decision = stage["stage"] == "policy-decision"
    if is_policy_decision and strict_jcs(receipt["result"]) != strict_jcs(decision["decision_output"]):
        errors.append("decision_output_mismatch")
        return {**bound, "decision_output_bound": False}
    decision_output_bound = True if is_policy_decision else "not_applicable"

    # Stage 6: the section 5.3.3 prev binding, only when the caller opted in.
    #
    # The opt-in is that the argument was passed, deliberately not its truthiness and not a
    # value test. A caller writing `predecessor=store.get(receipt["prev"])` has asked for the
    # binding; whether the lookup found anything is the answer to that request, not a
    # withdrawal of it. Reading the value instead would collapse "did not ask" and "asked
    # and could not establish" into one state and hand back valid for both.
    predecessor_bound = "not_checked"
    # Set only for the not_established case. The result is carried to the end rather than
    # returned here so that an invalid found by stage 7 still dominates, per section 5.6
    # line 1227: an unestablished axis downgrades a pass, it does not mask a failure.
    predecessor_not_established = False
    if predecessor is not _PREDECESSOR_NOT_PASSED:
        predecessor_result = verify_receipt_predecessor_v1(receipt, predecessor)
        if predecessor_result["status"] == "not_applicable":
            predecessor_bound = "not_applicable"
        elif predecessor_result["status"] == "indeterminate":
            # The primitive reached `predecessor_not_supplied`. Its code is pushed so a
            # caller reading the errors learns the record was never in hand, not that a
            # comparison refused the pair.
            predecessor_bound = "not_established"
            predecessor_not_established = True
            if predecessor_result["failure"] is not None:
                errors.append(predecessor_result["failure"])
        else:
            predecessor_bound = predecessor_result["bound"]
            if predecessor_bound is False:
                errors.append("predecessor_not_bound")
                # The primitive's own code, so a caller reading the errors learns which of
                # the section 5.3.3 comparisons refused the pair rather than only that one
                # did.
                if predecessor_result["failure"] is not None:
                    errors.append(predecessor_result["failure"])
                return {
                    **bound,
                    "decision_output_bound": decision_output_bound,
                    "predecessor_bound": False,
                }
    # Applied at every exit below that would otherwise pass. Invalid exits are left alone.
    pass_status = "indeterminate" if predecessor_not_established else "valid"

    # Stage 7: temporal relation, on operands now known to belong together.
    valid_until = decision["decision_output"]["valid_until"]
    if valid_until is None:
        # A deny decision carries no validity window by rule, so there is no instant that
        # could be later than issued_at and nothing here has failed. Whether a deny may be
        # consumed as an approval is the caller's rule at line 1098, not a property of this
        # pair of artifacts.
        return {
            **bound,
            "decision_output_bound": decision_output_bound,
            "predecessor_bound": predecessor_bound,
            "temporal_relation_valid": True if is_policy_decision else "not_applicable",
            "valid": pass_status == "valid",
            "status": pass_status,
        }
    if not _is_exact_utc_milliseconds(receipt["issued_at"]) or not _is_exact_utc_milliseconds(valid_until):
        errors.append("timestamp_invalid")
        return {
            **bound,
            "decision_output_bound": decision_output_bound,
            "predecessor_bound": predecessor_bound,
        }
    # The comparison is against the issued_at of the record that carries the window. For a
    # policy-decision record that is its own issued_at, which is what line 1091 fixes. For an
    # action-result record the window belongs to the decision it follows, and the draft
    # states no relation between that window and the result's own issuance time, so none is
    # invented: the check applies to the decision stage only.
    if is_policy_decision and not _is_later_utc_millisecond(valid_until, receipt["issued_at"]):
        errors.append("valid_until_not_after_issued_at")
        return {
            **bound,
            "decision_output_bound": decision_output_bound,
            "predecessor_bound": predecessor_bound,
        }

    return {
        "valid": pass_status == "valid",
        "status": pass_status,
        "receipt": receipt_result,
        "stage": stage,
        "decision_ref_present": True,
        "decision_ref_bound": True,
        "decision_output_bound": decision_output_bound,
        "temporal_relation_valid": True if is_policy_decision else "not_applicable",
        "predecessor_bound": predecessor_bound,
        "errors": errors,
    }
