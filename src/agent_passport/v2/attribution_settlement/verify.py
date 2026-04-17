# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Settlement record verification — Python port of
src/v2/attribution-settlement/verify.ts.

Checks S1-S5. S3 (conservation) is the strongest invariant.
"""

import hashlib
import re

from ...canonical import canonicalize
from ..attribution_primitive.canonical import assert_canonical_timestamp
from ..attribution_primitive.verify import verify_attribution_primitive
from .aggregate import _parse_ms, residual_leaf_hash_hex
from .merkle import build_merkle_root, empty_axis_merkle_root, leaf_hash
from .sign import verify_settlement_signature


_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX128 = re.compile(r"^[0-9a-f]{128}$")
_WEIGHT_6DP = re.compile(r"^\d+\.\d{6}$")

S3_EPSILON_PER_ACTION = 5e-6
S3_EPSILON_FLOOR = 1e-6


def _fail(reason: str, detail: str = None) -> dict:
    out = {"valid": False, "reason": reason}
    if detail is not None:
        out["detail"] = detail
    return out


def _malformed(record) -> str:
    if not isinstance(record, dict):
        return "record must be an object"
    if record.get("schema") != "aps.settlement.v1":
        return f"unsupported schema {record.get('schema')!r}"
    if not isinstance(record.get("gateway_did"), str) or not record["gateway_did"]:
        return "gateway_did required"
    sig = record.get("signature")
    if not isinstance(sig, str) or not _HEX128.match(sig):
        return "signature must be 128-char hex"
    period = record.get("period")
    if not isinstance(period, dict):
        return "period required"
    try:
        assert_canonical_timestamp(period["t0"])
        assert_canonical_timestamp(period["t1"])
        assert_canonical_timestamp(record["issued_at"])
    except ValueError as e:
        return str(e)
    if _parse_ms(period["t0"]) >= _parse_ms(period["t1"]):
        return "period.t0 must precede period.t1"
    axes = record.get("axes")
    if not isinstance(axes, dict):
        return "axes required"
    for tag in ("D", "P", "G", "C"):
        axis = axes.get(tag)
        if not isinstance(axis, dict):
            return f"axes.{tag} required"
        if axis.get("axis") != tag:
            return f"axes.{tag}.axis mismatch"
        if not isinstance(axis.get("axis_merkle_root"), str) or not _HEX64.match(axis["axis_merkle_root"]):
            return f"axes.{tag}.axis_merkle_root must be 64-char hex"
        if not isinstance(axis.get("total_actions"), int) or axis["total_actions"] < 0:
            return f"axes.{tag}.total_actions must be non-negative"
        if not isinstance(axis.get("contributors"), list):
            return f"axes.{tag}.contributors must be a list"
    irh = record.get("input_receipts_hash")
    if not isinstance(irh, str) or not _HEX64.match(irh):
        return "input_receipts_hash must be 64-char hex"
    if not isinstance(record.get("total_input_count"), int) or record["total_input_count"] < 0:
        return "total_input_count must be non-negative"
    return None


def _validate_residual_shape(r, axis: str) -> str:
    if axis == "G":
        return "governance axis cannot carry a residual bucket"
    expected = f"residual:{axis}"
    if r.get("residual_id") != expected:
        return f"residual_id mismatch: expected {expected}"
    tpw = r.get("total_pooled_weight")
    if not isinstance(tpw, str):
        return "total_pooled_weight must be string"
    try:
        w = float(tpw)
    except ValueError:
        return "total_pooled_weight not parseable"
    if w < 0:
        return "total_pooled_weight must be non-negative"
    cnt = r.get("count_of_pooled_contributors")
    if not isinstance(cnt, int) or cnt < 0:
        return "count_of_pooled_contributors must be non-negative"
    pch = r.get("pooled_contributors_hash")
    if not isinstance(pch, str) or not _HEX64.match(pch):
        return "pooled_contributors_hash must be 64-char hex"
    return None


def _check_axis_merkle_root(axis) -> bool:
    leaves = []
    for c in axis["contributors"]:
        body = {
            "contributor_did": c["contributor_did"],
            "total_weight": c["total_weight"],
            "contribution_count": c["contribution_count"],
        }
        expected = hashlib.sha256(canonicalize(body).encode("utf-8")).hexdigest()
        if expected != c["merkle_leaf_hash"].lower():
            return False
        leaves.append(bytes.fromhex(expected))
    if axis.get("residual_bucket"):
        leaves.append(bytes.fromhex(residual_leaf_hash_hex(axis["residual_bucket"])))
    computed = (
        empty_axis_merkle_root() if not leaves else build_merkle_root(leaves).hex()
    )
    return computed == axis["axis_merkle_root"].lower()


def _check_conservation(axis) -> tuple:
    total = 0.0
    for c in axis["contributors"]:
        total += float(c["total_weight"])
    if axis.get("residual_bucket"):
        total += float(axis["residual_bucket"]["total_pooled_weight"])
    delta = abs(total - axis["total_actions"])
    bound = max(S3_EPSILON_FLOOR, axis["total_actions"] * S3_EPSILON_PER_ACTION)
    return (delta <= bound, delta)


def verify_settlement_record(record, *, gateway_public_key_hex: str, input_receipts=None) -> dict:
    """Full settlement-record verification."""
    if not gateway_public_key_hex:
        return _fail("MALFORMED", "gateway_public_key_hex required")
    mal = _malformed(record)
    if mal:
        return _fail("MALFORMED", mal)

    # S4 residual shape + contributor well-formedness.
    for tag in ("D", "P", "G", "C"):
        axis = record["axes"][tag]
        if axis.get("residual_bucket"):
            err = _validate_residual_shape(axis["residual_bucket"], tag)
            if err:
                return _fail("RESIDUAL_BUCKET_MISMATCH", f"axes.{tag}: {err}")
        for c in axis["contributors"]:
            if not isinstance(c.get("contributor_did"), str) or not c["contributor_did"]:
                return _fail("MALFORMED", f"axes.{tag} contributor missing contributor_did")
            if not isinstance(c.get("total_weight"), str) or not _WEIGHT_6DP.match(c["total_weight"]):
                return _fail("MALFORMED", f"axes.{tag} contributor {c['contributor_did']} total_weight not canonical 6-digit")
            if not isinstance(c.get("contribution_count"), int) or c["contribution_count"] < 0:
                return _fail("MALFORMED", f"axes.{tag} contributor {c['contributor_did']} contribution_count invalid")
            if not isinstance(c.get("merkle_leaf_hash"), str) or not _HEX64.match(c["merkle_leaf_hash"]):
                return _fail("MALFORMED", f"axes.{tag} contributor {c['contributor_did']} merkle_leaf_hash invalid")
        for i in range(1, len(axis["contributors"])):
            if axis["contributors"][i]["contributor_did"] <= axis["contributors"][i - 1]["contributor_did"]:
                return _fail("MERKLE_ROOT_MISMATCH", f"axes.{tag} contributors not strictly lex-sorted by DID")

    # S2.
    for tag in ("D", "P", "G", "C"):
        if not _check_axis_merkle_root(record["axes"][tag]):
            return _fail("MERKLE_ROOT_MISMATCH", f"axes.{tag}.axis_merkle_root does not recompute from leaves")

    # S3.
    for tag in ("D", "P", "G", "C"):
        ok, delta = _check_conservation(record["axes"][tag])
        if not ok:
            return _fail(
                "CONSERVATION_VIOLATION",
                f"axes.{tag}: sum(contributors + residual) − total_actions = {delta:.3e} exceeds tolerance",
            )

    # S1.
    if not verify_settlement_signature(record, gateway_public_key_hex):
        return _fail("SIGNATURE_INVALID", "gateway signature does not verify over canonical body")

    # S5 (optional).
    if input_receipts is not None:
        t0 = _parse_ms(record["period"]["t0"])
        t1 = _parse_ms(record["period"]["t1"])
        refs = []
        for r in input_receipts:
            try:
                assert_canonical_timestamp(r["timestamp"])
            except ValueError as e:
                return _fail("MALFORMED", f"inputReceipts entry has invalid timestamp: {e}")
            ts = _parse_ms(r["timestamp"])
            if ts < t0 or ts >= t1:
                return _fail(
                    "RECEIPT_OUT_OF_PERIOD",
                    f"receipt {r['action_ref']} timestamp {r['timestamp']} outside period",
                )
            rv = verify_attribution_primitive(r, gateway_public_key_hex)
            if not rv.get("valid"):
                return _fail(
                    "RECEIPT_SIGNATURE_INVALID",
                    f"receipt {r['action_ref']} failed verification: {rv.get('reason')}",
                )
            refs.append(r["action_ref"])
        if len(refs) != record["total_input_count"]:
            return _fail(
                "INPUT_RECEIPTS_HASH_MISMATCH",
                f"total_input_count {record['total_input_count']} but received {len(refs)} receipts",
            )
        refs.sort()
        ref_leaves = [leaf_hash(ref) for ref in refs]
        computed = (
            empty_axis_merkle_root() if not ref_leaves else build_merkle_root(ref_leaves).hex()
        )
        if computed != record["input_receipts_hash"].lower():
            return _fail("INPUT_RECEIPTS_HASH_MISMATCH", "input_receipts_hash does not match supplied receipts")

    return {"valid": True}
