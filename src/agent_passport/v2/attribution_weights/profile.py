# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Default profile + validation + hash — Python port.

Numeric defaults must byte-match the TS DEFAULT_WEIGHT_PROFILE so that
cross-language profile hashes match. See build-b fixtures for the
reference vector.
"""

import hashlib
import math
from typing import Any, List

from ...canonical import canonicalize
from .types import ATTRIBUTION_ROLES, ValidationResult, WeightProfile


DEFAULT_WEIGHT_PROFILE: WeightProfile = {
    "version": "v0.1",
    "role_weights": {
        "primary_source": 1.0,
        "supporting_evidence": 0.6,
        "context_only": 0.3,
        "background_retrieval": 0.1,
    },
    "recency": {
        "min_recency": 0.2,
        # Wire key is "lambda" — matches TS Math.LN2 byte-for-byte.
        "lambda": math.log(2),
        "tau_days": 30,
    },
    "length": {
        "reference_length": 1000,
    },
    "compute": {
        "completion_multiplier": 3.0,
    },
}


def _is_nonneg_finite(v: Any) -> bool:
    return (
        isinstance(v, (int, float))
        and not isinstance(v, bool)
        and not (isinstance(v, float) and (math.isnan(v) or math.isinf(v)))
        and v >= 0
    )


def _is_positive_finite(v: Any) -> bool:
    return _is_nonneg_finite(v) and v > 0


def validate_weight_profile(profile: Any) -> ValidationResult:
    errors: List[str] = []
    if not isinstance(profile, dict):
        return {"valid": False, "errors": ["profile must be a dict"]}

    if not isinstance(profile.get("version"), str) or not profile.get("version"):
        errors.append("profile.version must be a non-empty string")

    rw = profile.get("role_weights")
    if not isinstance(rw, dict):
        errors.append("profile.role_weights missing")
    else:
        for role in ATTRIBUTION_ROLES:
            v = rw.get(role)
            if not _is_nonneg_finite(v):
                errors.append(f"profile.role_weights.{role} must be a non-negative finite number")

    rc = profile.get("recency")
    if not isinstance(rc, dict):
        errors.append("profile.recency missing")
    else:
        mr = rc.get("min_recency")
        if not (_is_nonneg_finite(mr) and 0 <= mr <= 1):
            errors.append("profile.recency.min_recency must be in [0, 1]")
        lam = rc.get("lambda", rc.get("lambda_"))
        if not _is_nonneg_finite(lam):
            errors.append("profile.recency.lambda must be a non-negative finite number")
        td = rc.get("tau_days")
        if not _is_positive_finite(td):
            errors.append("profile.recency.tau_days must be a positive finite number")

    ln = profile.get("length")
    if not isinstance(ln, dict):
        errors.append("profile.length missing")
    else:
        ref = ln.get("reference_length")
        if not _is_positive_finite(ref):
            errors.append("profile.length.reference_length must be a positive finite number")

    cp = profile.get("compute")
    if not isinstance(cp, dict):
        errors.append("profile.compute missing")
    else:
        m = cp.get("completion_multiplier")
        if not _is_nonneg_finite(m):
            errors.append("profile.compute.completion_multiplier must be a non-negative finite number")

    return {"valid": len(errors) == 0, "errors": errors}


def hash_weight_profile(profile: WeightProfile) -> str:
    """sha256(canonicalize(profile)) as lowercase hex.

    Canonicalization strips None values and sorts keys, so byte-identical
    with the TS hashWeightProfile. Cross-language fixtures in
    specs/fixtures/build-b pin the concrete hex for DEFAULT_WEIGHT_PROFILE.
    """
    result = validate_weight_profile(profile)
    if not result["valid"]:
        raise ValueError(
            "attribution-weights: cannot hash invalid profile — "
            + "; ".join(result["errors"])
        )
    return hashlib.sha256(canonicalize(profile).encode("utf-8")).hexdigest()
