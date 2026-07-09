# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""APS Composition Check Receipt v0 - public surface (Python port).

Carrier + stateless anchor verifier. Detection of composition hazards stays in the private
gateway. Mirrors src/v2/composition-check/index.ts and is cross-language signature
compatible (a receipt signed by the TS SDK verifies here and vice versa).
"""
from .verify import (
    ATTESTOR_INDEPENDENCE_CLASSES,
    COMPOSITION_CHECK_PROFILE,
    COMPOSITION_CHECK_RESULTS,
    COMPOSITION_CHECK_TAG,
    composition_check_signing_payload,
    verify_composition_check,
)

__all__ = [
    "COMPOSITION_CHECK_PROFILE",
    "COMPOSITION_CHECK_TAG",
    "COMPOSITION_CHECK_RESULTS",
    "ATTESTOR_INDEPENDENCE_CLASSES",
    "composition_check_signing_payload",
    "verify_composition_check",
]
