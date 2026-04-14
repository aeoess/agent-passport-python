# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""sign_attribution_consent — cited principal adds the consent signature."""

from ...crypto import sign, verify
from .create import receipt_core
from .types import AttributionReceipt


def sign_attribution_consent(
    receipt: AttributionReceipt,
    cited_principal_private_key: str,
) -> AttributionReceipt:
    """Add the cited principal's consent signature. Does not mutate the input.
    Raises ValueError if the private key does not match cited_principal_public_key."""
    core = receipt_core(receipt)
    cited_principal_signature = sign(core, cited_principal_private_key)

    if not verify(core, cited_principal_signature, receipt["cited_principal_public_key"]):
        raise ValueError(
            "sign_attribution_consent: consent signature does not verify against "
            "cited_principal_public_key — wrong private key?"
        )

    return {**receipt, "cited_principal_signature": cited_principal_signature}
