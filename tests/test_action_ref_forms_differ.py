# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""The three action-reference forms are distinct primitives with distinct preimages.

For the same underlying action, compute_action_ref (pre-draft-03
compatibility digest), compute_external_action_ref_v1 (draft-pidlisnyi-aps-03
section 4.2, action-ref-v1-jcs-sha256) and compute_action_ref_v2
(draft-pidlisnyi-aps-03 section 4.1, aps-action-ref-v2) MUST produce three
different digests: they hash different preimages under different rules, and
a caller must never treat one as interchangeable with another (see each
function's own docstring for what it is and is not).
"""

from __future__ import annotations

import re

from agent_passport import (
    ACTION_REF_V2_PROFILE,
    compute_action_ref,
    compute_action_ref_v2,
    compute_external_action_ref_v1,
    compute_payload_ref_v1,
)

_HEX64 = re.compile(r"[0-9a-f]{64}")

_AGENT_ID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
_ACTION_TYPE = "commerce_preflight"
_SCOPE = "commerce:write"
_TIMESTAMP = "2026-04-08T12:00:00.000Z"


def test_three_forms_give_three_different_digests():
    pre_draft = compute_action_ref(_AGENT_ID, _ACTION_TYPE, _SCOPE, _TIMESTAMP)

    external_v1 = compute_external_action_ref_v1(
        action_type=_ACTION_TYPE,
        agent_id=_AGENT_ID,
        scope=_SCOPE,
        timestamp=_TIMESTAMP,
    )

    native_v2 = compute_action_ref_v2(
        {
            "profile": ACTION_REF_V2_PROFILE,
            "agent_id": _AGENT_ID,
            "action_type": _ACTION_TYPE,
            "target": "https://api.example/payments",
            "payload_ref": compute_payload_ref_v1({"amount": "5000"}),
            "scope_required": [_SCOPE],
            "issued_at": _TIMESTAMP,
            "nonce": "00112233445566778899aabbccddeeff",
        }
    )

    digests = {pre_draft, external_v1, native_v2}
    assert len(digests) == 3, (
        "the pre-draft, section 4.2, and section 4.1 forms must never collide "
        f"for the same underlying action: {digests}"
    )

    for digest in (pre_draft, external_v1, native_v2):
        assert _HEX64.fullmatch(digest), digest
