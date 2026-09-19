# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Leap-second handling for the section 4.2 external correlation form
(action-ref-v1-jcs-sha256, :func:`agent_passport.compute_external_action_ref_v1`).

RFC 3339 admits second 60 for a leap second and a validator cannot consult
the leap-second table to know whether one actually occurred at a given UTC
instant, so this helper accepts it lexically; it still rejects second 61,
which no RFC 3339 rule admits.
"""

import re

import pytest

from agent_passport import ExternalActionRefError, compute_external_action_ref_v1


def _base() -> dict:
    return {
        "action_type": "commerce_preflight",
        "agent_id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
        "scope": "commerce:write",
        "timestamp": "2026-04-08T12:00:00.000Z",
    }


def test_leap_second_60_is_accepted_lexically():
    fields = _base()
    fields["timestamp"] = "2016-12-31T23:59:60.000Z"
    assert re.fullmatch(r"[0-9a-f]{64}", compute_external_action_ref_v1(**fields))


def test_leap_second_60_is_accepted_lexically_at_an_arbitrary_time():
    fields = _base()
    fields["timestamp"] = "2026-04-08T12:00:60.000Z"
    assert re.fullmatch(r"[0-9a-f]{64}", compute_external_action_ref_v1(**fields))


def test_second_61_is_still_rejected():
    fields = _base()
    fields["timestamp"] = "2026-04-08T12:00:61.000Z"
    with pytest.raises(ExternalActionRefError) as exc_info:
        compute_external_action_ref_v1(**fields)
    assert exc_info.value.code == "bad_timestamp"
