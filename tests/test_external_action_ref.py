# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Leap-second handling for the section 4.2 external correlation form
(action-ref-v1-jcs-sha256, :func:`agent_passport.compute_external_action_ref_v1`).

A canonical timestamp's second field of 60 is valid only when the hour is
23, the minute is 59, and the day is the last day of its month in the
proleptic Gregorian calendar (RFC 3339 section 5.7; Appendix D's
"YYYY-MM-DDT23:59:60Z"). Every other second-60 timestamp is rejected with
``bad_timestamp``. Second 61 is rejected under every rule; no RFC 3339
grammar admits it.
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


def test_second_60_at_2359_on_the_last_day_of_the_year_is_accepted():
    # 2016-12-31T23:59:60Z is an actual leap second, 23:59:60 on the last
    # day of a month.
    fields = _base()
    fields["timestamp"] = "2016-12-31T23:59:60.000Z"
    assert re.fullmatch(r"[0-9a-f]{64}", compute_external_action_ref_v1(**fields))


def test_second_60_at_an_arbitrary_time_is_now_rejected():
    # Formerly accepted lexically; now rejected because 12:00 on April 8 is
    # not 23:59 on the last day of a month.
    fields = _base()
    fields["timestamp"] = "2026-04-08T12:00:60.000Z"
    with pytest.raises(ExternalActionRefError) as exc_info:
        compute_external_action_ref_v1(**fields)
    assert exc_info.value.code == "bad_timestamp"


@pytest.mark.parametrize(
    "timestamp",
    [
        "2026-06-30T23:59:60.000Z",
        "2028-02-29T23:59:60.999Z",
        "2027-02-28T23:59:60.000Z",
        "0000-02-29T23:59:60.000Z",
    ],
)
def test_second_60_at_2359_on_the_last_day_of_the_month_is_accepted(timestamp):
    fields = _base()
    fields["timestamp"] = timestamp
    assert re.fullmatch(r"[0-9a-f]{64}", compute_external_action_ref_v1(**fields))


@pytest.mark.parametrize(
    "timestamp",
    [
        "2026-06-29T23:59:60.000Z",  # not the last day of the month
        "2016-12-31T23:58:60.000Z",  # minute 58, not 59
        "2016-12-31T22:59:60.000Z",  # hour 22, not 23
        "2028-02-28T23:59:60.000Z",  # not the last day of February in a leap year
        "2027-02-29T23:59:60.000Z",  # no such day
    ],
)
def test_second_60_outside_2359_on_the_last_day_of_the_month_is_rejected(timestamp):
    fields = _base()
    fields["timestamp"] = timestamp
    with pytest.raises(ExternalActionRefError) as exc_info:
        compute_external_action_ref_v1(**fields)
    assert exc_info.value.code == "bad_timestamp"


def test_second_61_is_still_rejected():
    fields = _base()
    fields["timestamp"] = "2026-04-08T12:00:61.000Z"
    with pytest.raises(ExternalActionRefError) as exc_info:
        compute_external_action_ref_v1(**fields)
    assert exc_info.value.code == "bad_timestamp"
