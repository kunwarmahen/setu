"""When Google will end a sign-in, said before it happens.

The bias: A WARNING THAT COMES TOO LATE OR NEVER STOPS. Google ends an
app in Testing's sign-ins 7 days after they are made and says so only by
refusing the next use -- a morning job fails, then you hear. So a
Google connection says the day it will end, and says it in `setu list`
and on the page only in its last days. And it never nags a published
app, or a sign-in that isn't Google's, or one already marked expired.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from setu import config, connections

MADE = "2026-10-19T02:44:08Z"
GMAIL = {"connector": "gmail", "account": "personal", "created": MADE}


def at(days: float) -> datetime:
    return datetime(2026, 10, 19, 2, 44, 8, tzinfo=UTC) + timedelta(days=days)


def test_a_google_sign_in_ends_seven_days_after_it_was_made():
    assert connections.ends(GMAIL, published=False) == "2026-10-26T02:44:08+00:00"


def test_a_published_app_and_other_roads_have_no_end():
    assert connections.ends(GMAIL, published=True) is None
    for auth in ("browser", "homeassistant", "own", "password", "phone"):
        assert connections.ends({**GMAIL, "auth": auth}, published=False) is None
    assert connections.ends({"connector": "gmail"}, published=False) is None


def test_it_is_said_only_in_its_last_days():
    assert connections.ends_line(GMAIL, False, now=at(2)) == ""
    line = connections.ends_line(GMAIL, False, now=at(5))
    assert line.startswith("SIGN-IN ENDS ")
    assert "setu connect gmail --as personal" in line
    assert "setu config google-published on" in line


def test_an_expired_one_is_not_also_ending():
    gone = {**GMAIL, connections.EXPIRED: {"since": MADE, "why": "refused"}}
    assert connections.ends_line(gone, False, now=at(6.5)) == ""


def test_the_switch_is_off_until_said(home):
    assert config.google_published() is False
    config.save("google_published", config.check("google-published", "on"))
    assert config.google_published() is True
