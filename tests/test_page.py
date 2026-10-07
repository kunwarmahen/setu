"""Setu's page (``setu serve``) -- what it shows, and who may see it.

The bias is A PAGE THAT HOLDS SIGN-INS, OPEN TO THE WRONG READER. Any
site a person visits can send a request to 127.0.0.1, and any site can
try to frame a page and lay its own buttons over it. So the tests ask
the server without a token, with the wrong one, from a frame it did not
name, and for a log by a ref that walks out of the folder -- and look for
known secrets in every answer it gives.

The other promise: THE PAGE SAYS WHAT ``setu status`` SAYS. Its cards
are the same report, less what is only for a harness.
"""

from __future__ import annotations

import json
import stat

import httpx
import pytest
from conftest import REFRESH, TOKEN
from setu import page, proxy
from setu.vault import FileVault
from test_status import seed

GOOD = "a-page-token-long-enough-1234"


@pytest.fixture
def served(home):
    seed(FileVault())
    server = page.PageServer(page.Api(FileVault()), GOOD, port=0,
                             embed=["http://127.0.0.1:8000"])
    server.start()
    yield server
    server.stop()


def get(server, path, token=GOOD):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return httpx.get(server.url.rstrip("/") + path, headers=headers, timeout=5)


def test_every_api_call_without_the_token_is_refused(served):
    for path in ("/api/status", "/api/connections", "/api/connectors",
                 "/api/log?ref=gmail:personal"):
        assert get(served, path, token=None).status_code == 401
        assert get(served, path, token="wrong-token-of-some-length").status_code == 401


def test_the_page_itself_needs_no_token_and_holds_no_data(served):
    for path in ("/", "/page.js", "/page.css"):
        res = get(served, path, token=None)
        assert res.status_code == 200
        assert "personal@example.com" not in res.text


def test_no_answer_carries_a_secret(served):
    text = "".join(get(served, p).text for p in
                   ("/api/status", "/api/connections", "/api/connectors"))
    for secret in (REFRESH, TOKEN, "shh-secret", GOOD):
        assert secret not in text


def test_a_connection_card_matches_the_report_without_the_harness_parts(served):
    row = get(served, "/api/connections").json()["connections"][0]
    assert row["ref"] == "gmail:personal"
    assert row["level_label"] == "Read, draft and send"
    assert row["road"] == "api"
    assert "mcp" not in row and "browser" not in row


def test_a_browser_connection_does_not_say_where_its_cookies_are(home):
    FileVault().put("amazon:personal", {
        "connector": "amazon", "account": "personal", "email": "personal",
        "auth": "browser", "level": "read", "profile": "/secret/place/profile",
        "browser": "/usr/bin/chrome", "secret": None})
    rows = page.Api(FileVault()).connections()
    assert rows[0]["road"] == "browser"
    assert "/secret/place" not in json.dumps(rows)


def test_connectors_say_their_levels_in_words(served):
    gmail = next(c for c in get(served, "/api/connectors").json()["connectors"]
                 if c["id"] == "gmail")
    assert gmail["connected"] is True
    assert [lv["label"] for lv in gmail["levels"]][0] == "Read only"


def test_the_status_names_the_folder_and_its_lock(served, home):
    data = get(served, "/api/status").json()
    assert data["folder"] == str(home)
    assert data["lock"] == {"locked": False, "open": False}
    assert data["connections"] == 1


def test_the_log_comes_newest_first_with_the_outcome_kept_whole(served, home):
    path = proxy.log_path("gmail:personal", home)
    path.parent.mkdir(parents=True)
    path.write_text("2026-10-06T09:00:00 GET /gmail/v1/users/me/threads 200\n"
                    "2026-10-06T09:01:00 POST /gmail/v1/users/me/messages/send "
                    "refused: not at this level\n")
    data = get(served, "/api/log?ref=gmail:personal").json()
    assert [e["method"] for e in data["entries"]] == ["POST", "GET"]
    assert data["entries"][0]["outcome"] == "refused: not at this level"


def test_the_log_reads_the_older_half_after_a_rotation(served, home):
    path = proxy.log_path("gmail:personal", home)
    path.parent.mkdir(parents=True)
    path.with_suffix(".log.1").write_text("2026-10-05T09:00:00 GET /old 200\n")
    path.write_text("2026-10-06T09:00:00 GET /new 200\n")
    data = get(served, "/api/log?ref=gmail:personal&limit=5").json()
    assert [e["path"] for e in data["entries"]] == ["/new", "/old"]


def test_a_log_is_only_for_a_connection_the_folder_holds(served, home):
    (home / "logs").mkdir(parents=True)
    (home / "elsewhere.log").write_text("2026-10-06T09:00:00 GET /private 200\n")
    for ref in ("../elsewhere", "gmail:nobody", ""):
        res = get(served, f"/api/log?ref={ref}")
        assert res.status_code == 404 and "/private" not in res.text


def test_only_named_sites_may_frame_the_page(served):
    policy = get(served, "/", token=None).headers["content-security-policy"]
    assert "frame-ancestors 'self' http://127.0.0.1:8000" in policy
    assert "script-src 'self'" in policy and "unsafe-inline" not in policy


def test_no_answer_lets_another_site_read_it(served):
    res = get(served, "/api/status")
    assert "access-control-allow-origin" not in res.headers


def test_an_embedder_that_is_not_an_origin_is_refused():
    assert page.embedders("http://127.0.0.1:8000, https://yantra.home") == [
        "http://127.0.0.1:8000", "https://yantra.home"]
    for bad in ("*", "https://*.example.com", "http://x/path", "javascript:alert(1)"):
        with pytest.raises(ValueError):
            page.embedders(bad)


def test_this_page_only_reads(served):
    res = httpx.post(served.url + "api/connections",
                     headers={"Authorization": f"Bearer {GOOD}"}, timeout=5)
    assert res.status_code == 405


def test_the_token_is_made_once_and_kept_for_you_alone(home, monkeypatch):
    monkeypatch.delenv(page.ENV_TOKEN, raising=False)
    first = page.page_token(home)
    assert page.page_token(home) == first and len(first) >= 16
    assert stat.S_IMODE((home / page.TOKEN_FILE).stat().st_mode) == 0o600


def test_a_short_token_from_the_environment_is_refused(home, monkeypatch):
    monkeypatch.setenv(page.ENV_TOKEN, "short")
    with pytest.raises(ValueError):
        page.page_token(home)


def test_the_printed_address_carries_the_token_after_the_hash(served):
    assert served.page_url == f"{served.url}#token={GOOD}"
    assert served.url.startswith("http://127.0.0.1:")
