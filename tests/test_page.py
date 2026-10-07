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
import sys

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
                 "/api/requests?ref=gmail:personal"):
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
    data = get(served, "/api/requests?ref=gmail:personal").json()
    assert [e["method"] for e in data["entries"]] == ["POST", "GET"]
    assert data["entries"][0]["outcome"] == "refused: not at this level"


def test_the_log_reads_the_older_half_after_a_rotation(served, home):
    path = proxy.log_path("gmail:personal", home)
    path.parent.mkdir(parents=True)
    path.with_suffix(".log.1").write_text("2026-10-05T09:00:00 GET /old 200\n")
    path.write_text("2026-10-06T09:00:00 GET /new 200\n")
    data = get(served, "/api/requests?ref=gmail:personal&limit=5").json()
    assert [e["path"] for e in data["entries"]] == ["/new", "/old"]


def test_a_log_is_only_for_a_connection_the_folder_holds(served, home):
    (home / "logs").mkdir(parents=True)
    (home / "elsewhere.log").write_text("2026-10-06T09:00:00 GET /private 200\n")
    for ref in ("../elsewhere", "gmail:nobody", ""):
        res = get(served, f"/api/requests?ref={ref}")
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


def test_no_address_looks_like_tracking_to_a_blocker(served):
    # blockers drop "/log?" addresses; the page then only said "Failed to fetch"
    js = get(served, "/page.js", token=None).text
    assert "/log?" not in js and "/api/requests?" in js


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


# ---- the buttons: connect, level, disconnect, add a site ------------------------------
#
# A stand-in `setu` plays the sign-in: it writes down how it was started,
# says what a real `connect --json` says, and reads its answers on stdin.

STAND_IN = r'''
import json, sys, time
args = sys.argv[1:]
with open(sys.argv[0] + ".argv", "a") as out:
    out.write(json.dumps(args) + "\n")
say = lambda **e: print(json.dumps(e), flush=True)
if args[0] == "disconnect":
    print(f"disconnected {args[1]}: revoked at the site, key deleted")
    sys.exit(0)
ref = (args[1] if args[1] != "--site" else args[2]) + ":" + args[args.index("--as") + 1]
say(event="started", ref=ref, level="read", level_label="Read only")
if "--slow" in open(sys.argv[0] + ".mode").read():
    time.sleep(30)
if "--site" in args:
    say(event="ask", question="Did you sign in?")
    if sys.stdin.readline().strip() != "yes":
        say(event="error", message="not signed in: nothing was saved")
        sys.exit(2)
elif "--paste" in args:
    say(event="url", url="https://accounts.example/o?x=1", paste=True)
    line = sys.stdin.readline().strip()
    say(event="pasted", address=line)
say(event="connected", ref=ref, email="me@example.com", level="read", level_label="Read only")
'''


@pytest.fixture
def stand_in(home, tmp_path, monkeypatch):
    script = tmp_path / "setu-stand-in.py"
    script.write_text(STAND_IN)
    (tmp_path / "setu-stand-in.py.mode").write_text("")
    client = tmp_path / "client.json"
    client.write_text("{}")
    monkeypatch.setenv("SETU_GOOGLE_CLIENT_FILE", str(client))
    monkeypatch.setenv("SETU_BROWSER", sys.executable)        # any program will do here
    seed(FileVault())
    api = page.Api(FileVault(), setu=[sys.executable, str(script)])
    api.script = script
    return api


def started(api) -> list[list[str]]:
    return [json.loads(line) for line in
            (api.script.parent / (api.script.name + ".argv")).read_text().splitlines()]


def finished(api, timeout: float = 10.0) -> dict:
    import time
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = api.signin.state()
        if any(e["event"] == "done" for e in state["events"]):
            return state
        time.sleep(0.05)
    raise AssertionError(f"the sign-in never finished: {api.signin.state()}")


def events(state) -> list[str]:
    return [e["event"] for e in state["events"]]


def test_connect_runs_setus_own_sign_in_at_the_level_asked(stand_in):
    stand_in.handle("POST", "/api/connect", {}, {"connector": "gmail", "account": "work",
                                                "level": "draft"})
    state = finished(stand_in)
    assert started(stand_in) == [["connect", "gmail", "--as", "work", "--json",
                                  "--level", "draft"]]
    assert events(state) == ["started", "connected", "done"]


def test_only_one_sign_in_at_a_time(stand_in):
    (stand_in.script.parent / (stand_in.script.name + ".mode")).write_text("--slow")
    stand_in.handle("POST", "/api/connect", {}, {"connector": "gmail"})
    with pytest.raises(page.ApiError) as caught:
        stand_in.handle("POST", "/api/connect", {}, {"connector": "gmail", "account": "b"})
    assert caught.value.code == 409
    stand_in.handle("POST", "/api/signin/cancel", {}, {})
    assert events(finished(stand_in))[-2:] == ["cancelled", "done"]


@pytest.mark.parametrize("body, code", [
    ({"connector": "nope"}, 404),
    ({"connector": "gmail", "level": "everything"}, 400),
    ({"connector": "gmail", "account": "../../x"}, 400),
    ({"connector": "gmail", "account": "a b"}, 400),
])
def test_a_connect_that_names_nothing_real_is_refused_before_anything_runs(
        stand_in, body, code):
    with pytest.raises(page.ApiError) as caught:
        stand_in.handle("POST", "/api/connect", {}, body)
    assert caught.value.code == code and stand_in.signin is None


def test_from_another_device_google_is_pasted_back_and_a_window_is_streamed(stand_in):
    stand_in.handle("POST", "/api/connect", {}, {"connector": "gmail"}, local=False)
    stand_in.handle("POST", "/api/signin/paste", {},
                    {"address": "http://127.0.0.1:5555/?code=abc&state=s"})
    state = finished(stand_in)
    assert "--paste" in started(stand_in)[0]
    assert {"event": "pasted", "address": "http://127.0.0.1:5555/?code=abc&state=s"} \
        in state["events"]
    stand_in.handle("POST", "/api/connect", {}, {"connector": "amazon"}, local=False)
    finished(stand_in)
    assert "--remote" in started(stand_in)[1]


def test_a_paste_that_is_not_an_address_never_reaches_setu(stand_in):
    stand_in.handle("POST", "/api/connect", {}, {"connector": "gmail"}, local=False)
    with pytest.raises(page.ApiError):
        stand_in.handle("POST", "/api/signin/paste", {}, {"address": "yes"})
    stand_in.handle("POST", "/api/signin/cancel", {}, {})
    finished(stand_in)


def test_adding_a_site_asks_the_person_and_needs_them_at_the_computer(stand_in):
    with pytest.raises(page.ApiError) as caught:
        stand_in.handle("POST", "/api/add-site", {}, {"site": "example.com"}, local=False)
    assert caught.value.code == 403 and stand_in.signin is None
    with pytest.raises(page.ApiError):
        stand_in.handle("POST", "/api/add-site", {}, {"site": "not a site"})
    stand_in.handle("POST", "/api/add-site", {}, {"site": "https://Example.com/shop"})
    import time
    while not any(e["event"] == "ask" for e in stand_in.signin.state()["events"]):
        time.sleep(0.05)
    with pytest.raises(page.ApiError):
        stand_in.handle("POST", "/api/signin/answer", {}, {"yes": "yes"})   # only true
    stand_in.handle("POST", "/api/signin/answer", {}, {"yes": True})
    assert events(finished(stand_in))[-2:] == ["connected", "done"]
    assert started(stand_in)[0][:3] == ["connect", "--site", "example.com"]


def test_disconnect_is_only_for_a_connection_the_folder_holds(stand_in):
    with pytest.raises(page.ApiError) as caught:
        stand_in.handle("POST", "/api/disconnect", {}, {"ref": "gmail:nobody"})
    assert caught.value.code == 404
    done = stand_in.handle("POST", "/api/disconnect", {}, {"ref": "gmail:personal"})[1]
    assert started(stand_in) == [["disconnect", "gmail:personal"]]
    assert "revoked" in done["said"]


def test_a_change_from_another_site_is_refused(served):
    for origin, code in (("https://evil.example", 403), (served.url.rstrip("/"), 404)):
        res = httpx.post(served.url + "api/nothing-here", json={},
                         headers={"Authorization": f"Bearer {GOOD}", "Origin": origin},
                         timeout=5)
        assert res.status_code == code


def test_a_named_embedder_may_send_changes(served):
    res = httpx.post(served.url + "api/nothing-here", json={},
                     headers={"Authorization": f"Bearer {GOOD}",
                              "Origin": "http://127.0.0.1:8000"}, timeout=5)
    assert res.status_code == 404           # past the Origin check, to the router


def test_the_pages_script_parses():
    import shutil
    import subprocess
    from importlib.resources import files
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    script = files("setu").joinpath("static", "page.js")
    done = subprocess.run([node, "--check", str(script)], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
