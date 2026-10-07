"""A browser-road sign-in from another device: the window, streamed.

The bias: THE LINK IS ONE PERSON'S, FOR A FEW MINUTES, AND PROVES NOTHING
BY ITSELF. It opens on the first device only; it stops working when the
time is up or the sign-in is done; and a connection is saved only when
the sign-in cookie is really there -- in a locked folder, packed away at
once.

Chrome is a fake here that speaks the DevTools protocol on fds 3 and 4,
like the real one under --remote-debugging-pipe: it sends one frame, and
sets the sign-in cookie, and leaves the sign-in page, when Enter is
pressed after some text typed key by key. It writes down how it was
started (headless or not, which display), for the headed window's tests.

And: A SITE THAT TURNS AWAY A HEADLESS BROWSER NEVER GETS ONE. X's
manifest says ``headed``; the window ran headless anyway and X refused
it. Nor does it get the owner's own screen, or text that arrives with no
key presses, or a phone whose client hints say it is a Linux desktop.
"""

from __future__ import annotations

import json
import os
import sys
import threading

import httpx
import pytest
from setu import connections, remote, seal
from setu.browser import BrowserSignInFailed
from setu.manifest import parse
from setu.vault import FileVault

CHROME = r'''
import json, os, sqlite3, sys
profile = next(a.split("=", 1)[1] for a in sys.argv if a.startswith("--user-data-dir="))
os.makedirs(os.path.join(profile, "Default"), exist_ok=True)
open(os.path.join(profile, "Local State"), "w").write("{}")
started = os.environ.get("FAKE_STARTED")
if started:
    open(started, "w").write(json.dumps({
        "headless": "--headless=new" in sys.argv, "display": os.environ.get("DISPLAY"),
        "says_automated": "--disable-blink-features=AutomationControlled" not in sys.argv}))
inp, out = os.fdopen(3, "rb", buffering=0), os.fdopen(4, "wb", buffering=0)
typed, cookies, buf = [], [], b""
# a cookie an earlier session left: there, while the page still asks
if os.environ.get("FAKE_STALE_COOKIE"): cookies.append({"name": "session", "domain": "shop.test"})
asking = True
def send(m): out.write(json.dumps(m).encode() + b"\0")
JPEG = ("/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAP//////////////////////////////////////////////"
        "////////////////////////////////////////2wBDAf//////////////////////////////////"
        "////////////////////////////////////////////////////wAARCAABAAEDASIAAhEBAxEB/8QA"
        "FAABAAAAAAAAAAAAAAAAAAAACP/EABQQAQAAAAAAAAAAAAAAAAAAAAD/xAAUAQEAAAAAAAAAAAAAAAAA"
        "AAAA/8QAFBEBAAAAAAAAAAAAAAAAAAAAAP/aAAwDAQACEQMRAD8AKp//2Q==")
while True:
    chunk = inp.read(65536)
    if not chunk: break
    buf += chunk
    while b"\0" in buf:
        raw, buf = buf.split(b"\0", 1)
        m = json.loads(raw); method, result = m["method"], {}
        if method == "Target.createTarget": result = {"targetId": "T1"}
        elif method == "Target.attachToTarget": result = {"sessionId": "S1"}
        elif method == "Browser.getVersion": result = {"product": "Chrome/130.0"}
        elif (method == "Input.dispatchKeyEvent" and m["params"]["type"] == "keyDown"
              and m["params"].get("text") not in (None, "\r")):
            typed.append(m["params"]["text"])
        elif method == "Runtime.evaluate" and "location.pathname" in m["params"]["expression"]:
            result = {"result": {"value": asking}}
        elif (method == "Input.dispatchKeyEvent" and m["params"]["type"] == "keyDown"
              and m["params"]["key"] == "Enter" and typed):
            asking = False
            cookies.append({"name": "session", "domain": "shop.test"})
            db = sqlite3.connect(os.path.join(profile, "Default", "Cookies"))
            db.execute("create table if not exists cookies (host_key text, name text)")
            db.execute("insert into cookies values ('.shop.test', 'session')"); db.commit()
        elif method == "Storage.getCookies": result = {"cookies": cookies}
        send({"id": m["id"], "result": result})
        if method == "Page.startScreencast":
            send({"method": "Page.screencastFrame", "sessionId": "S1",
                  "params": {"data": JPEG, "sessionId": 1, "metadata": {}}})
        if method == "Browser.close": sys.exit(0)
'''

SHOP = parse({"id": "shop", "name": "Shop", "road": "browser", "auth": "browser",
              "hosts": ["shop.test"], "levels": {"read": {}},
              "browser": {"start_url": "https://shop.test/", "login_url": "https://shop.test/",
                          "signed_in": ["session"]}})


@pytest.fixture
def chrome(tmp_path, monkeypatch):
    path = tmp_path / "chrome"
    path.write_text(f"#!{sys.executable}\n{CHROME}")
    path.chmod(0o755)
    monkeypatch.setenv(remote.ENV_HOST, "127.0.0.1")
    monkeypatch.delenv(remote.ENV_URL, raising=False)
    monkeypatch.delenv(remote.ENV_PORT, raising=False)
    monkeypatch.setattr(remote, "LOOK_EVERY", 0.2)
    monkeypatch.setattr(remote, "KEY_GAP", (0, 0))
    return str(path)


def sign_in(chrome: str, phone, *, open_for: float = 20.0):
    """connect_browser with the streamed window; ``phone(link)`` plays the person."""
    links: list[str] = []

    def on_link(url, _until):
        links.append(url)
        threading.Thread(target=phone, args=(url,), daemon=True).start()
    window = remote.window_for(on_link, site="Shop", patterns=("session",),
                               hosts=("shop.test",), open_for=open_for)
    entry = connections.connect_browser(SHOP, "personal", level=None, vault=FileVault(),
                                        browser=chrome, window=window)
    return entry, links


def person(seen: dict):
    def phone(link: str) -> None:
        me = httpx.Client(timeout=5)
        seen["page"] = me.get(link).status_code
        seen["other_device"] = httpx.get(link).status_code
        seen["stranger_input"] = httpx.post(link + "/input", json={"type": "text",
                                                                   "text": "x"}).status_code
        with me.stream("GET", link + "/stream") as r:
            got = b""
            for chunk in r.iter_bytes():
                got += chunk
                if b"\xff\xd9" in got:
                    break
        seen["frame"] = got.startswith(b"--frame") and b"image/jpeg" in got
        me.post(link + "/input", json={"type": "tap", "fx": 0.5, "fy": 0.1})
        me.post(link + "/input", json={"type": "text", "text": "me@example.com"})
        me.post(link + "/input", json={"type": "key", "key": "Enter"})
    return phone


def test_the_person_signs_in_through_the_stream_and_it_is_saved(home, chrome):
    seen: dict = {}
    entry, links = sign_in(chrome, person(seen))
    assert entry["auth"] == "browser" and entry["email"] == "shop.test"
    assert FileVault().get("shop:personal")["profile"].endswith("shop-personal")
    assert seen == {"page": 200, "other_device": 409, "stranger_input": 403, "frame": True}


def _listening(url: str) -> bool:
    try:
        httpx.get(url, timeout=1)
        return True
    except httpx.HTTPError:
        return False


def test_the_link_stops_working_once_the_sign_in_is_done(home, chrome):
    entry, links = sign_in(chrome, person({}))
    assert not _listening(links[0])


def test_nobody_signing_in_saves_nothing(home, chrome):
    with pytest.raises(connections.ConnectionFailed, match="nobody signed in"):
        sign_in(chrome, lambda link: httpx.get(link), open_for=1.0)
    assert FileVault().get("shop:personal") is None


def test_saying_done_without_signing_in_saves_nothing(home, chrome):
    def phone(link):
        me = httpx.Client(timeout=5)
        me.get(link)
        me.post(link + "/done", json={})
    with pytest.raises(connections.ConnectionFailed, match="has not signed you in"):
        sign_in(chrome, phone)


def test_a_cookie_left_from_before_is_not_a_sign_in(home, chrome, monkeypatch):
    """Amazon keeps its sign-in cookie while asking for the password again:
    the window closed on the password page, and nothing had been signed in."""
    monkeypatch.setenv("FAKE_STALE_COOKIE", "1")
    with pytest.raises(connections.ConnectionFailed, match="nobody signed in"):
        sign_in(chrome, lambda link: httpx.get(link), open_for=1.5)


def test_with_a_cookie_left_from_before_signing_in_still_works(home, chrome, monkeypatch):
    monkeypatch.setenv("FAKE_STALE_COOKIE", "1")
    entry, _links = sign_in(chrome, person({}))
    assert entry["email"] == "shop.test"


def test_a_page_between_pages_is_looked_at_again():
    window = object.__new__(remote.Window)
    window.hosts, window.patterns = ("shop.test",), ("session",)
    window.browser = type("B", (), {"call": lambda self, m, p=None: {
        "cookies": [{"name": "session", "domain": ".shop.test"}]}})()
    for value, signed in ((None, False), (True, False), (False, True)):
        window._value = lambda script, v=value: v
        assert window.look() is signed


def test_listening_everywhere_needs_the_address_a_phone_opens(monkeypatch):
    monkeypatch.setenv(remote.ENV_HOST, "0.0.0.0")
    monkeypatch.delenv(remote.ENV_URL, raising=False)
    with pytest.raises(remote.WindowSettingsError, match="SETU_WINDOW_URL"):
        remote.settings()
    monkeypatch.setenv(remote.ENV_URL, "https://door.example.net:8443/")
    assert remote.settings() == ("0.0.0.0", 0, "https://door.example.net:8443/")


def test_the_link_names_the_owners_public_address(home, chrome, monkeypatch):
    monkeypatch.setenv(remote.ENV_URL, "https://door.example.net")
    got: list[str] = []
    window = remote.window_for(lambda url, _t: got.append(url), site="Shop",
                               patterns=("session",), hosts=("shop.test",), open_for=0.5)
    with pytest.raises(BrowserSignInFailed):
        window(chrome, home / "profiles" / "shop-personal", "https://shop.test/")
    assert got[0].startswith("https://door.example.net/w/")


def test_in_a_locked_folder_the_new_sign_in_is_packed_away(home, chrome, monkeypatch):
    import subprocess
    monkeypatch.delenv(seal.ENV_KEY, raising=False)
    seal.create(FileVault().home, "correct horse battery")
    sites = FileVault().home / "sites"
    sites.mkdir()
    (sites / "shop.toml").write_text(
        'id = "shop"\nname = "Shop"\nroad = "browser"\nauth = "browser"\n'
        'hosts = ["shop.test"]\n[levels.read]\n[browser]\nstart_url = "https://shop.test/"\n'
        'login_url = "https://shop.test/"\nsigned_in = ["session"]\n')
    proc = subprocess.Popen([sys.executable, "-m", "setu.cli", "connect", "shop", "--json",
                             "--remote", "--browser", chrome], stdout=subprocess.PIPE,
                            text=True, env=dict(os.environ))
    for line in proc.stdout:
        event = json.loads(line)
        if event["event"] == "link":
            person({})(event["url"])
        if event["event"] in ("connected", "error"):
            break
    proc.wait(timeout=30)
    assert event["event"] == "connected", event
    profiles = FileVault().home / "profiles"
    assert seal.sealed_profiles(profiles) == ["shop-personal"]
    assert not (profiles / "shop-personal").exists()


def test_typed_text_lands_in_a_box_even_when_nobody_tapped_one():
    """On a phone, a person types under the picture and presses Send
    without tapping the page's box: typing into nothing did nothing."""
    window = object.__new__(remote.Window)
    window.size = (412, 700)
    sent = []
    window._send = lambda method, params=None: sent.append((method, params)) or {}
    window.act({"type": "text", "text": "me"})
    assert [m for m, _ in sent] == ["Runtime.evaluate"] + ["Input.dispatchKeyEvent"] * 4
    script = sent[0][1]["expression"]
    assert "document.activeElement" in script and ".focus()" in script


def test_text_is_typed_key_by_key_as_a_keyboard_sends_it(monkeypatch):
    """Pasted text fires no key events: a page listening for them saw a
    box fill by itself. Each character is a key-down with its text, then
    a key-up, at a person's pace."""
    monkeypatch.setattr(remote, "KEY_GAP", (0, 0))
    window, sent = _recording_window()
    window.type("a1 @")
    keys = [p for m, p in sent if m == "Input.dispatchKeyEvent"]
    assert [(k["type"], k["key"]) for k in keys] == [
        ("keyDown", "a"), ("keyUp", "a"), ("keyDown", "1"), ("keyUp", "1"),
        ("keyDown", " "), ("keyUp", " "), ("keyDown", "@"), ("keyUp", "@")]
    assert [k["text"] for k in keys if k["type"] == "keyDown"] == ["a", "1", " ", "@"]
    assert keys[0]["code"] == "KeyA" and keys[0]["windowsVirtualKeyCode"] == 65
    assert keys[2]["code"] == "Digit1" and "code" not in keys[6]
    assert "Input.insertText" not in [m for m, _ in sent]


def test_the_phone_says_the_same_thing_in_its_user_agent_and_its_hints():
    """A user agent that says Android while navigator.platform and the
    client hints say Linux is two answers to one question."""
    agent = remote.phone_agent("HeadlessChrome/130.0.6723.58")
    assert "Android" in agent["userAgent"] and "Headless" not in agent["userAgent"]
    assert "Chrome/130.0.6723.58 Mobile" in agent["userAgent"]
    assert agent["platform"].startswith("Linux arm")
    hints = agent["userAgentMetadata"]
    assert hints["platform"] == "Android" and hints["mobile"] is True
    assert {b["brand"]: b["version"] for b in hints["brands"]}["Google Chrome"] == "130"
    assert not any("Headless" in b["brand"] for b in hints["brands"])
    chromium = remote.phone_agent("Chromium/131.0.1")["userAgentMetadata"]["brands"]
    assert [b["brand"] for b in chromium] == ["Not)A;Brand", "Chromium"]


def _fake_xvfb(tmp_path, monkeypatch, *, display="7") -> None:
    """An Xvfb that reports a display on -displayfd, then waits to be stopped."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    xvfb = bin_dir / "Xvfb"
    xvfb.write_text(f"#!{sys.executable}\nimport os, sys, time\n"
                    "fd = int(sys.argv[sys.argv.index('-displayfd') + 1])\n"
                    f"os.write(fd, b'{display}\\n'); os.close(fd)\ntime.sleep(60)\n")
    xvfb.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")


def _headed_window(home, chrome, tmp_path, monkeypatch, *, headed: bool) -> dict:
    started = tmp_path / "started.json"
    monkeypatch.setenv("FAKE_STARTED", str(started))
    monkeypatch.setenv("DISPLAY", ":0")            # the owner's own screen
    window = remote.window_for(lambda _u, _t: None, site="X", patterns=("session",),
                               hosts=("shop.test",), open_for=0.5, headed=headed)
    with pytest.raises(BrowserSignInFailed, match="nobody signed in"):
        window(chrome, home / "profiles" / "x-personal", "https://shop.test/")
    return json.loads(started.read_text())


def test_a_site_that_wants_a_window_gets_one_on_a_screen_nobody_sees(
        home, chrome, tmp_path, monkeypatch):
    _fake_xvfb(tmp_path, monkeypatch, display="7")
    assert _headed_window(home, chrome, tmp_path, monkeypatch, headed=True) == {
        "headless": False, "display": ":7", "says_automated": False}


def test_any_other_site_stays_headless(home, chrome, tmp_path, monkeypatch):
    seen = _headed_window(home, chrome, tmp_path, monkeypatch, headed=False)
    assert seen["headless"] is True and seen["says_automated"] is False


def test_with_no_xvfb_a_site_that_wants_a_window_is_refused_not_run_headless(
        home, chrome, tmp_path, monkeypatch):
    monkeypatch.setattr(remote.shutil, "which",
                        lambda name: None if name == "Xvfb" else chrome)
    window = remote.window_for(lambda _u, _t: None, site="X", patterns=("session",),
                               hosts=("shop.test",), open_for=0.5, headed=True)
    with pytest.raises(BrowserSignInFailed, match="install Xvfb"):
        window(chrome, home / "profiles" / "x-personal", "https://shop.test/")


def _recording_window(value=None):
    window = object.__new__(remote.Window)
    window.size = (412, 700)
    sent = []

    def send(method, params=None):
        sent.append((method, params))
        return {"result": {"value": value}} if method == "Runtime.evaluate" else {}
    window._send = send
    return window, sent


def test_enter_in_a_form_that_does_not_submit_presses_its_button(monkeypatch):
    """Amazon's password page ignored an Enter from outside; its own
    button always works. The page's own submission is waited for first."""
    monkeypatch.setattr(remote, "ENTER_GRACE", 0)
    window, sent = _recording_window("form")
    window.act({"type": "key", "key": "Enter"})
    kinds = [(m, (p or {}).get("type")) for m, p in sent]
    assert kinds == [("Runtime.evaluate", None), ("Input.dispatchKeyEvent", "keyDown"),
                     ("Input.dispatchKeyEvent", "keyUp"), ("Runtime.evaluate", None)]
    down = sent[1][1]
    assert down["code"] == "Enter" and down["text"] == "\r"
    assert sent[3][1]["expression"] == remote.SUBMIT_IF_NOT
    assert "__setuSubmitted !== false" in remote.SUBMIT_IF_NOT     # never twice


def test_enter_outside_a_form_and_other_keys_are_only_keys(monkeypatch):
    monkeypatch.setattr(remote, "ENTER_GRACE", 0)
    window, sent = _recording_window("none")
    window.act({"type": "key", "key": "Enter"})
    window.act({"type": "key", "key": "Backspace"})
    assert [p["expression"] for m, p in sent if m == "Runtime.evaluate"] == [
        remote.WATCH_SUBMIT]
