"""A browser-road sign-in from another device: the window, streamed.

The bias: THE LINK IS ONE PERSON'S, FOR A FEW MINUTES, AND PROVES NOTHING
BY ITSELF. It opens on the first device only; it stops working when the
time is up or the sign-in is done; and a connection is saved only when
the sign-in cookie is really there -- in a locked folder, packed away at
once.

Chrome is a fake here that speaks the DevTools protocol on fds 3 and 4,
like the real one under --remote-debugging-pipe: it sends one frame, and
sets the sign-in cookie when Enter is pressed after some text.
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
inp, out = os.fdopen(3, "rb", buffering=0), os.fdopen(4, "wb", buffering=0)
typed, cookies, buf = [], [], b""
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
        elif method == "Input.insertText": typed.append(m["params"]["text"])
        elif method == "Input.dispatchKeyEvent" and m["params"]["type"] == "keyDown" and typed:
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
    window.act({"type": "text", "text": "me@example.com"})
    assert [m for m, _ in sent] == ["Runtime.evaluate", "Input.insertText"]
    script = sent[0][1]["expression"]
    assert "document.activeElement" in script and ".focus()" in script
    assert sent[1][1] == {"text": "me@example.com"}


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
