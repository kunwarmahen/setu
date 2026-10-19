"""A sign-in PAGE (Google's, Home Assistant's) from another device, in the window.

The bias: THE PAGE'S RETURN TO 127.0.0.1 LANDS ON THIS COMPUTER, AND
NOTHING OF IT IS KEPT IN A BROWSER. A phone that opened Google's link
went to its own 127.0.0.1 and failed, and a chat app's browser hid the
address that had to be copied back. In the window the browser runs here,
so the listener hears the code itself; the profile it ran on is gone
afterwards; and a sign-in that ended some other way (a paste, the time)
leaves no browser behind.

Chrome is a fake that speaks the DevTools protocol on fds 3 and 4. When
Enter is pressed after some typing, it does what Google's page does at
the end: it goes to the ``redirect_uri`` with a code and the state.
"""

from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path
from urllib.parse import quote

import httpx
import pytest
from setu import google, remote

CHROME = r'''
import json, os, sys, urllib.parse, urllib.request
profile = next(a.split("=", 1)[1] for a in sys.argv if a.startswith("--user-data-dir="))
started = os.environ.get("FAKE_STARTED")
if started:
    open(started, "w").write(json.dumps({"profile": profile,
        "headless": "--headless=new" in sys.argv, "display": os.environ.get("DISPLAY")}))
inp, out = os.fdopen(3, "rb", buffering=0), os.fdopen(4, "wb", buffering=0)
typed, buf, href = [], b"", "about:blank"
def send(m): out.write(json.dumps(m).encode() + b"\0")
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
        elif method == "Page.navigate": href = m["params"]["url"]
        elif (method == "Input.dispatchKeyEvent" and m["params"]["type"] == "keyDown"
              and m["params"].get("text") not in (None, "\r")):
            typed.append(m["params"]["text"])
        elif (method == "Input.dispatchKeyEvent" and m["params"]["type"] == "keyDown"
              and m["params"]["key"] == "Enter" and typed):
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(href).query)
            href = (q["redirect_uri"][0] + "?code=CODE&state=" + q["state"][0])
            urllib.request.urlopen(href).read()      # as the page's end does
        elif method == "Runtime.evaluate" and m["params"]["expression"] == "location.href":
            result = {"result": {"value": href}}
        send({"id": m["id"], "result": result})
        if method == "Browser.close": sys.exit(0)
'''


@pytest.fixture
def chrome(tmp_path, monkeypatch):
    path = tmp_path / "chrome"
    path.write_text(f"#!{sys.executable}\n{CHROME}")
    path.chmod(0o755)
    monkeypatch.setenv(remote.ENV_HOST, "127.0.0.1")
    monkeypatch.delenv(remote.ENV_URL, raising=False)
    monkeypatch.delenv(remote.ENV_PORT, raising=False)
    monkeypatch.delenv(remote.ENV_NAME, raising=False)
    # a screen that is there: nothing is started, and the window is headed
    monkeypatch.setenv(remote.ENV_DISPLAY, ":77")
    monkeypatch.setenv("FAKE_STARTED", str(tmp_path / "started.json"))
    monkeypatch.setattr(remote, "LOOK_EVERY", 0.2)
    monkeypatch.setattr(remote, "KEY_GAP", (0, 0))
    return str(path)


def page_for(listener: google.RedirectListener) -> str:
    return (f"https://accounts.test/o/auth?redirect_uri={quote(listener.redirect_uri)}"
            "&state=STATE")


def the_person(link: str) -> None:
    me = httpx.Client(timeout=5)
    me.get(link)
    me.post(link + "/input", json={"type": "text", "text": "me@example.com"})
    me.post(link + "/input", json={"type": "key", "key": "Enter"})


def test_the_pages_return_lands_here_and_the_code_is_heard_without_a_paste(chrome, tmp_path):
    listener = google.RedirectListener()
    links: list[str] = []
    window = remote.SignInPage(
        lambda url, _t: (links.append(url),
                         threading.Thread(target=the_person, args=(url,), daemon=True).start()),
        site="Gmail", browser=chrome, open_for=20)
    threading.Thread(target=window, args=(page_for(listener),), daemon=True).start()
    try:
        assert listener.wait("STATE", timeout=20) == "CODE"
    finally:
        window.close()
        listener.close()
    assert links and "/w/" in links[0]
    started = json.loads((tmp_path / "started.json").read_text())
    assert started["headless"] is False and started["display"] == ":77"
    assert not Path(started["profile"]).exists()       # nothing of it kept


def test_a_sign_in_that_ended_another_way_leaves_no_browser_behind(chrome, tmp_path):
    listener = google.RedirectListener()
    links: list[str] = []
    window = remote.SignInPage(lambda url, _t: links.append(url), site="Gmail",
                               browser=chrome, open_for=60)
    runner = threading.Thread(target=window, args=(page_for(listener),), daemon=True)
    runner.start()
    deadline = time.monotonic() + 10
    while not links and time.monotonic() < deadline:
        time.sleep(0.05)
    window.close()                     # an address pasted back, say
    listener.close()
    runner.join(5)
    assert not runner.is_alive()
    started = json.loads((tmp_path / "started.json").read_text())
    assert not Path(started["profile"]).exists()


def test_the_link_says_the_house_name_not_the_address_listened_on(chrome, monkeypatch):
    monkeypatch.setenv(remote.ENV_NAME, "beast.local")
    listener = google.RedirectListener()
    links: list[str] = []
    window = remote.SignInPage(lambda url, _t: links.append(url), site="Gmail",
                               browser=chrome, open_for=0.5)
    window(page_for(listener))
    listener.close()
    assert links[0].startswith("http://beast.local:")


def test_listening_everywhere_is_fine_once_the_link_has_a_name(monkeypatch):
    monkeypatch.setenv(remote.ENV_HOST, "0.0.0.0")
    monkeypatch.delenv(remote.ENV_URL, raising=False)
    monkeypatch.setenv(remote.ENV_NAME, "beast.local")
    assert remote.settings() == ("0.0.0.0", 0, None)
    assert remote.reaches_another_device()


def test_a_window_on_this_computer_alone_reaches_no_other_device(monkeypatch):
    for key in (remote.ENV_URL, remote.ENV_NAME):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv(remote.ENV_HOST, "127.0.0.1")
    assert not remote.reaches_another_device()
    monkeypatch.setenv(remote.ENV_HOST, "192.168.1.44")
    assert remote.reaches_another_device()
