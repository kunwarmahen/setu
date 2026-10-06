"""Signing in to a browser-road site from somewhere else: a window, streamed.

Amazon and X have no sign-in link a phone can finish (Google's, pasted
back, is notes in dvara). The connection IS a browser profile on the
computer running Setu, so the sign-in has to happen in a browser there.
For a person who isn't at that computer, Setu streams it: the browser
runs on the profile, and a page Setu serves shows them a live picture of
it and passes back their taps and typing. They sign in as they would on
their phone; the cookies land in their profile; nothing else changes.

    phone ──GET /w/<token>  (the page)──────────▶ setu connect --remote
          ◀──/stream: JPEG frames (MJPEG)────────   │ Chrome, on their profile,
          ──POST /input: tap, scroll, text, key──▶  │ driven over a private pipe
                                                    └ (--remote-debugging-pipe)

THE BROWSER IS DRIVEN OVER A PIPE, NOT A PORT. ``--remote-debugging-pipe``
gives Setu the DevTools protocol on two inherited file descriptors: no
port that another program on the machine could connect to and take over
a browser holding somebody's session. Frames come from
``Page.startScreencast``; taps are mouse clicks at the same place; text
is ``Input.insertText``, into the box they tapped -- or, when nothing
that takes text has focus, the page's first visible empty box. On a
phone people type under the picture and press Send without tapping the
page first, and text sent to nothing went nowhere, silently. And they
press their keyboard's Go rather than the page's Enter button, so Go in
that box sends the text and then presses Enter, in that order. Enter in
a form that does not submit by itself (Amazon's password page ignored
it) presses the form's own button. The page is shown at the phone's own
size, as a phone (``Emulation.setDeviceMetricsOverride`` and a mobile
user agent), so it reads like their own browser would.

WHO CAN OPEN IT. The link carries a random token, works for ten minutes,
and binds to the FIRST device that opens it (a cookie): a second one is
refused. The server stops when they're signed in, when they say they're
done, or when the time is up. The address it listens on and the address
in the link are the owner's choice (``SETU_WINDOW_HOST``,
``SETU_WINDOW_PORT``, ``SETU_WINDOW_URL``):

* the computer's own address on the home network: plain HTTP, so what
  they type crosses the Wi-Fi unencrypted beyond the Wi-Fi's own
  encryption -- for people at home;
* a Tailscale address: encrypted end to end, nothing on the internet;
* behind the owner's own HTTPS (a tunnel, a reverse proxy): listen on
  127.0.0.1 and put the public address in ``SETU_WINDOW_URL``.

SIGNED IN MEANS A SIGN-IN COOKIE, as at the machine: the manifest's
``signed_in`` names, read from the running browser
(``Storage.getCookies``, names only). A site Setu wrote the rules for
itself (``--site``) has no names to look for and is signed in to at the
machine.
"""

from __future__ import annotations

import base64
import fcntl
import fnmatch
import json
import os
import secrets
import shutil
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from setu.browser import COOKIE_KEY_ARG, BrowserSignInFailed, child_env

ENV_HOST, ENV_PORT, ENV_URL = "SETU_WINDOW_HOST", "SETU_WINDOW_PORT", "SETU_WINDOW_URL"
#: How long the link works.
OPEN_FOR = 600.0
#: How often the running browser is asked whether a sign-in cookie is set.
LOOK_EVERY = 2.0
#: The size the page starts at, before the phone says its own.
START_SIZE = (412, 800)
MOBILE_UA = ("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like "
             "Gecko) Chrome/{version} Mobile Safari/537.36")
KEYS = {"Enter": (13, "\r"), "Backspace": (8, ""), "Tab": (9, "\t")}
#: Before Enter: note whether a form submits, and whether Enter is pressed
#: in one at all.
WATCH_SUBMIT = """(() => {
  window.__setuSubmitted = false;
  addEventListener("submit", () => { window.__setuSubmitted = true; },
                   {capture: true, once: true});
  const a = document.activeElement;
  return a && a.form ? "form" : "none";
})()"""
#: After Enter, when it was pressed in a form and nothing submitted: press
#: the form's own submit button, as a tap on it would. A page that moved on
#: has no ``__setuSubmitted`` left, so nothing is pressed twice.
SUBMIT_IF_NOT = """(() => {
  const a = document.activeElement;
  if (window.__setuSubmitted !== false || !a || !a.form) return "left";
  const button = [...a.form.elements].find(el => el.type === "submit" && !el.disabled);
  if (button) button.click(); else a.form.requestSubmit();
  return "submitted";
})()"""
#: How long a page has to act on Enter before its form is submitted for it.
ENTER_GRACE = 0.6
#: Run before typed text: when nothing that takes text has focus, focus the
#: first visible box that does -- an empty one first. On a phone a person
#: types in the box under the picture and presses Send, often without
#: tapping the page's own box; typing into nothing did nothing, silently.
#: A box they tapped into is left alone.
FOCUS_A_BOX = """(() => {
  const takes = el => el && (el.isContentEditable || el.tagName === "TEXTAREA" ||
    (el.tagName === "INPUT" &&
     !/^(button|submit|reset|checkbox|radio|hidden|file|image|range|color)$/i.test(el.type)));
  if (takes(document.activeElement)) return "kept";
  const usable = el => { const r = el.getBoundingClientRect();
    return takes(el) && !el.disabled && !el.readOnly && r.width > 0 && r.height > 0 &&
           getComputedStyle(el).visibility !== "hidden"; };
  const boxes = [...document.querySelectorAll("input, textarea, [contenteditable]")]
    .filter(usable);
  const box = boxes.find(el => !el.value) || boxes[0];
  if (!box) return "none";
  box.focus();
  return "focused";
})()"""


class WindowSettingsError(ValueError):
    """The owner's window settings cannot make a link anybody can open."""


def settings() -> tuple[str, int, str | None]:
    """(host to listen on, port -- 0 for any, the link's base or None)."""
    host = os.environ.get(ENV_HOST, "").strip() or "127.0.0.1"
    raw = os.environ.get(ENV_PORT, "").strip()
    try:
        port = int(raw) if raw else 0
    except ValueError:
        raise WindowSettingsError(f"{ENV_PORT} must be a port number, not {raw!r}") from None
    url = os.environ.get(ENV_URL, "").strip() or None
    if host in ("0.0.0.0", "::") and url is None:
        raise WindowSettingsError(f"{ENV_HOST}={host} listens everywhere, so say the address "
                                  f"a phone opens in {ENV_URL}")
    return host, port, url


# ---- the browser, over a pipe ---------------------------------------------------------


def _high(fd: int) -> int:
    """``fd`` again, numbered 10 or above; the low one closed."""
    moved = fcntl.fcntl(fd, fcntl.F_DUPFD, 10)
    os.close(fd)
    return moved


class Browser:
    """Chrome on a profile, spoken to over ``--remote-debugging-pipe``."""

    def __init__(self, program: str, profile: Path, *, headless: bool = True,
                 extra: list[str] | None = None) -> None:
        to_chrome_r, to_chrome_w = os.pipe()
        from_chrome_r, from_chrome_w = os.pipe()
        # Chrome's two ends moved above 9, so putting them on 3 and 4 in the
        # shell below can never overwrite one with the other
        to_chrome_r, from_chrome_w = (_high(fd) for fd in (to_chrome_r, from_chrome_w))
        argv = [program, f"--user-data-dir={profile}", "--no-first-run",
                "--no-default-browser-check", COOKIE_KEY_ARG, "--remote-debugging-pipe",
                *(["--headless=new"] if headless else []), *(extra or []), "about:blank"]
        # the protocol is on fds 3 and 4 in Chrome: a few lines of Python
        # put the two inherited ends there and become Chrome (a shell
        # cannot: dash takes one-digit descriptors only)
        trampoline = ("import os,sys; r,w=int(sys.argv[1]),int(sys.argv[2]); os.dup2(r,3); "
                      "os.dup2(w,4); os.close(r); os.close(w); "
                      "os.execvp(sys.argv[3], sys.argv[3:])")
        self.proc = subprocess.Popen(
            [sys.executable, "-c", trampoline, str(to_chrome_r), str(from_chrome_w), *argv],
            pass_fds=(to_chrome_r, from_chrome_w),
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True, env=child_env())
        os.close(to_chrome_r)
        os.close(from_chrome_w)
        self._out = os.fdopen(to_chrome_w, "wb", buffering=0)
        self._in = os.fdopen(from_chrome_r, "rb", buffering=0)
        self._next = 0
        self._lock = threading.Lock()
        self._waiting: dict[int, tuple[threading.Event, list[dict[str, Any]]]] = {}
        self.on_event: Callable[[dict[str, Any]], None] = lambda _m: None
        self.gone = threading.Event()
        threading.Thread(target=self._read, daemon=True, name="setu-window-cdp").start()

    def _read(self) -> None:
        buffer = b""
        try:
            while chunk := self._in.read(65536):
                buffer += chunk
                while b"\0" in buffer:
                    raw, buffer = buffer.split(b"\0", 1)
                    message = json.loads(raw)
                    waiter = self._waiting.pop(message.get("id", -1), None)
                    if waiter is not None:
                        waiter[1].append(message)
                        waiter[0].set()
                    else:
                        self.on_event(message)
        finally:
            self.gone.set()
            for event, _box in list(self._waiting.values()):
                event.set()

    def call(self, method: str, params: dict[str, Any] | None = None,
             session: str | None = None, timeout: float = 15.0) -> dict[str, Any]:
        with self._lock:
            self._next += 1
            mid = self._next
            done, box = threading.Event(), []
            self._waiting[mid] = (done, box)
            message: dict[str, Any] = {"id": mid, "method": method, "params": params or {}}
            if session:
                message["sessionId"] = session
            self._out.write(json.dumps(message).encode() + b"\0")
        if not done.wait(timeout) or not box:
            raise BrowserSignInFailed(f"the browser did not answer {method}")
        if "error" in box[0]:
            raise BrowserSignInFailed(f"{method}: {box[0]['error'].get('message')}")
        return box[0].get("result") or {}

    def close(self) -> None:
        """Ask Chrome to close, so it writes its cookies; insist if it won't."""
        if self.proc.poll() is None:
            try:
                self.call("Browser.close", timeout=5)
            except (BrowserSignInFailed, OSError):
                pass
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        for stream in (self._out, self._in):
            try:
                stream.close()
            except OSError:
                pass


# ---- one sign-in --------------------------------------------------------------------------


class Window:
    """The browser, the page that shows it, and whether they're signed in."""

    def __init__(self, browser: Browser, url: str, patterns: tuple[str, ...],
                 hosts: tuple[str, ...]) -> None:
        self.browser, self.url, self.patterns, self.hosts = browser, url, patterns, hosts
        self.size = START_SIZE
        self.frame: bytes | None = None
        self.frames = threading.Condition()
        self.signed_in = threading.Event()
        self.done = threading.Event()
        browser.on_event = self._event
        target = browser.call("Target.createTarget", {"url": "about:blank"})["targetId"]
        self.session = browser.call("Target.attachToTarget",
                                    {"targetId": target, "flatten": True})["sessionId"]
        version = browser.call("Browser.getVersion").get("product", "Chrome/130").split("/")[-1]
        self._send("Network.setUserAgentOverride", {"userAgent": MOBILE_UA.format(
            version=version)})
        self.resize(*START_SIZE)
        self._send("Page.enable")
        self._send("Page.navigate", {"url": url})

    def _send(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        return self.browser.call(method, params, session=self.session)

    def resize(self, width: int, height: int) -> None:
        width, height = max(280, min(width, 1000)), max(400, min(height, 2000))
        self.size = (width, height)
        self._send("Emulation.setDeviceMetricsOverride", {
            "width": width, "height": height, "deviceScaleFactor": 2, "mobile": True})
        self._send("Page.startScreencast", {"format": "jpeg", "quality": 60,
                                            "maxWidth": width * 2, "maxHeight": height * 2})

    def _event(self, message: dict[str, Any]) -> None:
        if message.get("method") == "Page.screencastFrame":
            params = message["params"]
            with self.frames:
                self.frame = base64.b64decode(params["data"])
                self.frames.notify_all()
            threading.Thread(target=self._ack, args=(params["sessionId"],),
                             daemon=True).start()

    def _ack(self, frame_session: int) -> None:
        try:
            self._send("Page.screencastFrameAck", {"sessionId": frame_session})
        except (BrowserSignInFailed, OSError, ValueError):
            pass

    def act(self, event: dict[str, Any]) -> None:
        """One thing the person did on the page."""
        kind = event.get("type")
        width, height = self.size
        if kind == "tap":
            x, y = float(event["fx"]) * width, float(event["fy"]) * height
            for phase in ("mousePressed", "mouseReleased"):
                self._send("Input.dispatchMouseEvent", {"type": phase, "x": x, "y": y,
                                                        "button": "left", "clickCount": 1})
        elif kind == "scroll":
            self._send("Input.dispatchMouseEvent", {
                "type": "mouseWheel", "x": width / 2, "y": height / 2, "deltaX": 0,
                "deltaY": float(event["fy"]) * height})
        elif kind == "text":
            self._send("Runtime.evaluate", {"expression": FOCUS_A_BOX})
            self._send("Input.insertText", {"text": str(event.get("text", ""))[:500]})
        elif kind == "key" and event.get("key") in KEYS:
            key = event["key"]
            code, text = KEYS[key]
            # every field a page may look at, as a real keyboard sends them
            press = {"key": key, "code": key, "windowsVirtualKeyCode": code,
                     "nativeVirtualKeyCode": code}
            in_form = key == "Enter" and self._value(WATCH_SUBMIT) == "form"
            self._send("Input.dispatchKeyEvent", {"type": "keyDown", **press,
                                                  **({"text": text, "unmodifiedText": text}
                                                     if text else {})})
            self._send("Input.dispatchKeyEvent", {"type": "keyUp", **press})
            if in_form:
                # Some sign-in pages never submit on a key from outside (the
                # first real phone pressed Enter on Amazon's password page
                # and nothing happened); their own button always works.
                time.sleep(ENTER_GRACE)
                self._value(SUBMIT_IF_NOT)
        elif kind == "back":
            self._send("Runtime.evaluate", {"expression": "history.back()"})
        elif kind == "size":
            self.resize(int(event["width"]), int(event["height"]))

    def _value(self, script: str) -> Any:
        """What a script in the page returns; None when it could not run
        (the page moved on)."""
        try:
            return self._send("Runtime.evaluate", {"expression": script,
                                                   "returnByValue": True}
                              ).get("result", {}).get("value")
        except (BrowserSignInFailed, OSError, ValueError):
            return None

    def look(self) -> bool:
        """Whether a sign-in cookie is set now (names only)."""
        try:      # the browser's whole cookie jar, asked of the browser itself
            cookies = self.browser.call("Storage.getCookies").get("cookies", [])
        except BrowserSignInFailed:
            return False
        for cookie in cookies:
            host = str(cookie.get("domain", "")).lstrip(".")
            if any(host == h or host.endswith("." + h) for h in self.hosts) and any(
                    fnmatch.fnmatchcase(str(cookie.get("name", "")), p) for p in self.patterns):
                return True
        return False


_PAGE = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<title>Sign in to {site}</title><style>
body{{margin:0;font:15px system-ui,sans-serif;background:#111;color:#eee}}
#s{{display:block;width:100vw;touch-action:none;background:#222}}
#bar{{position:sticky;bottom:0;background:#1d1d1d;padding:8px;display:flex;gap:6px;
flex-wrap:wrap}}#bar input{{flex:1 1 60%;font-size:16px;padding:8px}}
button{{font-size:15px;padding:8px 10px}}#say{{padding:8px;color:#bbb}}
</style></head><body>
<div id="say">Signing in to {site}. Type in the box below and press Send: it goes into the
page's first empty box, or the one you tapped on the picture. Your keyboard's Go sends it
and presses Enter. This page works once, for 10 minutes.</div>
<img id="s" src="{base}/stream" alt="the sign-in page">
<div id="bar"><input id="t" autocomplete="off" autocapitalize="off" type="password"
enterkeyhint="go"
placeholder="type here, then Send or your keyboard's Go"><button id="v">show</button>
<button id="send">Send</button><button data-k="Enter">Enter</button>
<button data-k="Backspace">&#9003;</button><button data-k="Tab">Tab</button>
<button id="back">Back</button><button id="done">I've signed in</button></div>
<script>
const base="{base}",s=document.getElementById("s"),t=document.getElementById("t");
const post=(p,b)=>fetch(base+p,{{method:"POST",headers:{{"content-type":"application/json"}},
 body:JSON.stringify(b)}});
post("/input",{{type:"size",width:innerWidth,height:Math.round(innerHeight*0.8)}});
let y0=null;s.addEventListener("touchstart",e=>{{y0=e.touches[0].clientY}});
s.addEventListener("touchend",e=>{{const r=s.getBoundingClientRect(),c=e.changedTouches[0];
 const dy=c.clientY-y0;if(Math.abs(dy)>25){{post("/input",{{type:"scroll",fy:-dy/r.height}})}}
 else{{post("/input",{{type:"tap",fx:(c.clientX-r.left)/r.width,fy:(c.clientY-r.top)/r.height}})}}
 e.preventDefault()}});
s.addEventListener("click",e=>{{const r=s.getBoundingClientRect();
 post("/input",{{type:"tap",fx:(e.clientX-r.left)/r.width,fy:(e.clientY-r.top)/r.height}})}});
const sendText=async()=>{{if(t.value){{const v=t.value;t.value="";
 await post("/input",{{type:"text",text:v}})}}}};
document.getElementById("send").onclick=()=>sendText();
t.addEventListener("keydown",async e=>{{if(e.key==="Enter"){{e.preventDefault();
 await sendText();post("/input",{{type:"key",key:"Enter"}})}}}});
document.getElementById("v").onclick=e=>{{t.type=t.type=="password"?"text":"password";
 e.target.textContent=t.type=="password"?"show":"hide"}};
document.querySelectorAll("[data-k]").forEach(b=>b.onclick=()=>post("/input",
 {{type:"key",key:b.dataset.k}}));
document.getElementById("back").onclick=()=>post("/input",{{type:"back"}});
document.getElementById("done").onclick=()=>post("/done",{{}});
setInterval(async()=>{{const r=await fetch(base+"/state");const j=await r.json();
 if(j.state!="open"){{document.getElementById("say").textContent=j.say;s.remove();
 document.getElementById("bar").remove()}}}},2000);
</script></body></html>"""


def serve(window: Window, site: str, *, host: str, port: int, public: str | None,
          open_for: float = OPEN_FOR,
          on_link: Callable[[str, float], Any] = lambda _u, _t: None,
          on_opened: Callable[[], Any] = lambda: None) -> str:
    """Serve the page until they're signed in, say they're done, or the time
    is up. Returns ``"signed_in"``, ``"done"`` or ``"expired"``."""
    token = secrets.token_urlsafe(24)
    viewer: list[str] = []          # the one device that may use it
    state = {"value": "open"}
    deadline = time.monotonic() + open_for
    prefix = f"/w/{token}"

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_a: Any) -> None:
            pass

        def _theirs(self) -> bool:
            cookie = SimpleCookie(self.headers.get("Cookie", ""))
            return bool(viewer) and "setu_v" in cookie and secrets.compare_digest(
                cookie["setu_v"].value, viewer[0])

        def _send(self, code: int, body: bytes, kind: str = "application/json",
                  headers: dict[str, str] | None = None) -> None:
            self.send_response(code)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            path = urlsplit(self.path).path
            if not path.startswith(prefix) or time.monotonic() > deadline:
                return self._send(404, b'{"error": "no such page, or it has expired"}')
            rest = path[len(prefix):]
            if rest in ("", "/"):
                if viewer and not self._theirs():
                    return self._send(409, b"This sign-in is already open on another "
                                      b"device.", "text/plain; charset=utf-8")
                headers = {}
                if not viewer:
                    viewer.append(secrets.token_urlsafe(24))
                    headers["Set-Cookie"] = (f"setu_v={viewer[0]}; Path={prefix}; HttpOnly; "
                                             "SameSite=Strict")
                    on_opened()
                page = _PAGE.format(site=site, base=prefix).encode()
                return self._send(200, page, "text/html; charset=utf-8", headers)
            if not self._theirs():
                return self._send(403, b'{"error": "not this device"}')
            if rest == "/state":
                say = {"open": "", "signed_in": f"Signed in to {site}. You can close this "
                       "page.", "done": "Checking whether you signed in...",
                       "expired": "This sign-in ran out of time."}[state["value"]]
                return self._send(200, json.dumps({"state": state["value"], "say": say})
                                  .encode())
            if rest == "/stream":
                return self._stream()
            return self._send(404, b"{}")

        def _stream(self) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "multipart/x-mixed-replace; boundary=frame")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            last = None
            try:
                while state["value"] == "open":
                    with window.frames:
                        if window.frame is last and state["value"] == "open":
                            window.frames.wait(timeout=5)
                        frame = window.frame
                    if frame is None or frame is last:
                        continue
                    last = frame
                    self.wfile.write(b"--frame\r\nContent-Type: image/jpeg\r\nContent-Length: "
                                     + str(len(frame)).encode() + b"\r\n\r\n" + frame + b"\r\n")
            except (BrokenPipeError, ConnectionResetError):
                pass

        def do_POST(self) -> None:  # noqa: N802
            path = urlsplit(self.path).path
            if not path.startswith(prefix) or time.monotonic() > deadline:
                return self._send(404, b"{}")
            if not self._theirs():
                return self._send(403, b'{"error": "not this device"}')
            size = min(int(self.headers.get("Content-Length") or 0), 4096)
            try:
                event = json.loads(self.rfile.read(size) or b"{}")
            except ValueError:
                return self._send(400, b"{}")
            rest = path[len(prefix):]
            if rest == "/done":
                state["value"] = "done"
                window.done.set()
            elif rest == "/input" and state["value"] == "open":
                try:
                    window.act(event)
                except (BrowserSignInFailed, KeyError, ValueError, TypeError):
                    pass
            return self._send(200, b"{}")

    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    bound = server.server_address[1]
    base = (public or f"http://{host}:{bound}").rstrip("/")
    threading.Thread(target=server.serve_forever, daemon=True, name="setu-window").start()
    on_link(f"{base}{prefix}", time.time() + open_for)
    try:
        while time.monotonic() < deadline:
            if window.browser.gone.is_set():
                break
            if window.done.wait(LOOK_EVERY):
                break
            if window.look():
                state["value"] = "signed_in"
                window.signed_in.set()
                time.sleep(LOOK_EVERY + 1)       # let the page say so
                break
        else:
            state["value"] = "expired"
        return state["value"] if state["value"] != "open" else "expired"
    finally:
        with window.frames:
            window.frames.notify_all()
        server.shutdown()
        server.server_close()


def window_for(on_link: Callable[[str, float], Any], on_opened: Callable[[], Any] = lambda: None,
               *, site: str, patterns: tuple[str, ...], hosts: tuple[str, ...],
               open_for: float = OPEN_FOR) -> Callable[..., None]:
    """A ``window`` for ``connections.connect_browser``: the same profile
    and the same cookie check afterwards, signed in to from elsewhere."""
    host, port, public = settings()

    def window(browser: str, profile: Path, url: str, **_kw: Any) -> None:
        profile.mkdir(parents=True, exist_ok=True)
        os.chmod(profile.parent, 0o700)
        os.chmod(profile, 0o700)
        chrome = Browser(shutil.which(browser) or browser, profile)
        try:
            seen = serve(Window(chrome, url, patterns, hosts), site, host=host, port=port,
                         public=public, open_for=open_for, on_link=on_link,
                         on_opened=on_opened)
        finally:
            chrome.close()
        if seen == "expired":
            raise BrowserSignInFailed(f"nobody signed in to {site} within "
                                      f"{int(open_for // 60)} minutes; nothing was saved")
    return window
