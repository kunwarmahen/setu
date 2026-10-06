"""Signing in to Google from a program on your own computer.

Google calls this an "installed application": the program opens the
browser, Google asks the person what to allow, and the browser comes
back to ``http://127.0.0.1:<port>/`` -- a port THIS process is already
listening on -- carrying a one-time code. The code, plus a PKCE verifier
held only in this process, buys an access token and a refresh token.

Three things here are Google's rules rather than OAuth's defaults, and
each one was a failure before it was a line of code:

* THE CLIENT SECRET TRAVELS. Google's desktop clients have a secret and
  the token endpoint wants it, PKCE or not. Google says outright that a
  desktop client's secret is not treated as secret -- it ships inside
  every copy of the program -- so it is stored beside the refresh token,
  where refreshing needs it.
* ``access_type=offline`` AND ``prompt=consent``. Without the first
  there is no refresh token at all; without the second, a person who
  signed in once before gets an access token and no refresh token the
  second time, and the connection dies in an hour.
* SCOPES ARE EXACTLY THE LEVEL'S. Nothing is added "while we are
  there", and ``include_granted_scopes`` is left off, so a token never
  quietly carries access a person granted some other day for some other
  reason. What Google hands back is read from the response's ``scope``
  field, because the consent screen lets a person untick a box and the
  token is then smaller than what was asked.

SIGNING IN FROM ANOTHER DEVICE. A person on a phone, talking to an
agent on somebody else's computer, can sign in on the phone -- but the
phone's browser then goes to ``127.0.0.1``, which on a phone is the
phone, and the page fails to load. Its address still carries the code.
So a sign-in may also take that address PASTED back (``Pasted``): the
same ``state`` check, the same PKCE verifier held here, the same
one-time code. An address from another sign-in, or something that is not
one at all, is turned away without ending the wait, so a wrong paste
can be followed by the right one.

Only a desktop client file is accepted. A "web application" client needs
its redirect address registered in advance, which a random local port
cannot be; the error says which kind to create instead.
"""

from __future__ import annotations

import base64
import hashlib
import json
import queue
import secrets
import threading
import time
import webbrowser
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

import httpx

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
REVOKE_URL = "https://oauth2.googleapis.com/revoke"

#: How long the person gets to finish in the browser.
SIGN_IN_TIMEOUT = 300.0


class GoogleAuthError(Exception):
    """Anything between "open the browser" and a usable token."""


@dataclass(frozen=True, slots=True)
class Client:
    client_id: str
    client_secret: str
    auth_url: str = AUTH_URL
    token_url: str = TOKEN_URL


def client_from_file(path: Path) -> Client:
    """Read the JSON Google offers for download on a desktop OAuth client."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise GoogleAuthError(f"no client file at {path}") from None
    except json.JSONDecodeError as exc:
        raise GoogleAuthError(f"{path} is not JSON ({exc})") from None
    if "web" in data and "installed" not in data:
        raise GoogleAuthError(
            f"{path} is a 'Web application' client. Setu signs in from your "
            "own computer, which needs a 'Desktop app' client: Google Cloud "
            "console → APIs & Services → Credentials → Create credentials → "
            "OAuth client ID → Desktop app")
    info = data.get("installed")
    if not isinstance(info, dict) or not info.get("client_id"):
        raise GoogleAuthError(f"{path} holds no 'installed' client")
    if not info.get("client_secret"):
        raise GoogleAuthError(f"{path} has no client_secret")
    return Client(client_id=info["client_id"], client_secret=info["client_secret"],
                  auth_url=info.get("auth_uri", AUTH_URL),
                  token_url=info.get("token_uri", TOKEN_URL))


# ---------------------------------------------------------------------------
# The browser round trip
# ---------------------------------------------------------------------------


def make_pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def authorization_url(client: Client, *, scopes: Iterable[str], redirect_uri: str,
                      state: str, challenge: str, login_hint: str | None = None) -> str:
    params = {
        "response_type": "code",
        "client_id": client.client_id,
        "redirect_uri": redirect_uri,
        "scope": " ".join(scopes),
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "access_type": "offline",
        "prompt": "consent",
    }
    if login_hint:
        params["login_hint"] = login_hint
    return f"{client.auth_url}?{urlencode(params)}"


_PAGE = ("<!doctype html><meta charset=utf-8><title>Setu</title>"
         "<body style='font:16px system-ui;margin:3em'><h2>{title}</h2>"
         "<p>{text}</p></body>")


class _Catcher(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 (the base class's name)
        query = parse_qs(urlparse(self.path).query)
        got = {key: values[0] for key, values in query.items()}
        if "code" not in got and "error" not in got:
            self.send_response(404)
            self.end_headers()
            return
        self.server.result = got  # type: ignore[attr-defined]
        ok = "code" in got
        body = _PAGE.format(
            title="Signed in" if ok else "Not signed in",
            text=("You can close this tab and go back to the terminal."
                  if ok else f"The sign-in said: {got.get('error')}. Nothing was saved."))
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args: Any) -> None:
        pass


class Pasted:
    """Addresses a person pasted back, for the sign-in that is waiting.
    ``on_refused`` hears, in words, each one that was turned away."""

    def __init__(self, on_refused: Callable[[str], Any] | None = None) -> None:
        self._queue: queue.Queue[str] = queue.Queue()
        self.on_refused = on_refused

    def put(self, address: str) -> None:
        self._queue.put(address)

    def take(self, state: str) -> dict[str, str] | None:
        """The first pasted address that belongs to this sign-in, if any."""
        while True:
            try:
                address = self._queue.get_nowait()
            except queue.Empty:
                return None
            got = {k: v[0] for k, v in parse_qs(urlparse(address.strip()).query).items()}
            if "code" not in got and "error" not in got:
                self._refuse("that is not the address the sign-in ended on -- copy the "
                             "whole address of the page that would not load")
            elif got.get("state") != state:
                self._refuse("that address belongs to a different sign-in")
            else:
                return got

    def _refuse(self, why: str) -> None:
        if self.on_refused is not None:
            self.on_refused(why)


class RedirectListener:
    """A one-shot local page for the browser to come back to -- or, given
    ``pasted``, the same address pasted back from another device."""

    def __init__(self, host: str = "127.0.0.1", pasted: Pasted | None = None) -> None:
        self.pasted = pasted
        self._httpd = HTTPServer((host, 0), _Catcher)
        self._httpd.result = None  # type: ignore[attr-defined]
        self._httpd.timeout = 0.5
        self.redirect_uri = f"http://{host}:{self._httpd.server_address[1]}/"

    def wait(self, state: str, timeout: float = SIGN_IN_TIMEOUT) -> str:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self._httpd.handle_request()
            got = self._httpd.result  # type: ignore[attr-defined]
            if got is None and self.pasted is not None:
                got = self.pasted.take(state)
            if got is None:
                continue
            if got.get("error"):
                raise GoogleAuthError(f"sign-in refused: {got['error']}")
            if got.get("state") != state:
                # Somebody else's redirect, or a replay: never redeem it.
                raise GoogleAuthError("sign-in came back with the wrong state")
            return got["code"]
        raise GoogleAuthError(f"no sign-in within {int(timeout)}s")

    def close(self) -> None:
        self._httpd.server_close()


# ---------------------------------------------------------------------------
# The token endpoint
# ---------------------------------------------------------------------------


def _post(http: httpx.Client, url: str, form: dict[str, str], what: str) -> dict[str, Any]:
    try:
        response = http.post(url, data=form, timeout=30.0)
    except httpx.HTTPError as exc:
        raise GoogleAuthError(f"{what}: {url} unreachable ({exc})") from None
    try:
        payload = response.json()
    except ValueError:
        payload = {}
    if response.status_code != 200:
        reason = payload.get("error_description") or payload.get("error") or response.text[:200]
        raise GoogleAuthError(f"{what} refused: HTTP {response.status_code} {reason}")
    if not payload.get("access_token"):
        raise GoogleAuthError(f"{what}: no access_token in the answer")
    return payload


def exchange_code(client: Client, *, code: str, verifier: str, redirect_uri: str,
                  http: httpx.Client) -> dict[str, Any]:
    return _post(http, client.token_url, {
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": verifier,
        "redirect_uri": redirect_uri,
        "client_id": client.client_id,
        "client_secret": client.client_secret,
    }, "sign-in")


def refresh(client: Client, refresh_token: str, *, http: httpx.Client) -> dict[str, Any]:
    return _post(http, client.token_url, {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client.client_id,
        "client_secret": client.client_secret,
    }, "refresh")


def revoke(token: str, *, http: httpx.Client) -> bool:
    """Ask Google to forget the grant. True when Google agreed -- or
    already had: a token that is no longer valid has nothing left to
    revoke, and saying "failed" about it would only alarm."""
    try:
        response = http.post(REVOKE_URL, data={"token": token}, timeout=30.0)
    except httpx.HTTPError:
        return False
    if response.status_code == 200:
        return True
    try:
        return response.json().get("error") == "invalid_token"
    except ValueError:
        return False


def sign_in(client: Client, scopes: Iterable[str], *, http: httpx.Client,
            open_browser: Callable[[str], Any] | None = webbrowser.open,
            on_url: Callable[[str], Any] | None = None,
            login_hint: str | None = None,
            timeout: float = SIGN_IN_TIMEOUT,
            pasted: Pasted | None = None) -> dict[str, Any]:
    """Browser → code → tokens. Returns Google's token response."""
    scopes = list(scopes)
    listener = RedirectListener(pasted=pasted)
    try:
        verifier, challenge = make_pkce()
        state = secrets.token_urlsafe(24)
        url = authorization_url(client, scopes=scopes, redirect_uri=listener.redirect_uri,
                                state=state, challenge=challenge, login_hint=login_hint)
        if on_url is not None:
            on_url(url)
        if open_browser is not None:
            # A thread, because some browsers block the caller until they
            # exit, and the listener must already be answering by then.
            threading.Thread(target=open_browser, args=(url,), daemon=True).start()
        code = listener.wait(state, timeout=timeout)
        return exchange_code(client, code=code, verifier=verifier,
                             redirect_uri=listener.redirect_uri, http=http)
    finally:
        listener.close()


def granted(payload: dict[str, Any]) -> set[str]:
    """The scopes Google actually granted -- which may be fewer than asked."""
    return set(str(payload.get("scope", "")).split())
