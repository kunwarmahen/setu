"""A server of your own that signs you in on its own page (MCP's OAuth).

The bias is THE REFRESH TOKEN NEVER LEAVES SETU. A remote MCP server with
no token to paste answers 401 and points at its sign-in; a harness that
did the walk itself kept the refresh token in its own file, reachable by
one session only. So the tests assert where the tokens end up: in the
vault entry and nowhere else (not the manifest, not the status report,
not the page's events), renewed by Setu when due, the new one kept when
the server rotates it, and a renewal the server refuses marked as an
expired sign-in, which the daily check reports rather than skips.

Also designed against:

* **A code redeemed by someone else.** PKCE's S256 is checked by the
  stand-in, and ``resource`` names the one server the token is for.
* **A sign-in that can't happen where it was asked.** With no road to a
  browser it says so, and nothing is saved. From another device, the
  link is opened there and the address it ends on pasted back.
* **A client id made up.** An authorization server with no registration
  is said to need one from its dashboard.
"""

from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

import httpx
import pytest
from setu import connections, mcp_auth, own, status
from setu.google import Pasted
from setu.vault import FileVault

TOOLS = [{"name": "search", "inputSchema": {"type": "object"},
          "annotations": {"readOnlyHint": True}},
         {"name": "add_page", "inputSchema": {"type": "object"}}]


class SignInServer:
    """An MCP server and the authorization server that guards it, on one port."""

    def __init__(self, *, registration: bool = True) -> None:
        self.registration = registration
        self.access, self.refresh = "", ""
        self.issued = 0
        self.codes: dict[str, dict[str, str]] = {}
        self.registered: list[dict] = []
        self.refuse_refresh = False
        self.revoked: list[str] = []
        self.resources: list[str] = []
        self.asked: list[dict[str, str]] = []
        self.challenge_scope: str | None = "read write"
        self.offered: list[str] | None = None

    def _new_tokens(self) -> dict[str, Any]:
        self.issued += 1
        self.access, self.refresh = f"access-{self.issued}", f"refresh-{self.issued}"
        return {"access_token": self.access, "refresh_token": self.refresh,
                "token_type": "Bearer", "expires_in": 3600}

    def serve(self) -> str:
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a: Any) -> None:
                pass

            def _json(self, code: int, body: Any, extra: dict | None = None) -> None:
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self) -> None:  # noqa: N802
                parts = urlparse(self.path)
                if parts.path == "/.well-known/oauth-protected-resource":
                    meta = {"resource": fake.base + "/mcp",
                            "authorization_servers": [fake.base]}
                    if fake.offered is not None:
                        meta["scopes_supported"] = fake.offered
                    return self._json(200, meta)
                if parts.path == "/.well-known/oauth-authorization-server":
                    meta = {"issuer": fake.base,
                            "authorization_endpoint": fake.base + "/authorize",
                            "token_endpoint": fake.base + "/token",
                            "revocation_endpoint": fake.base + "/revoke",
                            "code_challenge_methods_supported": ["S256"]}
                    if fake.registration:
                        meta["registration_endpoint"] = fake.base + "/register"
                    return self._json(200, meta)
                if parts.path == "/authorize":
                    # the person signs in and allows it: back to the redirect
                    q = {k: v[0] for k, v in parse_qs(parts.query).items()}
                    code = f"code-{len(fake.codes) + 1}"
                    fake.codes[code] = q
                    fake.asked.append(q)
                    self.send_response(302)
                    self.send_header("Location", q["redirect_uri"] + "?" + urlencode(
                        {"code": code, "state": q["state"]}))
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                self._json(404, {})

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length)
                if self.path == "/mcp":
                    if not fake.access or \
                            self.headers.get("Authorization") != f"Bearer {fake.access}":
                        said = (f'Bearer realm="OAuth", resource_metadata="{fake.base}'
                                '/.well-known/oauth-protected-resource"')
                        if fake.challenge_scope:
                            said += f', scope="{fake.challenge_scope}"'
                        return self._json(401, {}, {"WWW-Authenticate": said})
                    body = json.loads(raw)
                    if body.get("id") is None:
                        return self._json(202, {})
                    if body["method"] == "initialize":
                        result = {"protocolVersion": "2025-06-18", "capabilities": {},
                                  "serverInfo": {"name": "Signed docs"}}
                    elif body["method"] == "tools/list":
                        result = {"tools": TOOLS}
                    else:
                        result = {"content": [{"type": "text", "text": "ok"}]}
                    return self._json(200, {"jsonrpc": "2.0", "id": body["id"],
                                            "result": result})
                if self.path == "/register":
                    fake.registered.append(json.loads(raw))
                    return self._json(201, {"client_id": "client-1"})
                form = {k: v[0] for k, v in parse_qs(raw.decode()).items()}
                if self.path == "/revoke":
                    fake.revoked.append(form.get("token", ""))
                    return self._json(200, {})
                if self.path == "/token":
                    fake.resources.append(form.get("resource", ""))
                    if form["grant_type"] == "authorization_code":
                        asked = fake.codes.pop(form["code"], None)
                        digest = hashlib.sha256(form.get("code_verifier", "").encode()).digest()
                        s256 = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
                        if asked is None or asked["code_challenge"] != s256:
                            return self._json(400, {"error": "invalid_grant"})
                        return self._json(200, fake._new_tokens())
                    if fake.refuse_refresh or form.get("refresh_token") != fake.refresh:
                        return self._json(400, {"error": "invalid_grant",
                                                "error_description": "revoked"})
                    return self._json(200, fake._new_tokens())
                self._json(404, {})

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        return self.base + "/mcp"

    def stop(self) -> None:
        self.httpd.shutdown()


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("SETU_HOME", str(tmp_path / "setu"))
    return tmp_path / "setu"


@pytest.fixture
def signs_in():
    fake = SignInServer()
    fake.url = fake.serve()
    yield fake
    fake.stop()


def person(link: str) -> None:
    """The person in the browser: signs in, and the browser follows the
    redirect back to Setu's listener."""
    back = httpx.get(link, follow_redirects=False).headers["location"]
    httpx.get(back)


def add(url: str, *, road=person, pasted: Pasted | None = None) -> dict:
    with httpx.Client() as http:
        return own.connect("docs", "personal", vault=FileVault(), http=http, url=url,
                           sign_in=lambda u, said: mcp_auth.sign_in(
                               u, said, http=http, open_browser=road, pasted=pasted,
                               timeout=20))


def test_the_server_points_at_its_sign_in_and_setu_follows(home, signs_in):
    entry = add(signs_in.url)
    assert entry["tools"] == 2
    secret = FileVault().get("docs:personal")["secret"]
    assert secret["kind"] == "oauth" and secret["token"] == "access-1"
    assert secret["refresh_token"] == "refresh-1" and secret["client_id"] == "client-1"
    assert signs_in.registered[0]["token_endpoint_auth_method"] == "none"


def test_the_tokens_are_in_the_vault_and_nowhere_else(home, signs_in):
    add(signs_in.url)
    manifest = (home / "servers" / "docs.toml").read_text()
    report = json.dumps(status.report(FileVault()))
    for token in ("access-1", "refresh-1"):
        assert token not in manifest and token not in report


def test_the_code_is_bound_to_this_sign_in_and_this_server(home, signs_in):
    add(signs_in.url)    # the stand-in refuses a code whose verifier doesn't match
    assert signs_in.resources == [signs_in.base + "/mcp"]


def test_the_scope_the_challenge_names_is_the_one_asked_for(home, signs_in):
    # Linear's and Notion's challenges both name one, as this stand-in's does
    add(signs_in.url)
    assert signs_in.asked[0]["scope"] == "read write"
    assert mcp_auth.asked_scope('Bearer resource_metadata="https://x/m"') is None


def test_with_no_scope_named_the_scopes_the_server_offers_are_asked_for(home, signs_in):
    # Robinhood's 401 names none, its details offer ["internal"], and its
    # sign-in page never comes back to Setu when the scope is left out
    signs_in.challenge_scope, signs_in.offered = None, ["internal"]
    add(signs_in.url)
    assert signs_in.asked[0]["scope"] == "internal"


def test_with_no_scope_named_or_offered_none_is_asked_for(home, signs_in):
    signs_in.challenge_scope = None
    add(signs_in.url)
    assert "scope" not in signs_in.asked[0]


def test_a_token_that_is_due_is_renewed_and_a_rotated_one_kept(home, signs_in):
    add(signs_in.url)
    vault = FileVault()
    entry = vault.get("docs:personal")
    entry["secret"]["expires_at"] = time.time() - 1
    vault.put("docs:personal", entry)
    with httpx.Client() as http:
        got = connections.token("docs:personal", vault=vault, http=http)
    assert got.access_token == "access-2" and got.headers() == {
        "Authorization": "Bearer access-2"}
    assert vault.get("docs:personal")["secret"]["refresh_token"] == "refresh-2"


def test_a_renewal_the_server_refuses_is_an_expired_sign_in_the_check_reports(home,
                                                                             signs_in):
    add(signs_in.url)
    signs_in.refuse_refresh = True
    vault = FileVault()
    with httpx.Client() as http:
        with pytest.raises(connections.ConnectionFailed, match="sign in again"):
            connections.token("docs:personal", vault=vault, http=http, force=True)
        rows = connections.check(vault=vault, http=http)
    row = next(r for r in rows if r["ref"] == "docs:personal")
    assert row["state"] == "expired"           # not "skipped", as a pasted token is


def test_with_no_road_to_a_browser_it_says_so_and_saves_nothing(home, signs_in):
    with httpx.Client() as http, pytest.raises(own.ServerError, match="signs in on its own"):
        own.connect("docs", "personal", vault=FileVault(), http=http, url=signs_in.url)
    assert FileVault().get("docs:personal") is None


def test_from_another_device_the_address_it_ended_on_is_pasted_back(home, signs_in):
    pasted = Pasted()

    def elsewhere(link: str) -> None:
        # opened on a phone: its redirect to 127.0.0.1 goes nowhere there,
        # so the person copies the address and pastes it into Setu
        pasted.put(httpx.get(link, follow_redirects=False).headers["location"])

    add(signs_in.url, road=elsewhere, pasted=pasted)
    assert FileVault().get("docs:personal")["secret"]["token"] == "access-1"


def test_no_registration_means_a_client_id_from_its_dashboard(home):
    fake = SignInServer(registration=False)
    url = fake.serve()
    try:
        with pytest.raises(own.ServerError, match="client id from its own dashboard"):
            add(url)
    finally:
        fake.stop()


def test_changing_the_level_keeps_the_sign_in(home, signs_in):
    add(signs_in.url)
    with httpx.Client() as http:
        entry = own.again("docs:personal", vault=FileVault(), http=http, level="read")
    assert entry["level"] == "read" and signs_in.issued == 1   # no new sign-in


def test_disconnecting_revokes_where_the_server_offers_it(home, signs_in):
    add(signs_in.url)
    with httpx.Client() as http:
        was, revoked = connections.disconnect("docs:personal", vault=FileVault(), http=http)
    assert was and revoked and signs_in.revoked == ["refresh-1"]


def test_the_page_sends_the_link_and_takes_the_address_back(home, signs_in):
    from setu import page
    api = page.Api(FileVault())
    api.handle("POST", "/api/add-server", {}, {"url": signs_in.url, "id": "docs"},
               local=False)
    assert "--paste" in api.signin.process.args
    deadline = time.monotonic() + 30
    link = None
    while link is None and time.monotonic() < deadline:
        link = next((e["url"] for e in api.signin.state()["events"]
                     if e["event"] == "url"), None)
        time.sleep(0.05)
    assert link is not None, api.signin.state()
    back = httpx.get(link, follow_redirects=False).headers["location"]
    api.handle("POST", "/api/signin/paste", {}, {"address": back})
    while time.monotonic() < deadline:
        state = api.signin.state()
        if any(e["event"] == "done" for e in state["events"]):
            break
        time.sleep(0.05)
    events = [e["event"] for e in state["events"]]
    assert "connected" in events, state
    assert "access-1" not in json.dumps(state) and "refresh-1" not in json.dumps(state)


def test_the_browser_opens_without_its_chatter(monkeypatch):
    """A running browser's own lines ("Opening in existing browser
    session", a zygote's broken pipe) don't land in Setu's terminal."""
    from setu import google

    seen = {}

    def popen(args, **kwargs):
        seen["args"], seen["kwargs"] = args, kwargs

    monkeypatch.setattr(google.shutil, "which", lambda name: "/usr/bin/xdg-open")
    monkeypatch.setattr(google.subprocess, "Popen", popen)
    assert google.open_quietly("https://example.test/oauth")
    assert seen["args"] == ["/usr/bin/xdg-open", "https://example.test/oauth"]
    for stream in ("stdin", "stdout", "stderr"):
        assert seen["kwargs"][stream] is google.subprocess.DEVNULL
