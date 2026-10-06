"""Setu makes the connector's requests, so the key never enters it.

A connector is somebody's program. Handed a token, it could send it
anywhere. So it is handed none: it is given the path of a unix socket
and a random key that means nothing anywhere else, and every request
it makes goes to Setu, which

1. checks the key (one per run, dead when the run ends);
2. checks the request against the connection's level -- the manifest's
   ``[requests]`` rules, by method and path (and, for a site's own MCP
   server, by tool) -- and refuses what the level does not reach,
   before anything leaves the computer;
3. adds the connection's token, fresh from the vault, and sends it to
   the connection's own host and no other;
4. writes one line to the connection's request log: when, method,
   path, answer. Never the query or the body -- what you searched for
   is not Setu's to keep.

::

    setu-gmail (bwrap: no network) ──unix socket──▶ setu run gmail:personal
           GET /gmail/v1/users/me/threads              │ key? level? token
           X-Setu-Key: <this run's>                    └──HTTPS──▶ gmail.googleapis.com

WHAT A CONNECTOR MAY ASK ABOUT ITSELF. ``GET /_setu/grant`` answers
the scopes, level, account and address the connection holds -- what
``setu.granted_scopes()`` reads -- without a token in it.

ONE ANSWER, WHOLE. A response is read to its end and passed back with
its length; nothing here streams. Every connector Setu ships asks for
answers that fit in memory, and a site that needs streaming is what
``token_mode = "callback"`` exists for.
"""

from __future__ import annotations

import hmac
import json
import secrets
import socketserver
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from fnmatch import fnmatchcase
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import httpx

from setu import connections
from setu.manifest import Manifest
from setu.vault import Vault, default_home

KEY_HEADER = "X-Setu-Key"
GRANT_PATH = "/_setu/grant"
#: Headers that belong to one hop, or that Setu sets itself.
DROP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te",
        "trailer", "transfer-encoding", "upgrade", "host", "authorization",
        "content-length", "content-encoding", KEY_HEADER.lower()}
#: A request body bigger than this is refused (Gmail's own cap is 35 MB).
MAX_BODY = 36 * 1024 * 1024
#: A request log longer than this is moved aside to ``.1``.
MAX_LOG = 1024 * 1024


class Refused(Exception):
    """A request the connection's level does not reach."""


@dataclass(frozen=True, slots=True)
class Rules:
    """What one connection's requests may be, from its manifest and level."""

    allow: tuple[str, ...]
    deny: tuple[str, ...]
    #: No ``[requests]`` in the manifest: any request to its host.
    open: bool
    mcp_path: str = ""
    #: At the first level, a ``tools/call`` must name a read tool.
    read_tools_only: bool = False
    verb: Callable[[str], str | None] = lambda _tool: None

    @classmethod
    def of(cls, manifest: Manifest, level: str) -> Rules:
        names = [lvl.name for lvl in manifest.levels]
        if level not in names:
            level = names[0]       # an unknown level is held to the least one
        allow: list[str] = []
        for name in names[:names.index(level) + 1]:
            allow += manifest.requests[name].allow if name in manifest.requests else ()
        own = manifest.requests.get(level)
        return cls(allow=tuple(allow), deny=own.deny if own else (),
                   open=not manifest.requests, mcp_path=manifest.mcp_path,
                   read_tools_only=level == names[0], verb=manifest.verb)

    def check(self, method: str, path: str, body: bytes) -> None:
        """Raise ``Refused``, in words, unless the level reaches this."""
        bare = path.partition("?")[0]
        segments = unquote(bare).split("/")
        if not bare.startswith("/") or "\\" in bare or any(
                s in (".", "..") for s in segments) or "//" in bare:
            raise Refused(f"{bare!r} is not a plain path")
        # matched as the site will read it: decoded, so %6Cock is lock
        line = f"{method} {unquote(bare)}"
        if self.mcp_path and bare == self.mcp_path and method == "POST":
            self._check_mcp(body)
            return
        if self.open:
            return
        if not any(fnmatchcase(line, rule) for rule in self.allow):
            raise Refused(f"{line} is not something this level does")
        if any(fnmatchcase(line, rule) or fnmatchcase(line.lower(), rule.lower())
               for rule in self.deny):
            raise Refused(f"{line} is beyond this level")

    def _check_mcp(self, body: bytes) -> None:
        if not self.read_tools_only:
            return
        try:
            message = json.loads(body or b"{}")
        except ValueError:
            raise Refused("an MCP request that is not JSON") from None
        for one in message if isinstance(message, list) else [message]:
            if not isinstance(one, dict) or one.get("method") != "tools/call":
                continue
            tool = str((one.get("params") or {}).get("name", ""))
            if self.verb(tool) != "read":
                raise Refused(f"the tool {tool!r} changes things, and this "
                              "connection only reads")


class _Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    proxy: Proxy


class _Handler(BaseHTTPRequestHandler):
    server: _Server
    protocol_version = "HTTP/1.1"

    def _do(self) -> None:
        self.server.proxy.handle(self)

    do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = _do

    def log_message(self, *args: Any) -> None:
        pass   # the proxy keeps its own log, without queries

    def address_string(self) -> str:
        return "connector"


class Proxy:
    """One connection's forwarder, for the length of one run."""

    def __init__(self, ref: str, manifest: Manifest, *, vault: Vault, http: httpx.Client,
                 base: str, log: Path | None = None) -> None:
        if not base:
            raise connections.ConnectionFailed(
                f"{ref}: the connector names no address to send requests to")
        self.ref, self.manifest, self.vault, self.http = ref, manifest, vault, http
        self.base = base.rstrip("/")
        self.key = secrets.token_urlsafe(32)
        self.log = log
        self._lock = threading.Lock()
        self._token: connections.Token | None = None
        entry = vault.get(ref) or {}
        self.rules = Rules.of(manifest, entry.get("level", ""))
        self.folder = Path(tempfile.mkdtemp(prefix="setu-"))   # 0700
        self.socket = self.folder / "proxy.sock"
        self._server = _Server(str(self.socket), _Handler)
        self._server.proxy = self
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> Proxy:
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self._server.shutdown()
        self._server.server_close()
        self.socket.unlink(missing_ok=True)
        self.folder.rmdir()

    # ---- the token, kept between requests ---------------------------------

    def token(self, *, force: bool = False) -> connections.Token:
        with self._lock:
            held = self._token
            if (held is None or force
                    or time.time() >= held.expires_at - connections.EXPIRY_SKEW):
                self._token = connections.token(self.ref, vault=self.vault,
                                                http=self.http, force=force)
            return self._token

    # ---- one request ---------------------------------------------------------

    def handle(self, req: _Handler) -> None:
        method, path = req.command, req.path
        if not hmac.compare_digest(req.headers.get(KEY_HEADER, ""), self.key):
            return self._reply(req, 403, {"error": "not this run's key"})
        length = int(req.headers.get("Content-Length") or 0)
        if req.headers.get("Transfer-Encoding"):
            return self._reply(req, 411, {"error": "send a Content-Length"})
        if length > MAX_BODY:
            return self._reply(req, 413, {"error": "request too large"})
        body = req.rfile.read(length) if length else b""
        if path == GRANT_PATH and method == "GET":
            return self._grant(req)
        try:
            self.rules.check(method, path, body)
        except Refused as exc:
            self._note(method, path, f"refused: {exc}")
            return self._reply(req, 403, {"error": f"Setu refused: {exc}"})
        headers = {k: v for k, v in req.headers.items() if k.lower() not in DROP}
        try:
            response = self._send(method, path, headers, body)
        except (httpx.HTTPError, connections.ConnectionFailed) as exc:
            self._note(method, path, "failed")
            return self._reply(req, 502, {"error": f"Setu could not reach the site: {exc}"})
        self._note(method, path, str(response.status_code))
        out = [(k, v) for k, v in response.headers.multi_items() if k.lower() not in DROP]
        self._reply(req, response.status_code, response.content, out)

    def _send(self, method: str, path: str, headers: dict[str, str],
              body: bytes) -> httpx.Response:
        def once(force: bool) -> httpx.Response:
            sent = dict(headers, Authorization=f"Bearer {self.token(force=force).access_token}")
            return self.http.request(method, self.base + path, headers=sent, content=body,
                                     follow_redirects=False)
        response = once(False)
        if response.status_code == 401:
            response = once(True)    # the token may have been revoked or rotated
        return response

    def _grant(self, req: _Handler) -> None:
        try:
            held = self.token()
        except connections.ConnectionFailed as exc:
            return self._reply(req, 502, {"error": str(exc)})
        self._reply(req, 200, {"scopes": list(held.scopes), "level": held.level,
                               "account": held.account, "email": held.email})

    @staticmethod
    def _reply(req: _Handler, status: int, body: bytes | dict[str, Any],
               headers: list[tuple[str, str]] | None = None) -> None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        req.send_response(status)
        for key, value in headers or [("Content-Type", "application/json")]:
            req.send_header(key, value)
        req.send_header("Content-Length", str(len(data)))
        req.end_headers()
        if req.command != "HEAD":
            req.wfile.write(data)

    def _note(self, method: str, path: str, outcome: str) -> None:
        if self.log is None:
            return
        line = (f"{time.strftime('%Y-%m-%dT%H:%M:%S')} {method} "
                f"{path.partition('?')[0]} {outcome}\n")
        with self._lock:
            try:
                self.log.parent.mkdir(parents=True, exist_ok=True)
                if self.log.exists() and self.log.stat().st_size > MAX_LOG:
                    self.log.replace(self.log.with_suffix(".log.1"))
                with self.log.open("a", encoding="utf-8") as out:
                    out.write(line)
            except OSError:
                pass     # a log that cannot be written never stops a request


def log_path(ref: str, home: Path | None = None) -> Path:
    """Where a connection's request log is kept."""
    return (home or default_home()) / "logs" / (ref.replace(":", "-") + ".log")
