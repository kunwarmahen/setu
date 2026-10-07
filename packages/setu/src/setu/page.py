"""Setu's own page, and the JSON behind it -- served by ``setu serve``.

Everything a person can learn from ``setu list``, ``setu connectors``,
``setu log`` and ``setu status`` they can see in a browser instead, at
an address ``setu serve`` prints. The page is drawn from a small JSON
API on the same server:

    GET /api/status                     the folder, its lock, the catalog, problems
    GET /api/connections                one card per connection -- never a key
    GET /api/connectors                 what is installed, with its levels in words
    GET /api/log?ref=REF&limit=N        the requests Setu made for one, newest first

ONE ANSWER, THREE ROADS. Every endpoint is built from ``status.report()``
-- the same dict ``setu status --json`` prints and a harness imports --
so the page, the terminal and the harness cannot say different things.
The page leaves out what is only for a harness: the command that starts
a connector, and the browser profile's path (where the cookies are).

A TOKEN, ALWAYS. Every ``/api`` call carries ``Authorization: Bearer``.
Localhost is not a boundary: any web page you visit can send a request
to 127.0.0.1. The token is ``$SETU_PAGE_TOKEN``, or one Setu makes once
and keeps in its folder (readable by you alone). ``setu serve`` prints
the page's address with the token after a ``#`` -- the part of an
address a browser never sends to a server, so it is in no log -- and the
page keeps it for next time.

EMBEDDING IS BY NAME. A page that holds sign-ins must not be wrapped by
a site that lays its own buttons over it (click-jacking), so the page
says who may frame it: ``Content-Security-Policy: frame-ancestors``,
itself and the origins in ``$SETU_PAGE_EMBED`` (a harness's own page,
such as Yantra's). Every other site that frames it gets nothing.

NOTHING RUNS INLINE. The page is three static files -- HTML, a script,
a stylesheet -- with no data in them, and the policy allows scripts only
from the page's own address. Something that slipped into a connection's
name could be shown, never run. No CORS headers are sent, so a page on
another site cannot read an answer even if it could send a request.

LOCALHOST BY DEFAULT, deliberately; reaching the network is a decision
(``--host``), as it is for Samay and Dvara.

Standard library only, like the streamed window (remote.py): a page this
small is not worth a web framework in every install of Setu.
"""

from __future__ import annotations

import hmac
import json
import os
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from setu import health, proxy, status
from setu.vault import FileVault, default_home

DEFAULT_PORT = 8775
ENV_TOKEN = "SETU_PAGE_TOKEN"
ENV_EMBED = "SETU_PAGE_EMBED"
ENV_PUBLIC = "SETU_PAGE_URL"
TOKEN_FILE = "page.token"

#: The most log lines one request returns.
MAX_LOG_LINES = 1000

#: The page's own files, and what each is served as.
STATIC = {"/": ("index.html", "text/html; charset=utf-8"),
          "/index.html": ("index.html", "text/html; charset=utf-8"),
          "/page.js": ("page.js", "text/javascript; charset=utf-8"),
          "/page.css": ("page.css", "text/css; charset=utf-8")}


def page_token(home: Path | None = None) -> str:
    """``$SETU_PAGE_TOKEN``, or the one kept in the Setu folder (made once)."""
    configured = os.environ.get(ENV_TOKEN, "").strip()
    if configured:
        if len(configured) < 16:
            raise ValueError(f"{ENV_TOKEN} must be at least 16 characters")
        return configured
    path = (home or default_home()) / TOKEN_FILE
    try:
        kept = path.read_text().strip()
        if len(kept) >= 16:
            return kept
    except OSError:
        pass
    token = secrets.token_urlsafe(24)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as out:
        out.write(token + "\n")
    return token


def embedders(raw: str | None = None) -> list[str]:
    """The origins allowed to frame the page, from ``$SETU_PAGE_EMBED``
    (spaces or commas between them). Each must be ``scheme://host[:port]``
    and nothing else: a path or a wildcard would let in more than named."""
    raw = os.environ.get(ENV_EMBED, "") if raw is None else raw
    found = []
    for item in raw.replace(",", " ").split():
        parsed = urlparse(item)
        if (parsed.scheme not in ("http", "https") or not parsed.netloc
                or "*" in item or parsed.path not in ("", "/") or parsed.query):
            raise ValueError(f"{ENV_EMBED}: {item!r} is not an origin like "
                             "http://127.0.0.1:8000")
        found.append(f"{parsed.scheme}://{parsed.netloc}")
    return found


def policy(embed: list[str]) -> str:
    """The Content-Security-Policy every answer carries."""
    ancestors = " ".join(["'self'", *embed])
    return ("default-src 'none'; script-src 'self'; style-src 'self'; "
            "connect-src 'self'; img-src 'self' data:; base-uri 'none'; "
            f"form-action 'none'; frame-ancestors {ancestors}")


class ApiError(Exception):
    def __init__(self, code: int, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


class Api:
    """What each endpoint does, apart from HTTP -- so tests can call it
    straight, and the handler below stays a thin skin."""

    def __init__(self, vault: FileVault | None = None) -> None:
        self.vault = vault or FileVault()

    def handle(self, method: str, path: str, query: dict[str, list[str]]
               ) -> tuple[int, dict[str, Any]]:
        if method != "GET":
            raise ApiError(405, "this page only reads, for now")
        parts = [p for p in path.split("/") if p][1:]      # after "api"
        if parts == ["status"]:
            return 200, self.status()
        if parts == ["connections"]:
            return 200, {"connections": self.connections()}
        if parts == ["connectors"]:
            return 200, {"connectors": self.connectors()}
        if parts == ["log"]:
            ref = (query.get("ref") or [""])[0]
            limit = _int((query.get("limit") or ["100"])[0], "limit")
            return 200, self.log(ref, max(1, min(limit, MAX_LOG_LINES)))
        raise ApiError(404, f"no such endpoint: GET /api/{'/'.join(parts)}")

    def status(self) -> dict[str, Any]:
        data = status.report(self.vault)
        index = data["catalog"]
        return {"format": "setu.page.status.v1", "version": data["version"],
                "folder": str(self.vault.home), "lock": data["lock"],
                "setup": {k: bool(v) for k, v in data["setup"].items()},
                "catalog": ({"source": index["source"], "issued": index["issued"]}
                            if index else None),
                "connections": len(data["connections"]),
                "problems": data["problems"]}

    def connections(self) -> list[dict[str, Any]]:
        rows = []
        for row in status.report(self.vault)["connections"]:
            # for a harness only: how to start it, and where its cookies are
            card = {k: v for k, v in row.items() if k not in ("mcp", "browser")}
            card["road"] = "browser" if row["browser"] else "api"
            card["health_line"] = health.line(row["ref"])
            rows.append(card)
        return rows

    def connectors(self) -> list[dict[str, Any]]:
        return [{k: v for k, v in card.items() if k != "browser"}
                for card in status.report(self.vault)["connectors"]]

    def log(self, ref: str, limit: int) -> dict[str, Any]:
        # a ref the vault does not hold is refused before it names a file
        if not ref or ref not in self.vault.list():
            raise ApiError(404, f"no connection {ref!r}")
        path = proxy.log_path(ref, self.vault.home)
        lines: list[str] = []
        for part in (path.with_suffix(".log.1"), path):     # the older half first
            try:
                lines += part.read_text(encoding="utf-8").splitlines()
            except OSError:
                pass
        return {"ref": ref, "entries": [_entry(line) for line in reversed(lines[-limit:])],
                "total": len(lines)}


def _entry(line: str) -> dict[str, str]:
    """``2026-10-06T09:14:02 GET /gmail/v1/users/me/threads 200`` as fields;
    the outcome is the rest of the line (``refused: not at this level``)."""
    at, method, path, outcome = (line.split(" ", 3) + ["", "", ""])[:4]
    return {"at": at, "method": method, "path": path, "outcome": outcome}


def _int(value: str, name: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ApiError(400, f"{name} must be a whole number") from None


def public_address(raw: str | None) -> str | None:
    """``$SETU_PAGE_URL`` or ``--public-url``, checked: an address a browser
    can open, ending in one slash. None when not given."""
    raw = (raw if raw is not None else os.environ.get(ENV_PUBLIC, "")).strip()
    if not raw:
        return None
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(f"the page's public address must look like "
                         f"http://host:port/ -- got {raw!r}")
    return raw.rstrip("/") + "/"


class PageServer:
    """The API and the page, until stopped."""

    def __init__(self, api: Api, token: str, *, host: str = "127.0.0.1",
                 port: int = DEFAULT_PORT, public_url: str | None = None,
                 embed: list[str] | None = None) -> None:
        self.api = api
        self.token = token
        self.public_url = public_address(public_url)
        self.embed = embedders() if embed is None else embed
        self.httpd = ThreadingHTTPServer((host, port), _handler(self))
        self.httpd.daemon_threads = True
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        """Where a browser reaches the page -- not always where it is bound.
        Bound to every address, this machine reaches it at 127.0.0.1;
        behind a port mapping or a proxy only the owner knows the address,
        and says it with ``--public-url`` / ``$SETU_PAGE_URL``."""
        if self.public_url:
            return self.public_url
        host, port = self.httpd.server_address[:2]
        if host in ("0.0.0.0", "::"):
            host = "127.0.0.1"
        return f"http://{host}:{port}/"

    @property
    def page_url(self) -> str:
        return f"{self.url}#token={self.token}"

    def serve_forever(self) -> None:
        self.httpd.serve_forever()

    def start(self) -> None:
        self._thread = threading.Thread(target=self.httpd.serve_forever,
                                        name="setu-page", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        if self._thread is not None:
            self._thread.join()


def _handler(server: PageServer):
    csp = policy(server.embed)

    class Handler(BaseHTTPRequestHandler):
        server_version = "setu"

        def log_message(self, *_a: Any) -> None:
            pass

        def _send(self, code: int, body: bytes, kind: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", csp)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, data: dict[str, Any]) -> None:
            self._send(code, json.dumps(data).encode(), "application/json")

        def _authorized(self) -> bool:
            offered = self.headers.get("Authorization", "")
            return hmac.compare_digest(offered.encode(), f"Bearer {server.token}".encode())

        def _dispatch(self, method: str) -> None:
            url = urlparse(self.path)
            if method == "GET" and url.path in STATIC:
                name, kind = STATIC[url.path]
                return self._send(200, files("setu").joinpath("static", name).read_bytes(),
                                  kind)
            if not url.path.startswith("/api/"):
                return self._json(404, {"detail": "not found"})
            if not self._authorized():
                return self._json(401, {"detail": "missing or wrong token"})
            try:
                code, data = server.api.handle(method, url.path, parse_qs(url.query))
            except ApiError as exc:
                return self._json(exc.code, {"detail": exc.detail})
            except Exception as exc:     # a bug is a 500 that says what, not a hang
                return self._json(500, {"detail": f"{type(exc).__name__}: {exc}"})
            self._json(code, data)

        def do_GET(self) -> None:
            self._dispatch("GET")

        def do_POST(self) -> None:
            self._dispatch("POST")

        def do_DELETE(self) -> None:
            self._dispatch("DELETE")

    return Handler
