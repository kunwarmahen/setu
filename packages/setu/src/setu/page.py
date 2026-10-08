"""Setu's own page, and the JSON behind it -- served by ``setu serve``.

Everything a person can learn from ``setu list``, ``setu connectors``,
``setu log`` and ``setu status`` they can see in a browser instead, at
an address ``setu serve`` prints. The page is drawn from a small JSON
API on the same server:

    GET /api/status                     the folder, its lock, the catalog, problems
    GET /api/connections                one card per connection -- never a key
    GET /api/connectors                 what is installed, with its levels in words
    GET /api/requests?ref=REF&limit=N   the requests Setu made for one, newest first
    POST /api/connect      {connector, account, level, road?}   start a sign-in
    POST /api/add-site     {site, account, level}               a site Setu has no
                                                                connector for
    GET  /api/signin       the sign-in in progress, and what it has said so far
    POST /api/signin/answer {yes}        "did you sign in?", when the page can't tell
    POST /api/signin/paste  {address}    the address a sign-in ended on, pasted back
    POST /api/signin/cancel
    POST /api/disconnect   {ref}         revoke, then forget
    GET  /api/catalog      the signed catalog: who wrote each, installs, withdrawn
                           versions, the wheel's hash, certifications
    POST /api/install      {connector, sha256}   install, if the hash is still
                                                 the one the page showed
    GET  /api/certifiers   certifiers you trust, and how many versions each certified
    POST /api/certifiers/remove {id}     stop trusting one
    GET  /api/settings     the settings ``setu config`` shows -- never a key
    POST /api/settings     {name, value}  (value null: forget it)
    POST /api/people/claim {link}        a person's one-time link, for a session
    POST /api/session/close              a person closes the page on this device

ONE SIGN-IN ROAD, THE ONE A HARNESS USES. Connecting is ``setu connect
--json`` run as a child process, its events read line by line and its
questions answered on its stdin -- the contract Yantra's page already
drives, so there is one sign-in, not a second written for the page.
Cancel ends the child. Changing a level is connecting again at the new
one, as in the terminal. One sign-in at a time.

WHERE THE PERSON IS DECIDES THE ROAD. Google's and Home Assistant's
sign-ins come back to a port on this computer, and a browser-road site
opens a window here. A page opened on this computer gets those. A page
reached from elsewhere (``--host``) gets the roads made for another
device: the address pasted back, or the streamed window (``--remote``).
A request says which it wants only by where it comes from.

A WRITE COMES FROM THE PAGE ITSELF. On top of the token, a POST whose
``Origin`` is another site is refused -- a form on a page you happen to
visit cannot start a sign-in or revoke a key.

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

NOT CALLED "log". Ad and privacy blockers drop any address with
``/log?`` in it as tracking, and the page would say only "Failed to
fetch". The request log is ``/api/requests``.

THE HASH YOU SAW IS THE HASH INSTALLED. The page shows the sha256 the
signed catalog names for a connector's wheel, and Install sends it back.
If the catalog changed in between, the install is refused and the page
shows the new one: a person agrees to bytes, not to a name. The install
itself is ``setu install`` as a child, which checks the download against
the same hash.

SETTINGS ARE ``setu config``'s, CHECKED BY THE SAME FUNCTION
(``config.check``). Making keys, signing, and trusting a new certifier or
catalog key (a file you were handed) stay in the terminal.

PEOPLE: THEIR OWN FOLDER, AND LESS OF THE PAGE. With ``--people DIR`` the
server also answers a person's session (people.py) for the folder of
that name under DIR. Their page is the same page with the owner's parts
gone: no catalog, installs, certifiers, settings or adding a site --
those change what is installed on the owner's computer. They connect,
change a level, disconnect and read their log, each in their own folder
(the sign-in runs with ``SETU_HOME`` there). The owner's switch
(``setu config people-page off``) refuses every person's session at once.

LOCALHOST BY DEFAULT, deliberately; reaching the network is a decision
(``--host``), as it is for Samay and Dvara.

Standard library only, like the streamed window (remote.py): a page this
small is not worth a web framework in every install of Setu.
"""

from __future__ import annotations

import hmac
import json
import os
import re
import secrets
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from setu import catalog, certify, config, health, people, proxy, status
from setu.manifest import installed
from setu.vault import FileVault, default_home

DEFAULT_PORT = 8775
ENV_TOKEN = "SETU_PAGE_TOKEN"
ENV_EMBED = "SETU_PAGE_EMBED"
ENV_PUBLIC = "SETU_PAGE_URL"
ENV_PEOPLE = "SETU_PAGE_PEOPLE"
TOKEN_FILE = "page.token"

#: The most log lines one request returns.
MAX_LOG_LINES = 1000
MAX_BODY = 64 * 1024
#: What a person may call an account, and what a site's address may be.
ACCOUNT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$")
SITE_RE = re.compile(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
#: How long an install may take before the page says it failed.
INSTALL_SECONDS = 600
#: What a person's page answers; the rest of the API is the owner's.
PERSON_GET = {("status",), ("connections",), ("connectors",), ("requests",), ("signin",)}
PERSON_POST = {("connect",), ("disconnect",), ("signin", "answer"), ("signin", "paste"),
               ("signin", "cancel")}
#: What each setting is, in words, for the page.
SETTINGS = {
    "client-file": "Google's Desktop app client file (its path; the file stays where it is)",
    "homeassistant-url": "Your Home Assistant's address",
    "browser": "The browser sign-in windows open in",
    "share-installs": "Tell the catalog, anonymously, which of its connectors are installed",
    "people-page": "People may get a link to their own folder's page",
}
#: Where a setting can also come from, which wins over the remembered one.
SETTING_ENV = {"client-file": config.ENV_CLIENT_FILE, "homeassistant-url": config.ENV_HA_URL,
               "browser": config.ENV_BROWSER}

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


def setu_argv() -> list[str]:
    """This Setu, as a program: the same code the page runs."""
    return [sys.executable, "-m", "setu.cli"]


class SignIn:
    """One ``setu connect --json`` in progress, its events kept in order.

    ``answer`` and ``paste`` are lines on its stdin: ``yes``/``no`` for an
    ``ask``, an address for ``--paste``. ``events`` is everything it said,
    ending with ``done`` once it has exited.
    """

    def __init__(self, argv: list[str], ref: str,
                 env: dict[str, str] | None = None) -> None:
        self.ref = ref
        self.events: list[dict[str, Any]] = []
        self.cancelled = False
        self._lock = threading.Lock()
        self.process = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env=env)
        self._thread = threading.Thread(target=self._read, daemon=True, name="setu-signin")
        self._thread.start()

    def _add(self, event: dict[str, Any]) -> None:
        with self._lock:
            self.events.append(event)

    def _read(self) -> None:
        assert self.process.stdout is not None
        last: dict[str, Any] = {}
        for line in self.process.stdout:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue        # not a line of the contract; never guessed at
            if isinstance(event, dict) and event.get("event"):
                if event["event"] == "connected" and event.get("ref"):
                    self.ref = str(event["ref"])
                last = event
                self._add(event)
        self.process.wait()
        why = (self.process.stderr.read() if self.process.stderr else "").strip()
        for pipe in (self.process.stdin, self.process.stdout, self.process.stderr):
            if pipe is not None:
                pipe.close()
        if self.cancelled:
            self._add({"event": "cancelled"})
        elif last.get("event") not in ("connected", "error"):
            self._add({"event": "error",
                       "message": why.splitlines()[-1] if why else "setu stopped early"})
        self._add({"event": "done", "ref": self.ref})

    @property
    def running(self) -> bool:
        return self.process.poll() is None

    def say(self, line: str) -> None:
        if not self.running or self.process.stdin is None:
            raise ApiError(409, "that sign-in is over")
        try:
            self.process.stdin.write(line.replace("\n", " ").strip() + "\n")
            self.process.stdin.flush()
        except (BrokenPipeError, ValueError):
            raise ApiError(409, "that sign-in is over") from None

    def cancel(self) -> None:
        self.cancelled = True
        if self.running:
            self.process.terminate()

    def state(self) -> dict[str, Any]:
        with self._lock:
            return {"ref": self.ref, "running": self.running, "events": list(self.events)}


class Api:
    """What each endpoint does, apart from HTTP -- so tests can call it
    straight, and the handler below stays a thin skin."""

    def __init__(self, vault: FileVault | None = None,
                 setu: list[str] | None = None, *, person: str | None = None,
                 env: dict[str, str] | None = None) -> None:
        self.vault = vault or FileVault()
        self.setu = setu or setu_argv()
        #: A person's page (people.py), or None for the owner's.
        self.person = person
        #: The environment Setu's children run in (a person's: their folder).
        self.env = env
        self.signin: SignIn | None = None
        self._signin_lock = threading.Lock()

    @classmethod
    def for_person(cls, person: str, home: Path, setu: list[str] | None = None) -> Api:
        """A person's page, on their folder. Their sign-ins borrow the
        owner's Google client when their folder names none of its own --
        it is the owner's app either way."""
        env = {**os.environ, "SETU_HOME": str(home)}
        env.pop("SETU_VAULT_KEY", None)
        own = {}
        try:
            own = json.loads((home / config.CONFIG_FILE).read_text("utf-8"))
        except (OSError, ValueError):
            pass
        client = config.google_client_file()
        if client and not (isinstance(own, dict) and own.get("google_client_file")):
            env[config.ENV_CLIENT_FILE] = client
        return cls(FileVault(home), setu, person=person, env=env)

    def handle(self, method: str, path: str, query: dict[str, list[str]],
               body: dict | None = None, *, local: bool = True
               ) -> tuple[int, dict[str, Any]]:
        parts = [p for p in path.split("/") if p][1:]      # after "api"
        if self.person is not None and tuple(parts) not in (
                PERSON_POST if method == "POST" else PERSON_GET):
            raise ApiError(403, "that part of the page is your owner's")
        if method == "POST":
            return self._write(parts, body or {}, local)
        if method != "GET":
            raise ApiError(405, f"no such endpoint: {method} /api/{'/'.join(parts)}")
        if parts == ["signin"]:
            return 200, (self.signin.state() if self.signin else {"ref": None,
                                                                   "running": False,
                                                                   "events": []})
        if parts == ["status"]:
            return 200, self.status()
        if parts == ["connections"]:
            return 200, {"connections": self.connections()}
        if parts == ["connectors"]:
            return 200, {"connectors": self.connectors()}
        if parts == ["requests"]:
            ref = (query.get("ref") or [""])[0]
            limit = _int((query.get("limit") or ["100"])[0], "limit")
            return 200, self.log(ref, max(1, min(limit, MAX_LOG_LINES)))
        if parts == ["catalog"]:
            return 200, self.catalog()
        if parts == ["certifiers"]:
            return 200, {"certifiers": self.certifiers()}
        if parts == ["settings"]:
            return 200, self.settings()
        raise ApiError(404, f"no such endpoint: GET /api/{'/'.join(parts)}")

    # ---- writes ---------------------------------------------------------------

    def _write(self, parts: list[str], body: dict, local: bool) -> tuple[int, dict[str, Any]]:
        if parts == ["connect"]:
            return 200, self.connect(body, local)
        if parts == ["add-site"]:
            return 200, self.add_site(body, local)
        if parts == ["disconnect"]:
            return 200, self.disconnect(str(body.get("ref") or ""))
        if parts == ["signin", "answer"]:
            if not isinstance(body.get("yes"), bool):
                raise ApiError(400, "yes must be true or false")
            self._current().say("yes" if body["yes"] else "no")
            return 200, {"ok": True}
        if parts == ["signin", "paste"]:
            address = str(body.get("address") or "").strip()
            if not address.startswith(("http://", "https://")):
                raise ApiError(400, "paste the whole address the page ended on")
            self._current().say(address)
            return 200, {"ok": True}
        if parts == ["signin", "cancel"]:
            if self.signin is not None:
                self.signin.cancel()
            return 200, {"ok": True}
        if parts == ["install"]:
            return 200, self.install(str(body.get("connector") or ""),
                                     str(body.get("sha256") or ""))
        if parts == ["certifiers", "remove"]:
            kid = str(body.get("id") or "")
            if kid not in certify.trusted(self.vault.home):
                raise ApiError(404, f"no trusted certifier {kid!r}")
            certify.distrust(kid, self.vault.home)
            return 200, {"removed": kid}
        if parts == ["settings"]:
            return 200, self.set(str(body.get("name") or ""), body.get("value"))
        raise ApiError(404, f"no such endpoint: POST /api/{'/'.join(parts)}")

    def _current(self) -> SignIn:
        if self.signin is None or not self.signin.running:
            raise ApiError(409, "no sign-in is waiting")
        return self.signin

    def _start(self, argv: list[str], ref: str) -> dict[str, Any]:
        with self._signin_lock:
            if self.signin is not None and self.signin.running:
                raise ApiError(409, f"a sign-in to {self.signin.ref} is already waiting -- "
                                    "finish or cancel it first")
            self.signin = SignIn(argv, ref, self.env)
        return {"ref": ref, "started": True}

    def connect(self, body: dict, local: bool) -> dict[str, Any]:
        connector = str(body.get("connector") or "")
        account = str(body.get("account") or "personal").strip()
        level = str(body.get("level") or "")
        if not ACCOUNT_RE.match(account):
            raise ApiError(400, f"account name {account!r}: letters, digits, '.', '_' and "
                                "'-', starting with a letter or digit")
        cards = {c["id"]: c for c in self.connectors()}
        card = cards.get(connector)
        if card is None:
            raise ApiError(404, f"no installed connector {connector!r}")
        if level and level not in [lv["name"] for lv in card["levels"]]:
            raise ApiError(400, f"{card['name']} has no access level {level!r}")
        if not card["ready"]:
            raise ApiError(409, f"{card['name']} {card['not_ready']}")
        argv = [*self.setu, "connect", connector, "--as", account, "--json"]
        argv += ["--level", level] if level else []
        if not local:
            # the person is on another device: the roads made for that
            argv += ["--remote"] if card["road"] == "browser" else ["--paste"]
        return self._start(argv, f"{connector}:{account}")

    def add_site(self, body: dict, local: bool) -> dict[str, Any]:
        site = str(body.get("site") or "").strip().lower()
        site = site.removeprefix("https://").removeprefix("http://").split("/")[0]
        account = str(body.get("account") or "personal").strip()
        level = str(body.get("level") or "read")
        if not SITE_RE.match(site):
            raise ApiError(400, f"{site!r} is not a site's address (try: example.com)")
        if not ACCOUNT_RE.match(account):
            raise ApiError(400, f"account name {account!r} is not a plain word")
        if level not in ("read", "write"):
            raise ApiError(400, f"a site's levels are read and write, not {level!r}")
        if not local:
            # Setu learns the site's sign-in by watching the page, which takes
            # someone at this computer (cli: _connect_remote_json says why)
            raise ApiError(403, "adding a site needs you at the computer running Setu: "
                                f"there, run setu connect --site {site} --as {account}")
        return self._start([*self.setu, "connect", "--site", site, "--as", account,
                            "--level", level, "--json"], f"{site}:{account}")

    def disconnect(self, ref: str) -> dict[str, Any]:
        if not ref or ref not in self.vault.list():
            raise ApiError(404, f"no connection {ref!r}")
        done = subprocess.run([*self.setu, "disconnect", ref], capture_output=True,
                              text=True, timeout=120, env=self.env)
        said = (done.stdout + done.stderr).strip()
        if done.returncode != 0:
            raise ApiError(502, said or "setu disconnect failed")
        return {"disconnected": ref, "said": said}

    def status(self) -> dict[str, Any]:
        data = status.report(self.vault)
        index = data["catalog"]
        if self.person is not None:
            # a person's page: their folder by its name, nothing of the owner's
            return {"format": "setu.page.status.v1", "version": data["version"],
                    "person": self.person, "folder": self.person, "lock": data["lock"],
                    "catalog": None, "connections": len(data["connections"]),
                    "problems": [p for p in data["problems"] if not p.startswith("catalog")]}
        return {"format": "setu.page.status.v1", "version": data["version"],
                "person": None, "folder": str(self.vault.home), "lock": data["lock"],
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
            card["health_line"] = health.line(row["ref"], self.vault.home)
            rows.append(card)
        return rows

    def connectors(self) -> list[dict[str, Any]]:
        return [{k: v for k, v in card.items() if k != "browser"}
                for card in status.report(self.vault)["connectors"]]

    # ---- the catalog, certifiers, settings (the owner's) ------------------------------

    def catalog(self) -> dict[str, Any]:
        """``setu catalog``, as data: each listed connector with who wrote
        it, its installs, every withdrawn version, the hash its wheel must
        have, and what certifiers said; then what is installed but not
        listed, and the recipes."""
        home = self.vault.home
        index = catalog.kept(home)
        if index is None:
            # no catalog, no labels: nothing is "sideloaded" against nothing
            return {"kept": False, "connectors": [], "recipes": [], "unlisted": [],
                    "trusted_keys": list(catalog.trusted(home))}
        try:
            known = installed()
        except Exception:                  # a broken manifest is status's to report
            known = {}
        rows = []
        for cid, entry in index.connectors.items():
            card = index.card(cid)
            wheel = entry.get("wheel") or {}
            withdrawn = entry.get("yanked") or {}
            rows.append({
                "id": cid, "name": entry.get("name") or cid,
                "summary": entry.get("summary") or "",
                "by": ("by Setu" if entry["label"] == "by-setu" else
                       f"by {entry.get('author') or '?'}, reviewed and published by Setu"),
                "label": entry["label"], "author_signed": card.get("author_signed", ""),
                "installs": entry.get("installs"), "latest": entry.get("version") or "",
                "installed": cid in known,
                "installed_version": card.get("installed_version") or "",
                "withdrawn": {str(v): str(r) for v, r in withdrawn.items()},
                "latest_withdrawn": str(withdrawn.get(entry.get("version") or "", "")),
                "sha256": str(wheel.get("sha256") or "").lower(),
                "certified": certify.certified(index, "connector", cid, home).get("line", ""),
            })
        return {
            "kept": True, "source": index.source, "key": index.key,
            "issued": index.data.get("issued") or "", "kept_at": catalog.kept_at(home),
            "connectors": rows,
            "unlisted": [{"id": cid, "how": "added on this computer" if known[cid].local
                          else "sideloaded"}
                         for cid in sorted(set(known) - set(index.connectors))],
            "recipes": [{"name": r.get("name") or "", "needs": list(r.get("needs") or []),
                         "author": r.get("author") or "",
                         "certified": certify.certified(index, "recipe", r.get("name", ""),
                                                        home).get("line", "")}
                        for r in index.recipes],
            "trusted_keys": list(catalog.trusted(home)),
        }

    def install(self, connector: str, sha256: str) -> dict[str, Any]:
        """``setu install`` -- if the hash the page showed is still the one
        the signed catalog names."""
        index = catalog.kept(self.vault.home)
        entry = index.connectors.get(connector) if index is not None else None
        if entry is None:
            raise ApiError(404, f"the catalog does not list {connector!r}")
        wanted = str((entry.get("wheel") or {}).get("sha256") or "").lower()
        if not wanted or not hmac.compare_digest(wanted, sha256.lower()):
            raise ApiError(409, f"the catalog's hash for {connector} is now "
                                f"{wanted[:16]}…, not the one shown -- look again")
        try:
            done = subprocess.run([*self.setu, "install", connector], capture_output=True,
                                  text=True, timeout=INSTALL_SECONDS, env=self.env)
        except subprocess.TimeoutExpired:
            raise ApiError(504, f"installing {connector} took too long") from None
        said = (done.stdout + done.stderr).strip()
        if done.returncode != 0:
            raise ApiError(502, said.removeprefix("error: ") or "setu install failed")
        return {"installed": connector, "said": said}

    def certifiers(self) -> list[dict[str, Any]]:
        """The certifiers you trust, and how many versions each certified
        (their latest word on each; a withdrawal is counted apart)."""
        home = self.vault.home
        latest: dict[tuple[str, str], dict[str, Any]] = {}
        for cert in catalog.certifications(home):
            try:
                kid = certify.verify(cert)
            except certify.CertError:
                continue
            s = cert["subject"]
            key = (kid, f"{s.get('kind')}:{s.get('id')}:{s.get('sha256')}")
            if key not in latest or cert["at"] > latest[key]["at"]:
                latest[key] = cert
        rows = []
        for kid, who in certify.trusted(home).items():
            mine = [c for (k, _), c in latest.items() if k == kid]
            rows.append({"id": kid, "name": who.get("name") or "",
                         "certified": sum(c["verdict"] == "certified" for c in mine),
                         "withdrawn": sum(c["verdict"] == "revoked" for c in mine)})
        return rows

    def settings(self) -> dict[str, Any]:
        kept = config.load()
        rows = []
        for name, key in config.KEYS.items():
            env = SETTING_ENV.get(name)
            rows.append({"name": name, "about": SETTINGS.get(name, ""),
                         "value": kept.get(key) or "",
                         "switch": name in config.SWITCHES,
                         "from_env": env if env and os.environ.get(env) else ""})
        window = {k: os.environ.get(k, "") for k in
                  ("SETU_WINDOW_HOST", "SETU_WINDOW_PORT", "SETU_WINDOW_URL")}
        return {"settings": rows, "window": window}

    def set(self, name: str, value: Any) -> dict[str, Any]:
        if name not in config.KEYS:
            raise ApiError(404, f"no setting {name!r}")
        if value is None or value == "":
            config.save(config.KEYS[name], None)
            return {"name": name, "value": ""}
        try:
            kept = config.check(name, str(value))
        except (ValueError, OSError) as exc:
            raise ApiError(400, str(exc)) from None
        except Exception as exc:          # a client file Google's reader refused
            raise ApiError(400, str(exc)) from None
        config.save(config.KEYS[name], kept)
        return {"name": name, "value": kept}

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


def people_dir(raw: str | None) -> Path | None:
    """``--people`` or ``$SETU_PAGE_PEOPLE``: the folder people's own Setu
    folders are in (a door's ``state/setu``). None: no person's page."""
    raw = (raw if raw is not None else os.environ.get(ENV_PEOPLE, "")).strip()
    if not raw:
        return None
    path = Path(raw).expanduser().resolve()
    if not path.is_dir():
        raise ValueError(f"people's folders: {path} is not a folder")
    return path


def link_base(raw: str | None = None) -> str:
    """The address a person's link opens: ``--url``, ``$SETU_PAGE_URL``, or
    the streamed window's host (``SETU_WINDOW_HOST``) on the page's port --
    so one Tailscale or home-network choice covers both. A link to
    127.0.0.1 would open nothing on a phone, so with none of them set
    there is no link."""
    found = public_address(raw)
    if found:
        return found
    host = os.environ.get("SETU_WINDOW_HOST", "").strip()
    if host and host not in ("127.0.0.1", "localhost", "::1", "0.0.0.0"):
        port = os.environ.get("SETU_PAGE_PORT", "").strip() or str(DEFAULT_PORT)
        return f"http://{host}:{port}/"
    raise ValueError("a person's link needs the address their phone reaches Setu's page "
                     f"at: set {ENV_PUBLIC} (or SETU_WINDOW_HOST, the streamed window's)")


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
                 embed: list[str] | None = None, people_dir: Path | None = None) -> None:
        self.api = api
        self.token = token
        #: Where people's own folders are (``--people``); None: no person's page.
        self.people = people_dir
        self._people: dict[str, Api] = {}
        self._people_lock = threading.Lock()
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

    def people_on(self) -> bool:
        """People's pages: given a folder for them, and not switched off in
        the owner's folder. Asked on every request, so the switch is
        immediate."""
        return self.people is not None and config.people_page(self.api.vault.home)

    def api_for(self, offered: str) -> Api | None:
        """The page this token opens: the owner's, a person's, or none."""
        if hmac.compare_digest(offered.encode(), self.token.encode()):
            return self.api
        if not offered.startswith(people.PREFIX) or self.people is None:
            return None
        person = people.session(self.people, offered)
        if person is None:
            return None
        if not self.people_on():
            raise ApiError(403, "your owner has turned this page off. /accounts and "
                                "/connect still work in your chat")
        with self._people_lock:
            if person not in self._people:
                self._people[person] = Api.for_person(person, self.people / person,
                                                      self.api.setu)
            return self._people[person]

    def claim(self, link: str, device: str) -> dict[str, Any]:
        if self.people is None:
            raise ApiError(404, "this Setu has no people's pages")
        if not self.people_on():
            raise ApiError(403, "your owner has turned this page off. /accounts and "
                                "/connect still work in your chat")
        try:
            person, secret = people.claim(self.people, link, device)
        except people.PeopleError as exc:
            raise ApiError(403, str(exc)) from None
        return {"person": person, "token": secret}

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

        def _offered(self) -> str:
            offered = self.headers.get("Authorization", "")
            return offered[7:].strip() if offered.startswith("Bearer ") else ""

        def _dispatch(self, method: str) -> None:
            url = urlparse(self.path)
            if method == "GET" and url.path in STATIC:
                name, kind = STATIC[url.path]
                return self._send(200, files("setu").joinpath("static", name).read_bytes(),
                                  kind)
            if not url.path.startswith("/api/"):
                return self._json(404, {"detail": "not found"})
            # a person's link is its own key: the only call without a token
            claiming = method == "POST" and url.path == "/api/people/claim"
            try:
                api = None if claiming else server.api_for(self._offered())
            except ApiError as exc:
                return self._json(exc.code, {"detail": exc.detail})
            if api is None and not claiming:
                return self._json(401, {"detail": "missing or wrong token"})
            body: dict = {}
            if method == "POST":
                origin = self.headers.get("Origin")
                allowed = {f"http://{self.headers.get('Host')}",
                           f"https://{self.headers.get('Host')}", *server.embed}
                if origin is not None and origin not in allowed:
                    return self._json(403, {"detail": "a change comes from this page only"})
                size = int(self.headers.get("Content-Length") or 0)
                if size > MAX_BODY:
                    return self._json(413, {"detail": "request too large"})
                try:
                    body = json.loads(self.rfile.read(size) or b"{}")
                except json.JSONDecodeError:
                    return self._json(400, {"detail": "the body is not JSON"})
                if not isinstance(body, dict):
                    return self._json(400, {"detail": "the body is a JSON object"})
            # where the person is: this computer, or another device
            local = self.client_address[0] in ("127.0.0.1", "::1", "::ffff:127.0.0.1")
            try:
                if claiming:
                    code, data = 200, server.claim(str(body.get("link") or ""),
                                                   self.headers.get("User-Agent") or "")
                elif url.path == "/api/session/close" and method == "POST":
                    if api is server.api:
                        raise ApiError(400, "the owner's page has no session to close")
                    people.close(server.people, self._offered())
                    code, data = 200, {"closed": True}
                else:
                    code, data = api.handle(method, url.path, parse_qs(url.query), body,
                                            local=local)
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
