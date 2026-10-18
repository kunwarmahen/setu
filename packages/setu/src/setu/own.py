"""A server of your own: an MCP server you bring, kept by Setu.

Connectors are written for a site: Gmail's, Home Assistant's. A person
also has servers nobody wrote a connector for -- a docs server at work,
a tool they run on their own computer. Without Setu such a server is a
line in each harness's own config, its token pasted into each, and a
household's chat never sees it. ``setu connect --server URL`` (or
``--server-command 'uvx weather-mcp'``) makes it a connection like any
other: one place it is added, one place its token lives, and every
harness that asks Setu what to start -- Yantra, Dvara -- starts it.

EACH SERVER IS A CONNECTOR OF ITS OWN. A harness merges the accounts of
one connector into one set of tools (Yantra's ``account`` argument), so
two different servers under one generic connector would be merged into
nonsense. Each gets a manifest Setu writes into ``servers/``, named by
``--id`` (or from the address), and the connection is ``<id>:<account>``
as everywhere else. An id an installed connector or a site already has
is refused.

TRIED BEFORE IT IS KEPT. Adding one talks to it: ``initialize``, then
``tools/list``. A server that does not answer, asks for a token nobody
gave, or refuses the one given saves nothing -- the way Home Assistant's
pasted token is tried first.

THE SERVER'S LIST, CLASSED ONCE, THEN THE PERSON'S. Every tool it lists
is written into ``[verbs]``: ``read`` when the server marks it read-only
(``readOnlyHint``) and not destructive, ``write`` otherwise, and ``"*" =
"write"`` for whatever it adds later -- asked about, never run unasked.
It is the server's own claim, taken once and written down where the
person can read and change it (``setu site file ID``); adding the server
again keeps every line already there and adds the new tools.

TWO LEVELS. *Only its reading tools* is the least, as every manifest's
first level is; *All its tools* is what adding one gives unless told,
since the person brought the server. At the first level a ``tools/call``
of anything not classed read is refused before it leaves the computer,
and the list a harness sees has only the read ones.

TWO ROADS, AND THE CARD SAYS WHICH.

* **An address** runs as every connector runs: this module's bridge
  (``setu-own-mcp``) reads MCP lines on stdio and POSTs each one with
  ``setu.http()``, inside bubblewrap, with no network and no key; Setu's
  proxy adds the token and sends it to that address only. A server that
  refuses the token marks the connection, as an expired sign-in does.
* **A program you run** (``--server-command``) is started by ``setu run``
  itself, with the environment values the person gave (``--env NAME``,
  kept in the vault, not in the file), and its stdio relayed through
  the same level. It is NOT sandboxed: a server you run needs your
  network and your files, and its card says it runs as you. The command
  lives in the vault entry, never in the file, so only ``setu connect``
  -- the person, at their computer -- can make Setu run a program.

A SERVER THAT SIGNS IN ON ITS OWN PAGE. One that answers 401 and says
where its sign-in is (MCP's OAuth) is signed in to the way Google is:
its page in a browser, or a link opened elsewhere and the address it
ended on pasted back (mcp_auth.py). The refresh token stays in the
vault and is renewed by Setu, so nothing else ever holds it.

A TOKEN IS NEVER AN ARGUMENT, and never part of the address: ``--token-
stdin`` reads it, and an address with a query string (where keys like
to hide) is refused with that advice.
"""

from __future__ import annotations

import json
import os
import queue
import re
import shlex
import signal
import subprocess
import sys
import threading
from collections import deque
from collections.abc import Callable
from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path
from typing import IO, Any
from urllib.parse import urlparse

import httpx

from setu import __version__
from setu.manifest import Manifest, ManifestError, installed, load, servers_dir
from setu.vault import Vault

#: What a POST to a Streamable HTTP server says it can read back.
HEADERS = {"Accept": "application/json, text/event-stream",
           "Content-Type": "application/json"}
PROTOCOL = "2025-06-18"
INIT = {"protocolVersion": PROTOCOL, "capabilities": {},
        "clientInfo": {"name": "setu", "version": __version__}}
#: The bridge's two settings, from ``setu run``: the server's path, and
#: (at the first level) the tools it may show.
ENV_PATH = "SETU_MCP_PATH"
ENV_READ = "SETU_READ_TOOLS"
#: How long trying a server may take, per answer.
PROBE_TIMEOUT = 30.0
#: ``tools/list`` pages read when trying a server, at most.
MAX_PAGES = 20
#: The two levels, in order (the first is the default of the manifest).
LEVELS = {
    "read": {"label": "Only its reading tools",
             "description": "The tools the server marks read-only, as Setu wrote them down "
                            "when it was added (change any in its file). Every other tool is "
                            "hidden, and refused before it leaves this computer."},
    "write": {"label": "All its tools",
              "description": "Every tool the server offers. The ones not classed read are "
                             "asked about before they run."},
}
#: What adding a server gives unless told: the person brought it.
ADDED_LEVEL = "write"
#: Runners whose first plain word is the server's name (uvx weather-mcp).
_RUNNERS = {"uvx", "npx", "pipx", "bunx", "pnpx", "uv", "node", "python", "python3",
            "deno", "bun", "docker", "podman", "run", "exec", "tool", "dlx"}
ID_RE = re.compile(r"[a-z0-9][a-z0-9_-]*")
HEADER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*")
ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class ServerError(Exception):
    """A server that cannot be added as asked, said in words."""


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---- names -----------------------------------------------------------------------


def address(url: str) -> tuple[str, str, str]:
    """``https://docs.example.com/mcp`` -> (origin, path, host), checked."""
    parsed = urlparse(url.strip())
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ServerError(f"{url!r} is not a server's address (try: https://example.com/mcp)")
    if parsed.username or parsed.password:
        raise ServerError("put no name or password in the address; give a token with "
                          "--ask-token instead")
    if parsed.query or parsed.fragment:
        raise ServerError("the address has a query (?...); a key there would be kept "
                          "in plain sight, so give the token with --ask-token instead")
    host = parsed.hostname.lower()
    port = f":{parsed.port}" if parsed.port else ""
    shown = f"[{host}]" if ":" in host else host
    return f"{parsed.scheme}://{shown}{port}", parsed.path or "/", host


def _word(text: str) -> str:
    return re.sub(r"[^a-z0-9_-]+", "-", text.lower()).strip("-_")


def id_from(*, url: str | None = None, command: list[str] | None = None) -> str:
    """The id an address or a command suggests -- or ServerError, when
    nothing in it is a name (an IP address, ``localhost``)."""
    if url:
        _, path, host = address(url)
        try:
            ip_address(host)
            named = ""
        except ValueError:
            labels = [x for x in host.split(".") if x not in ("www", "mcp", "api")]
            named = labels[-2] if len(labels) >= 2 else ("" if host == "localhost"
                                                         else labels[0] if labels else "")
        if not named:
            # a server on this computer: its path may still say what it is
            named = next((p for p in reversed(path.split("/")) if p and p != "mcp"), "")
        found = _word(named)
    else:
        argv = list(command or [])
        words = [Path(argv[0]).name] if argv else []
        for arg in argv[1:]:
            if words and words[-1] not in _RUNNERS:
                break
            if arg.startswith("-"):
                continue
            words.append(arg.split("/")[-1].split("@")[0] if arg.startswith("@")
                         else arg.split("@")[0])
        found = _word(words[-1]) if words else ""
        found = re.sub(r"(^mcp-|-mcp$|-server$|^server-)", "", found) or found
    if not found or not ID_RE.fullmatch(found):
        raise ServerError("Setu cannot make a name from that; give one with --id")
    return found


def path_for(server_id: str) -> Path:
    return servers_dir() / f"{server_id}.toml"


# ---- talking MCP, to try it -----------------------------------------------------


def messages(response: httpx.Response) -> list[dict[str, Any]]:
    """The JSON-RPC message(s) in one answer: a JSON body, or the data
    lines of an event stream."""
    kind = response.headers.get("content-type", "")
    if "text/event-stream" in kind:
        out = []
        for line in response.text.splitlines():
            if line.startswith("data:") and line[5:].strip():
                out.append(json.loads(line[5:].strip()))
        return out
    if not response.content.strip():
        return []
    data = response.json()
    return data if isinstance(data, list) else [data]


class _HttpPeer:
    """A Streamable HTTP server, for the few messages of a try."""

    def __init__(self, url: str, headers: dict[str, str], http: httpx.Client) -> None:
        self.url, self.http, self.headers = url, http, {**HEADERS, **headers}
        self.with_token = bool(headers)
        self.session: str | None = None
        self.next = 0

    def _post(self, message: dict[str, Any]) -> httpx.Response:
        headers = dict(self.headers)
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        try:
            response = self.http.post(self.url, json=message, headers=headers,
                                      timeout=PROBE_TIMEOUT)
        except httpx.HTTPError as exc:
            raise ServerError(f"{self.url} did not answer: {exc}") from None
        self.session = response.headers.get("mcp-session-id") or self.session
        if response.status_code in (401, 403):
            raise ServerError(
                f"{self.url} refused the token you gave (HTTP {response.status_code})"
                if self.with_token
                else f"{self.url} asks for a token (HTTP {response.status_code}); add one "
                     "with --ask-token (and --header NAME if it is not a Bearer token)")
        if response.status_code == 404:
            raise ServerError(f"{self.url} has no MCP server there (HTTP 404)")
        if response.status_code >= 400:
            raise ServerError(f"{self.url} answered HTTP {response.status_code}: "
                              f"{response.text[:200]}")
        return response

    def request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self.next += 1
        response = self._post({"jsonrpc": "2.0", "id": self.next, "method": method,
                               "params": params})
        try:
            found = [m for m in messages(response) if m.get("id") == self.next]
        except ValueError:
            raise ServerError(f"{self.url} answered with something that is not MCP") from None
        if not found:
            raise ServerError(f"{self.url} gave no answer to {method}")
        return found[0]

    def notify(self, method: str) -> None:
        try:
            self._post({"jsonrpc": "2.0", "method": method})
        except ServerError:
            pass                    # a notification has no answer to miss

    def close(self) -> None:
        pass


class _StdioPeer:
    """A program speaking MCP on its stdio, started for the try."""

    def __init__(self, argv: list[str], env: dict[str, str]) -> None:
        try:
            self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE, text=True, env=env)
        except OSError as exc:
            raise ServerError(f"cannot start {argv[0]!r}: {exc}") from None
        self.lines: queue.Queue[str | None] = queue.Queue()
        self.said: deque[str] = deque(maxlen=5)
        self.next = 0
        threading.Thread(target=self._read, daemon=True).start()
        threading.Thread(target=self._errors, daemon=True).start()

    def _read(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            self.lines.put(line)
        self.lines.put(None)

    def _errors(self) -> None:
        assert self.proc.stderr is not None
        for line in self.proc.stderr:
            if line.strip():
                self.said.append(line.strip())

    def _send(self, message: dict[str, Any]) -> None:
        assert self.proc.stdin is not None
        try:
            self.proc.stdin.write(json.dumps(message) + "\n")
            self.proc.stdin.flush()
        except (BrokenPipeError, ValueError):
            raise ServerError(self._gone()) from None

    def _gone(self) -> str:
        last = f": {self.said[-1]}" if self.said else ""
        return f"the program stopped before it answered{last}"

    def request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self.next += 1
        self._send({"jsonrpc": "2.0", "id": self.next, "method": method, "params": params})
        while True:
            try:
                line = self.lines.get(timeout=PROBE_TIMEOUT)
            except queue.Empty:
                raise ServerError(f"the program did not answer {method} within "
                                  f"{int(PROBE_TIMEOUT)} seconds") from None
            if line is None:
                raise ServerError(self._gone())
            try:
                message = json.loads(line)
            except ValueError:
                continue              # a line of its own logging, on the wrong stream
            if isinstance(message, dict) and message.get("id") == self.next \
                    and "method" not in message:
                return message

    def notify(self, method: str) -> None:
        self._send({"jsonrpc": "2.0", "method": method})

    def close(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


def _talk(peer: _HttpPeer | _StdioPeer) -> dict[str, Any]:
    try:
        hello = peer.request("initialize", INIT)
        if "error" in hello:
            raise ServerError(f"the server would not start a session: "
                              f"{hello['error'].get('message', hello['error'])}")
        peer.notify("notifications/initialized")
        tools: list[dict[str, Any]] = []
        cursor = None
        for _ in range(MAX_PAGES):
            answer = peer.request("tools/list", {"cursor": cursor} if cursor else {})
            if "error" in answer:
                raise ServerError(f"the server would not list its tools: "
                                  f"{answer['error'].get('message', answer['error'])}")
            result = answer.get("result") or {}
            tools += [t for t in result.get("tools") or [] if isinstance(t, dict)
                      and isinstance(t.get("name"), str)]
            cursor = result.get("nextCursor")
            if not cursor:
                break
        return {"server": (hello.get("result") or {}).get("serverInfo") or {}, "tools": tools}
    finally:
        peer.close()


def probe_http(url: str, headers: dict[str, str], http: httpx.Client) -> dict[str, Any]:
    """``{"server": serverInfo, "tools": [...]}`` from the server at ``url``."""
    return _talk(_HttpPeer(url, headers, http))


def probe_stdio(argv: list[str], env: dict[str, str]) -> dict[str, Any]:
    return _talk(_StdioPeer(argv, env))


# ---- the file ----------------------------------------------------------------------


def _read_only(tool: dict[str, Any]) -> bool:
    notes = tool.get("annotations") or {}
    return notes.get("readOnlyHint") is True and notes.get("destructiveHint") is not True


def draft(server_id: str, *, name: str, tools: list[dict[str, Any]], url: str | None = None,
          program: str = "", before: Manifest | None = None) -> dict[str, Any]:
    """The manifest for a server, from what it listed. A line already in
    ``before`` -- the person's, or the first try's -- is kept as it is."""
    kept = dict(before.verbs) if before is not None else {}
    verbs: dict[str, str] = {}
    described: dict[str, str] = {}
    for tool in tools:
        tid = tool["name"]
        verbs[tid] = kept.pop(tid, None) or ("read" if _read_only(tool) else "write")
        described[tid] = " ".join(str(tool.get("description") or "").split())[:90]
    for tid, klass in kept.items():
        if tid != "*":
            verbs[tid] = klass            # gone from the list now; the person's line stays
    verbs["*"] = "write"
    data: dict[str, Any] = {
        "id": server_id,
        "name": name,
        "road": "mcp",
        "auth": "own",
        "levels": LEVELS,
        "verbs": verbs,
        "_described": described,
    }
    if url:
        origin, path, host = address(url)
        data.update({
            "summary": f"Your own MCP server at {host}{'' if path == '/' else path}.",
            "api_base": origin, "mcp_path": path, "hosts": [host],
            # every request goes to the server's own address; at the first
            # level, Setu itself refuses a tool the verbs do not class read
            "requests": {"read": {"allow": [f"POST {path}", f"GET {path}",
                                            f"DELETE {path}"]}},
        })
    else:
        data["summary"] = f"Your own MCP server: the program {program}, run on this computer."
    return data


def _value(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


def _key(name: str) -> str:
    return name if re.fullmatch(r"[A-Za-z0-9_-]+", name) else _value(name)


def to_toml(data: dict[str, Any]) -> str:
    lines = [f"# {data['name']}: a server of your own, added by `setu connect --server`.",
             "# Each tool's line says whether it only reads (\"read\": may run unasked, and",
             "# is all \"Only its reading tools\" shows) or changes things (\"write\": asked",
             "# about first). They were written from the server's own list; change any.",
             "# What it reaches is in the connection, not here.", ""]
    for key in ("id", "name", "summary", "road", "auth", "api_base", "mcp_path", "hosts"):
        if key in data:
            lines.append(f"{key} = {_value(data[key])}")
    for level, spec in data["levels"].items():
        lines += ["", f"[levels.{level}]"]
        lines += [f"{key} = {_value(value)}" for key, value in spec.items()]
    lines += ["", "[verbs]"]
    described = data.get("_described") or {}
    for tool, klass in data["verbs"].items():
        if described.get(tool):
            lines.append(f"# {described[tool]}")
        lines.append(f"{_key(tool)} = {_value(klass)}")
    for level, rules in (data.get("requests") or {}).items():
        lines += ["", f"[requests.{level}]"]
        lines += [f"{key} = {_value(value)}" for key, value in rules.items()]
    return "\n".join(lines) + "\n"


def write(data: dict[str, Any]) -> Manifest:
    """Save to ``servers/`` and read it back the way every manifest is
    read -- a file Setu itself cannot load is never left."""
    directory = servers_dir()
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    target = path_for(data["id"])
    staged = target.with_suffix(".toml.new")
    staged.write_text(to_toml(data), encoding="utf-8")
    try:
        load(staged)
    except ManifestError:
        staged.unlink()
        raise
    staged.replace(target)
    return load(target)


def forget(server_id: str) -> None:
    """The server's file, gone with its last connection."""
    for path in (path_for(server_id), path_for(server_id).with_suffix(".toml.bak")):
        path.unlink(missing_ok=True)


def read_tools(manifest: Manifest) -> list[str]:
    return sorted(t for t, k in manifest.verbs.items() if k == "read" and t != "*")


# ---- adding one ------------------------------------------------------------------------


def _clean_env(base: dict[str, str] | None = None) -> dict[str, str]:
    from setu import seal
    env = dict(os.environ if base is None else base)
    for name in (seal.ENV_KEY, "SETU_VAULT_KEY", "SETU_PROXY", "SETU_PROXY_KEY",
                 "SETU_TOKEN_FD", "SETU_ACCESS_TOKEN"):
        env.pop(name, None)
    return env


def connect(server_id: str | None, account: str, *, vault: Vault, http: httpx.Client,
            url: str | None = None, command: str | list[str] | None = None,
            token: str | None = None, header: str | None = None,
            env: dict[str, str] | None = None, level: str | None = None,
            sign_in: Callable[[str, str], dict[str, Any]] | None = None,
            signed_in: dict[str, Any] | None = None) -> dict[str, Any]:
    """Try the server, write its file, keep the connection. The entry
    comes back with ``tools`` (how many) and ``manifest_path``.

    ``sign_in(url, challenge)`` is called when the server asks for a
    sign-in on its own page (mcp_auth.sign_in, with the caller's browser
    or paste road); ``signed_in`` is one already made (``again``)."""
    from setu import connections
    if (url is None) == (command is None):
        raise ServerError("give the server's address (--server URL) or the command that "
                          "starts it (--server-command CMD), one of them")
    argv = shlex.split(command) if isinstance(command, str) else list(command or [])
    if command is not None and not argv:
        raise ServerError("the command is empty")
    if header and not token:
        raise ServerError("--header names where a token goes; give the token too "
                          "(--ask-token)")
    if header and not HEADER_RE.fullmatch(header):
        raise ServerError(f"{header!r} is not a header's name (try X-API-Key)")
    if argv and token:
        raise ServerError("a program you run takes its keys in its environment: "
                          "--env NAME, not --ask-token")
    if url and env:
        raise ServerError("--env is for a program you run; a server at an address takes "
                          "a token (--ask-token)")
    for name in env or {}:
        if not ENV_NAME_RE.fullmatch(name):
            raise ServerError(f"{name!r} is not an environment variable's name")
    if server_id is None:
        try:
            server_id = id_from(url=url, command=argv)
        except ServerError:
            server_id = None          # the server's own name, once it has said it
    if server_id is not None:
        server_id = _checked_id(server_id.lower(), account)
    secret: dict[str, Any]
    if url:
        address(url)
        found, signed_in = _try_signed_in(url.strip(), account, http, token=token,
                                          header=header, sign_in=sign_in, signed_in=signed_in)
        _, path, host = address(url)
        where, server = host + ("" if path == "/" else path), {"url": url.strip()}
        secret = (signed_in if signed_in is not None else
                  {"token": token or "", "header": header or "Authorization"} if token else {})
    else:
        found = probe_stdio(argv, {**_clean_env(), **(env or {})})
        where, server = Path(argv[0]).name, {"command": argv}
        secret = {"env": dict(env or {})} if env else {}
    info = found["server"]
    if server_id is None:
        named = _word(str(info.get("name") or info.get("title") or ""))
        if not named or not ID_RE.fullmatch(named):
            raise ServerError("Setu cannot make a name from that address or from the "
                              "server; give one with --id")
        server_id = _checked_id(named, account)
    name = str(info.get("title") or info.get("name") or server_id).strip()[:60] or server_id
    ref = connections.ref_for(server_id, account)
    known = installed().get(server_id)
    manifest = write(draft(server_id, name=name, tools=found["tools"], url=url,
                           program=" ".join(argv), before=known))
    held = manifest.level(level or ADDED_LEVEL)
    entry = {
        "connector": server_id,
        "account": account,
        "auth": "own",
        "email": where,
        "level": held.name,
        "asked_level": held.name,
        "scopes": [],
        "created": _now(),
        "last_used": None,
        "server": server,
        "secret": secret,
    }
    if url:
        entry["base_url"] = address(url)[0]
    vault.put(ref, entry)
    return {**entry, "tools": len(found["tools"]), "manifest_path": str(path_for(server_id))}


def _try_signed_in(url: str, account: str, http: httpx.Client, *, token: str | None,
                   header: str | None, sign_in: Callable[[str, str], dict[str, Any]] | None,
                   signed_in: dict[str, Any] | None) -> tuple[dict[str, Any], dict | None]:
    """The server's answer, and the sign-in it took (None for a pasted
    token or none). Tried as given first; only a 401 that says where its
    sign-in is starts one."""
    from setu import connections, mcp_auth

    def probe(value: str, name: str) -> dict[str, Any]:
        sent = connections.Token(access_token=value, expires_at=0, scopes=(),
                                 account=account, email="", header=name).headers()
        return probe_http(url, sent, http)

    try:
        if signed_in is not None:
            try:
                if mcp_auth.due(signed_in):
                    signed_in = mcp_auth.refresh(signed_in, http)
                return probe(signed_in["token"], "Authorization"), signed_in
            except (mcp_auth.McpAuthError, ServerError):
                if sign_in is None:
                    raise
                signed_in = None        # renewed no more: a new sign-in, below
        try:
            return probe(token or "", header or "Authorization"), None
        except ServerError:
            said = None if token else mcp_auth.challenge(url, http)
            if said is None:
                raise
        if sign_in is None:
            raise ServerError(f"{url} signs in on its own page; add it where a browser can "
                              "open that page (setu connect --server URL, or Setu's page)")
        signed_in = sign_in(url, said)
        return probe(signed_in["token"], "Authorization"), signed_in
    except mcp_auth.McpAuthError as exc:
        raise ServerError(f"signing in to {url}: {exc}") from None


def _checked_id(server_id: str, account: str) -> str:
    """An id this server may have: a plain word no connector or site has."""
    from setu import connections
    if not ID_RE.fullmatch(server_id):
        raise ServerError(f"{server_id!r} cannot name a server: letters, digits, - and _ only")
    connections.ref_for(server_id, account)        # the account is a plain word too
    known = installed().get(server_id)
    if known is not None and known.auth != "own":
        how = "a site added here" if known.local else "an installed connector"
        raise ServerError(f"Setu already has {known.name} ({server_id}, {how}); give this "
                          "server another name with --id")
    return server_id


def again(ref: str, *, vault: Vault, http: httpx.Client, level: str | None = None,
          sign_in: Callable[[str, str], dict[str, Any]] | None = None) -> dict[str, Any]:
    """``setu connect docs --level read``: the connection added before,
    tried again and kept at the level asked -- its address or program,
    and its token or values, as they were. Changing a level is connecting
    again, here as for every connector."""
    entry = vault.get(ref)
    if entry is None or entry.get("auth") != "own":
        cid = ref.partition(":")[0]
        raise ServerError(f"{ref} is not connected, so Setu has no address for it: add "
                          f"it with setu connect --server URL --id {cid} --as "
                          f"{ref.partition(':')[2]}")
    server, secret = entry.get("server") or {}, entry.get("secret") or {}
    if secret.get("kind") == "oauth":
        # its own sign-in, renewed if due: nothing to sign in to again
        # and signed in to anew (sign_in) when the server stopped taking it
        return connect(entry["connector"], entry["account"], vault=vault, http=http,
                       url=server.get("url"), signed_in=secret, sign_in=sign_in,
                       level=level or entry.get("level"))
    header = secret.get("header") if secret.get("token") else None
    return connect(entry["connector"], entry["account"], vault=vault, http=http,
                   url=server.get("url"), command=server.get("command"),
                   token=secret.get("token") or None,
                   header=None if header == "Authorization" else header,
                   env=secret.get("env") or None, level=level or entry.get("level"))


# ---- running one -----------------------------------------------------------------------


def _error(mid: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


class Level:
    """The first level, kept on the wire: a call refused, a list cut."""

    def __init__(self, level: str, readable: list[str] | frozenset[str]) -> None:
        self.read_only = level == "read"
        self.readable = frozenset(readable)

    def refuse(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """The answer to a call this level does not reach, else None."""
        if not self.read_only or message.get("method") != "tools/call":
            return None
        name = str((message.get("params") or {}).get("name", ""))
        if name in self.readable:
            return None
        return _error(message.get("id"), -32601, f"{name!r} changes things, and this "
                      "connection only reads (Setu: Only its reading tools)")

    def cut(self, answer: dict[str, Any]) -> dict[str, Any]:
        result = answer.get("result")
        if self.read_only and isinstance(result, dict) and isinstance(result.get("tools"), list):
            return {**answer, "result": {**result, "tools": [
                t for t in result["tools"] if t.get("name") in self.readable]}}
        return answer


class Bridge:
    """stdio -> the server's address, through ``setu.http()``: Setu's
    proxy adds the token. Nothing is interpreted but the level."""

    def __init__(self, http: httpx.Client, path: str, level: Level) -> None:
        self.http, self.path, self.level = http, path, level
        self.session: str | None = None

    def handle(self, message: dict[str, Any]) -> list[dict[str, Any]]:
        mid = message.get("id")
        refused = self.level.refuse(message)
        if refused is not None:
            return [refused]
        headers = dict(HEADERS)
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        try:
            response = self.http.post(self.path, json=message, headers=headers)
        except httpx.HTTPError as exc:
            return [] if mid is None else [_error(mid, -32000, f"the server is unreachable: "
                                                  f"{exc}")]
        self.session = response.headers.get("mcp-session-id") or self.session
        if response.status_code >= 400:
            try:
                said = response.json().get("error") or response.text
            except ValueError:
                said = response.text
            return [] if mid is None else [_error(
                mid, -32000, f"the server answered HTTP {response.status_code}: "
                f"{str(said)[:300]}")]
        if mid is None:
            return []
        try:
            return [self.level.cut(m) for m in messages(response)]
        except ValueError:
            return [_error(mid, -32000, "the server answered with something that is not MCP")]

    def run(self, stdin: IO[str], stdout: IO[str]) -> None:
        for line in stdin:
            if not line.strip():
                continue
            try:
                message = json.loads(line)
            except ValueError:
                answers = [_error(None, -32700, "not JSON")]
            else:
                answers = self.handle(message) if isinstance(message, dict) else [
                    _error(None, -32600, "one message per line")]
            for answer in answers:
                stdout.write(json.dumps(answer) + "\n")
                stdout.flush()


def main() -> int:
    """``setu-own-mcp``: the bridge, as ``setu run`` starts it."""
    import setu
    try:
        level = setu.granted_level()
        http = setu.http(timeout=120.0)
    except setu.NoToken as exc:
        print(f"setu-own-mcp: {exc}", file=sys.stderr)
        return 2
    try:
        readable = json.loads(os.environ.get(ENV_READ) or "[]")
    except ValueError:
        readable = []
    Bridge(http, os.environ.get(ENV_PATH) or "/", Level(level, readable)).run(
        sys.stdin, sys.stdout)
    return 0


def run_command(ref: str, entry: dict[str, Any], manifest: Manifest, *,
                stdin: IO[str] | None = None, stdout: IO[str] | None = None,
                on_exit: Callable[[int], None] | None = None) -> int:
    """Start a program of your own and relay its stdio through the level.
    Its environment is this one, without Setu's keys, plus the values
    the person gave when adding it."""
    stdin, stdout = stdin or sys.stdin, stdout or sys.stdout
    argv = list((entry.get("server") or {}).get("command") or [])
    if not argv:
        raise ServerError(f"{ref} names no program to run; add it again")
    env = {**_clean_env(), **((entry.get("secret") or {}).get("env") or {})}
    try:
        child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 text=True, env=env)
    except OSError as exc:
        raise ServerError(f"cannot start {argv[0]!r}: {exc}") from None
    level = Level(entry.get("level", ""), read_tools(manifest))
    lists: set[Any] = set()
    lock = threading.Lock()

    def out(message: dict[str, Any]) -> None:
        with lock:
            stdout.write(json.dumps(message) + "\n")
            stdout.flush()

    def back() -> None:
        assert child.stdout is not None
        for line in child.stdout:
            try:
                message = json.loads(line)
            except ValueError:
                continue         # its own logging on the wrong stream: not MCP
            if isinstance(message, dict) and "method" not in message \
                    and message.get("id") in lists:
                lists.discard(message.get("id"))
                message = level.cut(message)
            out(message)

    reader = threading.Thread(target=back, daemon=True)
    reader.start()

    def forward(signum: int, _frame: Any) -> None:
        if child.poll() is None:
            child.send_signal(signum)

    previous = {sig: signal.signal(sig, forward) for sig in (signal.SIGINT, signal.SIGTERM)} \
        if threading.current_thread() is threading.main_thread() else {}
    try:
        assert child.stdin is not None
        for line in stdin:
            if not line.strip():
                continue
            try:
                message = json.loads(line)
            except ValueError:
                message = None
            if isinstance(message, dict):
                refused = level.refuse(message)
                if refused is not None:
                    out(refused)
                    continue
                if message.get("method") == "tools/list" and "id" in message:
                    lists.add(message["id"])
            try:
                child.stdin.write(line if line.endswith("\n") else line + "\n")
                child.stdin.flush()
            except (BrokenPipeError, ValueError):
                break
        try:
            child.stdin.close()
        except BrokenPipeError:
            pass
        code = child.wait()
        reader.join(timeout=5)
        return code
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        if child.poll() is None:
            child.terminate()
