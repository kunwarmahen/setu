"""The connector's side: ``setu.http()``, and nothing to know about keys.

A connector author writes::

    http = setu.http()
    http.get("/gmail/v1/users/me/labels")

and gets an ``httpx.Client`` whose requests are already signed. Where
the token came from is decided by whoever started the process, not by
the connector:

* started by ``setu run`` -- no token at all: requests go over a unix
  socket (``SETU_PROXY``) to Setu, which adds the token itself and sends
  them on to the site (proxy.py);
* started by ``setu run`` for a connector granted the callback -- a
  private pipe (``SETU_TOKEN_FD``), asked again whenever the token is
  due, and once more after a 401;
* started by hand for a quick try -- ``SETU_ACCESS_TOKEN`` in the
  environment, used as-is until it stops working.

ONE CALL, EVERY MODE. Under the proxy the client's base address is
Setu's and its transport is the socket; in the other modes it is the
site's, with a token attached. A connector written against
``setu.http()`` runs unchanged under each, which is the whole reason the
call exists instead of each connector reading tokens itself. So a
connector asks for PATHS (``/gmail/v1/users/me/labels``), never whole
addresses: the proxy refuses to guess which site a full URL meant.

THE BASE ADDRESS IS GIVEN, NOT HARD-CODED. ``SETU_API_BASE`` names the
host a connector talks to; its manifest supplies the real one. That is
also how tests point a connector at a stub: the same seam, not a
testing flag.
"""

from __future__ import annotations

import json
import os
import socket
import threading
import time
from collections.abc import Generator
from dataclasses import dataclass

import httpx

from setu.helper import (
    ENV_ACCESS_TOKEN,
    ENV_API_BASE,
    ENV_FD,
    ENV_LEVEL,
    ENV_PROXY,
    ENV_PROXY_KEY,
    ENV_SCOPES,
)
from setu.proxy import GRANT_PATH, KEY_HEADER

#: The base address a proxied client is given; the socket is the route.
PROXY_BASE = "http://setu"

#: Ask for a new token this long before the old one would expire.
SKEW = 60


class NoToken(Exception):
    """The connector was started with no way to get a token."""


@dataclass(slots=True)
class Granted:
    access_token: str
    expires_at: float
    scopes: frozenset[str]
    account: str = ""
    email: str = ""
    level: str = ""


class PipeSource:
    """Tokens from ``setu run``, over the inherited descriptor."""

    def __init__(self, fd: int) -> None:
        self._sock = socket.socket(fileno=fd)
        self._stream = self._sock.makefile("rwb")
        self._lock = threading.Lock()
        self._cached: Granted | None = None

    def get(self, *, force: bool = False) -> Granted:
        with self._lock:
            cached = self._cached
            if cached is not None and not force and time.time() < cached.expires_at - SKEW:
                return cached
            self._stream.write(json.dumps({"op": "token", "force": force}).encode() + b"\n")
            self._stream.flush()
            line = self._stream.readline()
            if not line:
                raise NoToken("setu closed the token pipe")
            reply = json.loads(line)
            if "error" in reply:
                raise NoToken(reply["error"])
            self._cached = Granted(access_token=reply["access_token"],
                                   expires_at=float(reply["expires_at"]),
                                   scopes=frozenset(reply.get("scopes") or ()),
                                   account=reply.get("account", ""),
                                   email=reply.get("email", ""),
                                   level=reply.get("level", ""))
            return self._cached


class EnvSource:
    """A token pasted into the environment: no refresh, no expiry known."""

    def __init__(self, token: str, scopes: str = "", level: str = "") -> None:
        self._granted = Granted(access_token=token, expires_at=float("inf"),
                                scopes=frozenset(scopes.split()), level=level)

    def get(self, *, force: bool = False) -> Granted:
        if force:
            raise NoToken(f"the token in {ENV_ACCESS_TOKEN} was refused and cannot be "
                          "refreshed; start this connector with `setu run` instead")
        return self._granted


class ProxySource:
    """No token: what the connection holds, asked of Setu over the socket.
    ``access_token`` is always empty -- there is nothing to hand over."""

    def __init__(self, path: str, key: str) -> None:
        self.path, self.key = path, key
        self._granted: Granted | None = None

    def client(self, timeout: float = 30.0) -> httpx.Client:
        return httpx.Client(base_url=PROXY_BASE, transport=httpx.HTTPTransport(uds=self.path),
                            headers={KEY_HEADER: self.key}, timeout=timeout)

    def get(self, *, force: bool = False) -> Granted:
        if self._granted is None or force:
            with self.client() as http:
                try:
                    response = http.get(GRANT_PATH)
                except httpx.HTTPError as exc:
                    raise NoToken(f"setu is not answering on {self.path}: {exc}") from None
            if response.status_code != 200:
                raise NoToken(response.json().get("error", f"HTTP {response.status_code}"))
            reply = response.json()
            self._granted = Granted(access_token="", expires_at=float("inf"),
                                    scopes=frozenset(reply.get("scopes") or ()),
                                    account=reply.get("account", ""),
                                    email=reply.get("email", ""),
                                    level=reply.get("level", ""))
        return self._granted


_source_lock = threading.Lock()
_source: PipeSource | EnvSource | ProxySource | None = None


def source() -> PipeSource | EnvSource | ProxySource:
    """The process's one token source, chosen from how it was started."""
    global _source
    with _source_lock:
        if _source is None:
            fd = os.environ.get(ENV_FD)
            token = os.environ.get(ENV_ACCESS_TOKEN)
            proxy = os.environ.get(ENV_PROXY)
            if proxy:
                _source = ProxySource(proxy, os.environ.get(ENV_PROXY_KEY, ""))
            elif fd:
                _source = PipeSource(int(fd))
            elif token:
                _source = EnvSource(token, os.environ.get(ENV_SCOPES, ""),
                                    os.environ.get(ENV_LEVEL, ""))
            else:
                raise NoToken(f"no {ENV_FD} and no {ENV_ACCESS_TOKEN}: start this "
                              "connector with `setu run <connector>:<account>`")
        return _source


class SetuAuth(httpx.Auth):
    """Signs each request; on a 401, asks once for a fresh token and retries."""

    def __init__(self, tokens: PipeSource | EnvSource | ProxySource) -> None:
        self.tokens = tokens

    def auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response]:
        request.headers["Authorization"] = f"Bearer {self.tokens.get().access_token}"
        response = yield request
        if response.status_code == 401:
            request.headers["Authorization"] = (
                f"Bearer {self.tokens.get(force=True).access_token}")
            yield request


def http(default_base: str = "", *,
         tokens: PipeSource | EnvSource | ProxySource | None = None,
         transport: httpx.BaseTransport | None = None, timeout: float = 30.0) -> httpx.Client:
    """An ``httpx.Client`` that is already signed in."""
    tokens = tokens or source()
    if isinstance(tokens, ProxySource) and transport is None:
        return tokens.client(timeout)
    base = os.environ.get(ENV_API_BASE) or default_base
    return httpx.Client(base_url=base, auth=SetuAuth(tokens),
                        transport=transport, timeout=timeout)


def granted_scopes() -> frozenset[str]:
    """What this connection may do -- so a connector offers only the tools
    its grant can carry out, instead of tools that fail with 403."""
    return source().get().scopes


def granted_level() -> str:
    """The level this connection was given -- for a provider with no
    scopes (Home Assistant), the only word on which tools to offer."""
    return source().get().level
