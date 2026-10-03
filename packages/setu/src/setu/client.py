"""The connector's side: ``setu.http()``, and nothing to know about keys.

A connector author writes::

    http = setu.http()
    http.get("/gmail/v1/users/me/labels")

and gets an ``httpx.Client`` whose requests are already signed. Where
the token came from is decided by whoever started the process, not by
the connector:

* started by ``setu run`` -- a private pipe (``SETU_TOKEN_FD``), asked
  again whenever the token is due, and once more after a 401;
* started by hand for a quick try -- ``SETU_ACCESS_TOKEN`` in the
  environment, used as-is until it stops working.

ONE CALL, EVERY MODE. The stricter mode, where the connector holds no
token at all and every request goes through Setu, arrives as a
different base address and transport behind the same call. A connector
written against ``setu.http()`` today runs unchanged under it, which is
the whole reason the call exists instead of each connector reading
tokens itself.

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

from setu.helper import ENV_ACCESS_TOKEN, ENV_API_BASE, ENV_FD, ENV_LEVEL, ENV_SCOPES

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


_source_lock = threading.Lock()
_source: PipeSource | EnvSource | None = None


def source() -> PipeSource | EnvSource:
    """The process's one token source, chosen from how it was started."""
    global _source
    with _source_lock:
        if _source is None:
            fd = os.environ.get(ENV_FD)
            token = os.environ.get(ENV_ACCESS_TOKEN)
            if fd:
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

    def __init__(self, tokens: PipeSource | EnvSource) -> None:
        self.tokens = tokens

    def auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response]:
        request.headers["Authorization"] = f"Bearer {self.tokens.get().access_token}"
        response = yield request
        if response.status_code == 401:
            request.headers["Authorization"] = (
                f"Bearer {self.tokens.get(force=True).access_token}")
            yield request


def http(default_base: str = "", *, tokens: PipeSource | EnvSource | None = None,
         transport: httpx.BaseTransport | None = None, timeout: float = 30.0) -> httpx.Client:
    """An ``httpx.Client`` that is already signed in."""
    base = os.environ.get(ENV_API_BASE) or default_base
    return httpx.Client(base_url=base, auth=SetuAuth(tokens or source()),
                        transport=transport, timeout=timeout)


def granted_scopes() -> frozenset[str]:
    """What this connection may do -- so a connector offers only the tools
    its grant can carry out, instead of tools that fail with 403."""
    return source().get().scopes


def granted_level() -> str:
    """The level this connection was given -- for a provider with no
    scopes (Home Assistant), the only word on which tools to offer."""
    return source().get().level
