"""`setu run`: start a connector, and keep the key out of its hands.

Two modes. THE PROXY, the default: the connector holds no token at all,
runs with no network, and asks Setu to make each request for it (see
proxy.py and sandbox.py). THE CALLBACK, below, is the exception a
manifest asks for with ``token_mode = "callback"``, for an API that
cannot go through Setu -- or that ``setu run --callback`` asks for
when trying things. The rest of this note is the callback.

A connector is a program somebody else may have written, and it needs a
token to do its job. The question is how much of the key it gets to
hold. Here: an ACCESS token for its own connection, fresh on request --
never the refresh token, never another connection's anything.

    harness ──stdio (MCP)──▶ setu-gmail
                                │  {"op": "token"}          one private pipe,
                                ▼                           inherited as a fd
                         setu run gmail:personal ──▶ vault (refresh token)

THE PIPE IS THE SCOPE. ``setu run gmail:personal`` opens a socket pair,
hands one end to the connector as a file descriptor, and answers on the
other end for ``gmail:personal`` alone. A request cannot name another
connection -- there is no field for it -- so a connector can only ever
learn the thing it was started for. Nothing is listening anywhere else:
no port, no path another process could open.

STDIO PASSES STRAIGHT THROUGH. The connector inherits this process's
stdin and stdout, so the MCP conversation never touches Setu; Setu is a
parent that waits, forwards Ctrl-C, and exits with the child's code.

ONE LINE OF JSON EACH WAY:

    → {"op": "token"}                      (or {"op": "token", "force": true}
    ← {"access_token": "...", "expires_at": 1790000000.0,   after a 401)
       "scopes": [...], "account": "personal", "email": "...",
       "level": "read"}
    ← {"error": "why not, in words"}

What a connector does with the token it gets is not enforced here:
this mode trusts the connector with an access token for its lifetime
(about an hour at Google). In the proxy mode the connector's code is
the same -- it only ever calls ``setu.http()`` -- and holds nothing.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import threading
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import httpx

from setu import connections, sandbox, seal
from setu.manifest import Manifest
from setu.proxy import Proxy, log_path
from setu.vault import Vault, default_home

ENV_FD = "SETU_TOKEN_FD"
ENV_CONNECTION = "SETU_CONNECTION"
ENV_API_BASE = "SETU_API_BASE"
#: The fallback for a connector run by hand, with no helper: a token in
#: the environment. Short-lived and never refreshed -- for trying things.
ENV_ACCESS_TOKEN = "SETU_ACCESS_TOKEN"
ENV_SCOPES = "SETU_SCOPES"
ENV_LEVEL = "SETU_LEVEL"
#: The proxy mode's two: the socket Setu listens on, and this run's key.
ENV_PROXY = "SETU_PROXY"
ENV_PROXY_KEY = "SETU_PROXY_KEY"


def answer(request: dict[str, Any], ref: str, *, vault: Vault,
           http: httpx.Client) -> dict[str, Any]:
    if request.get("op") != "token":
        return {"error": f"unknown op {request.get('op')!r}; the only one is 'token'"}
    try:
        got = connections.token(ref, vault=vault, http=http, force=bool(request.get("force")))
    except connections.ConnectionFailed as exc:
        return {"error": str(exc)}
    return {"access_token": got.access_token, "expires_at": got.expires_at,
            "scopes": list(got.scopes), "account": got.account, "email": got.email,
            "level": got.level}


def serve(sock: socket.socket, ref: str, *, vault: Vault, http: httpx.Client) -> None:
    """Answer requests on ``sock`` until the connector closes its end."""
    with sock, sock.makefile("rwb") as stream:
        for line in stream:
            try:
                request = json.loads(line)
            except ValueError:
                reply: dict[str, Any] = {"error": "not JSON"}
            else:
                reply = answer(request, ref, vault=vault, http=http)
            stream.write(json.dumps(reply).encode("utf-8") + b"\n")
            stream.flush()


def resolve(command: Sequence[str]) -> list[str]:
    """The connector's program: on PATH, or installed beside this Python.

    A harness starts ``setu`` by its full path and with its own PATH, which
    need not include the environment Setu was installed into; the
    connector installed alongside Setu is found there all the same."""
    argv = list(command)
    if argv and shutil.which(argv[0]) is None:
        beside = Path(sys.executable).parent / argv[0]
        if beside.exists():
            argv[0] = str(beside)
    return argv


def _child(argv: list[str], env: dict[str, str], pass_fds: tuple[int, ...] = ()) -> int:
    """Start the connector and wait for it, forwarding Ctrl-C."""
    try:
        child = subprocess.Popen(argv, env=env, pass_fds=pass_fds)
    except FileNotFoundError:
        raise connections.ConnectionFailed(
            f"cannot start {argv[0]!r}: not installed on PATH") from None

    def forward(signum: int, _frame: Any) -> None:
        if child.poll() is None:
            child.send_signal(signum)

    previous = {sig: signal.signal(sig, forward) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        return child.wait()
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def run_proxied(ref: str, manifest: Manifest, *, vault: Vault, http: httpx.Client,
                api_base: str = "", env: dict[str, str] | None = None,
                confine: bool | None = None) -> int:
    """Start ``manifest``'s connector with no token and no network: its
    requests come to a socket, and Setu makes them. Return its exit code."""
    child_env = dict(os.environ if env is None else env)
    # the upstream is Setu's to know; a stub's address in the environment
    # (as tests give) is where Setu sends, not where the connector does
    base = child_env.pop(ENV_API_BASE, "") or api_base
    for name in (ENV_ACCESS_TOKEN, ENV_FD, ENV_SCOPES, ENV_LEVEL, seal.ENV_KEY):
        child_env.pop(name, None)
    argv = resolve(manifest.command)
    if not argv or (shutil.which(argv[0]) is None and not Path(argv[0]).exists()):
        raise connections.ConnectionFailed(
            f"cannot start {manifest.command[0]!r}: not installed on PATH")
    home = getattr(vault, "home", None) or default_home()
    with Proxy(ref, manifest, vault=vault, http=http, base=base,
               log=log_path(ref, home)) as proxy:
        child_env[ENV_PROXY] = str(proxy.socket)
        child_env[ENV_PROXY_KEY] = proxy.key
        child_env[ENV_CONNECTION] = ref
        if confine is None:
            confine = sandbox.available()
        if confine:
            argv = [shutil.which(argv[0]) or argv[0], *argv[1:]]
            argv = sandbox.wrap(argv, keep=[proxy.folder], hide=[home])
        return _child(argv, child_env)


def run(ref: str, command: Sequence[str], *, vault: Vault, http: httpx.Client,
        api_base: str = "", env: dict[str, str] | None = None) -> int:
    """Start ``command`` with a token pipe for ``ref`` (the callback mode);
    return its exit code."""
    ours, theirs = socket.socketpair()
    child_env = dict(os.environ if env is None else env)
    child_env[ENV_FD] = str(theirs.fileno())
    child_env[ENV_CONNECTION] = ref
    if api_base and ENV_API_BASE not in child_env:
        child_env[ENV_API_BASE] = api_base
    # Never let a token from the parent's environment ride along: the
    # child gets its key from the pipe or not at all.
    child_env.pop(ENV_ACCESS_TOKEN, None)
    child_env.pop(seal.ENV_KEY, None)     # a locked folder's key stays with Setu
    server = threading.Thread(target=serve, args=(ours, ref),
                              kwargs={"vault": vault, "http": http}, daemon=True)
    server.start()
    try:
        return _child(resolve(command), child_env, (theirs.fileno(),))
    finally:
        theirs.close()   # the child holds its own copy, or never started
