"""`setu run`: start a connector, and answer its one question.

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
       "scopes": [...], "account": "personal", "email": "..."}
    ← {"error": "why not, in words"}

What a connector does with the token it gets is not enforced here:
this mode trusts the connector with an access token for its lifetime
(about an hour at Google). The stricter mode, where the connector never
holds a token at all, is a proxy on the same pipe -- the connector's
code does not change, because it only ever calls ``setu.http()``.
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

from setu import connections
from setu.vault import Vault

ENV_FD = "SETU_TOKEN_FD"
ENV_CONNECTION = "SETU_CONNECTION"
ENV_API_BASE = "SETU_API_BASE"
#: The fallback for a connector run by hand, with no helper: a token in
#: the environment. Short-lived and never refreshed -- for trying things.
ENV_ACCESS_TOKEN = "SETU_ACCESS_TOKEN"
ENV_SCOPES = "SETU_SCOPES"


def answer(request: dict[str, Any], ref: str, *, vault: Vault,
           http: httpx.Client) -> dict[str, Any]:
    if request.get("op") != "token":
        return {"error": f"unknown op {request.get('op')!r}; the only one is 'token'"}
    try:
        got = connections.token(ref, vault=vault, http=http, force=bool(request.get("force")))
    except connections.ConnectionFailed as exc:
        return {"error": str(exc)}
    return {"access_token": got.access_token, "expires_at": got.expires_at,
            "scopes": list(got.scopes), "account": got.account, "email": got.email}


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


def run(ref: str, command: Sequence[str], *, vault: Vault, http: httpx.Client,
        api_base: str = "", env: dict[str, str] | None = None) -> int:
    """Start ``command`` with a token pipe for ``ref``; return its exit code."""
    ours, theirs = socket.socketpair()
    child_env = dict(os.environ if env is None else env)
    child_env[ENV_FD] = str(theirs.fileno())
    child_env[ENV_CONNECTION] = ref
    if api_base and ENV_API_BASE not in child_env:
        child_env[ENV_API_BASE] = api_base
    # Never let a token from the parent's environment ride along: the
    # child gets its key from the pipe or not at all.
    child_env.pop(ENV_ACCESS_TOKEN, None)
    try:
        child = subprocess.Popen(resolve(command), env=child_env,
                                 pass_fds=(theirs.fileno(),))
    except FileNotFoundError:
        ours.close()
        theirs.close()
        raise connections.ConnectionFailed(
            f"cannot start {command[0]!r}: not installed on PATH") from None
    theirs.close()   # the child holds its own copy now
    server = threading.Thread(target=serve, args=(ours, ref),
                              kwargs={"vault": vault, "http": http}, daemon=True)
    server.start()

    def forward(signum: int, _frame: Any) -> None:
        if child.poll() is None:
            child.send_signal(signum)

    previous = {sig: signal.signal(sig, forward) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        return child.wait()
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
