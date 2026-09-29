"""`setu run`, as a harness meets it: a process that speaks MCP.

The bias is THE KEY LEAKING SIDEWAYS. What a connector may hold is an
access token for its own connection, handed over on request. So these
tests start real processes and look at what a child can actually see:
its environment must carry no refresh token, no client secret, no
token of the parent's; the pipe must answer for one connection only.

The last test is the whole road in one: a harness-shaped client starts
``setu run gmail:personal``, which starts ``setu-gmail``, which asks the
pipe for a token and reads a stub Gmail over real HTTP -- MCP on stdio
the whole way, with Setu never touching the conversation.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time

import httpx
from conftest import REFRESH, TOKEN, FakeGmail
from setu import helper
from setu.vault import FileVault

READ = "https://www.googleapis.com/auth/gmail.readonly"


def seed(vault: FileVault, scopes: list[str], token: str = TOKEN) -> None:
    vault.put("gmail:personal", {
        "connector": "gmail", "account": "personal", "email": "me@example.com",
        "level": "read", "asked_level": "read", "scopes": scopes,
        "created": "2026-09-28T00:00:00Z", "last_used": None,
        "secret": {"client_id": "cid", "client_secret": "shh",
                   "token_url": "https://oauth2.googleapis.com/token",
                   "refresh_token": REFRESH, "access_token": token,
                   "expires_at": time.time() + 3600}})


SPY = r"""
import json, os, socket, sys
sock = socket.socket(fileno=int(os.environ["SETU_TOKEN_FD"]))
stream = sock.makefile("rwb")
stream.write(b'{"op": "token"}\n'); stream.flush()
reply = json.loads(stream.readline())
stream.write(b'{"op": "token", "connection": "gmail:work"}\n'); stream.flush()
other = json.loads(stream.readline())
with open(sys.argv[1], "w") as out:
    json.dump({"reply": reply, "other": other, "env": dict(os.environ)}, out)
"""


class TestWhatTheChildCanSee:
    def run_spy(self, tmp_path, monkeypatch):
        vault = FileVault()
        seed(vault, [READ])
        monkeypatch.setenv("SETU_ACCESS_TOKEN", "a-token-the-parent-happened-to-have")
        out = tmp_path / "spy.json"
        with httpx.Client() as http:
            code = helper.run("gmail:personal", [sys.executable, "-c", SPY, str(out)],
                              vault=vault, http=http)
        assert code == 0
        return json.loads(out.read_text())

    def test_the_pipe_hands_over_an_access_token_and_its_scopes(self, home, tmp_path,
                                                                  monkeypatch):
        seen = self.run_spy(tmp_path, monkeypatch)
        assert seen["reply"]["access_token"] == TOKEN
        assert seen["reply"]["scopes"] == [READ]
        assert seen["reply"]["email"] == "me@example.com"

    def test_the_refresh_token_and_secret_never_reach_the_child(self, home, tmp_path,
                                                                monkeypatch):
        seen = self.run_spy(tmp_path, monkeypatch)
        everything = json.dumps(seen)
        assert REFRESH not in everything and "shh" not in everything

    def test_a_token_in_the_parents_environment_does_not_ride_along(self, home, tmp_path,
                                                                    monkeypatch):
        seen = self.run_spy(tmp_path, monkeypatch)
        assert "SETU_ACCESS_TOKEN" not in seen["env"]

    def test_the_pipe_answers_for_its_own_connection_whatever_is_asked(self, home, tmp_path,
                                                                        monkeypatch):
        """There is no field to name another connection; a request that
        tries gets the same connection's token, never gmail:work's."""
        seen = self.run_spy(tmp_path, monkeypatch)
        assert seen["other"]["account"] == "personal"


def test_a_connector_beside_this_python_is_found_off_path(monkeypatch):
    """A harness's PATH need not include Setu's environment."""
    monkeypatch.setenv("PATH", "/nonexistent")
    resolved = helper.resolve(["setu-gmail"])
    assert resolved[0].endswith("/setu-gmail") and os.path.exists(resolved[0])


class MCP:
    """A harness-shaped MCP client over a child's stdio."""

    def __init__(self, argv: list[str], env: dict[str, str]) -> None:
        self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, env=env, text=True)
        self.ids = 0

    def request(self, method: str, params: dict | None = None) -> dict:
        self.ids += 1
        self._send({"jsonrpc": "2.0", "id": self.ids, "method": method, "params": params or {}})
        while True:
            line = self.proc.stdout.readline()
            if not line:
                raise AssertionError(f"server exited: {self.proc.stderr.read()}")
            message = json.loads(line)
            if message.get("id") == self.ids:
                return message

    def notify(self, method: str) -> None:
        self._send({"jsonrpc": "2.0", "method": method})

    def _send(self, message: dict) -> None:
        self.proc.stdin.write(json.dumps(message) + "\n")
        self.proc.stdin.flush()

    def close(self) -> int:
        self.proc.stdin.close()
        return self.proc.wait(timeout=10)


def test_a_harness_reads_the_mailbox_through_setu_run(home):
    fake = FakeGmail()
    base, server = fake.serve()
    try:
        seed(FileVault(), [READ])
        env = dict(os.environ, SETU_API_BASE=base)
        client = MCP([sys.executable, "-m", "setu.cli", "run", "gmail:personal"], env)
        try:
            init = client.request("initialize", {
                "protocolVersion": "2025-06-18", "capabilities": {},
                "clientInfo": {"name": "harness", "version": "0"}})
            assert init["result"]["serverInfo"]["name"] == "setu-gmail"
            client.notify("notifications/initialized")
            names = {t["name"] for t in client.request("tools/list")["result"]["tools"]}
            assert "search_threads" in names and "create_draft" not in names
            answer = client.request("tools/call", {"name": "search_threads",
                                                   "arguments": {"query": "invoice"}})
            text = answer["result"]["content"][0]["text"]
            assert "thread t1" in text and "Invoice 1042" in text
        finally:
            assert client.close() == 0
        assert "GET /gmail/v1/users/me/threads" in fake.calls
    finally:
        server.shutdown()
