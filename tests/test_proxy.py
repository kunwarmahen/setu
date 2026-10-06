"""The proxy: the connector holds no key, and Setu makes its requests.

The bias is A CONNECTOR THAT WANTS MORE THAN IT WAS GIVEN. So these
tests play the connector as a hostile one would: asking for a send on
a read-only connection, spelling a lock as ``%6Cock``, walking up with
``..``, sending its own Authorization header, guessing the key, and --
in a real sandbox -- looking for the token in its environment, opening
the vault file, and dialling the site directly instead of through Setu.
Each must come away with nothing.
"""

from __future__ import annotations

import json
import os
import sys
import time

import httpx
import pytest
from conftest import REFRESH, TOKEN, FakeGmail
from setu import helper, proxy, sandbox
from setu.client import ProxySource
from setu.manifest import find, parse
from setu.proxy import Proxy, Refused, Rules
from setu.vault import FileVault

READ = "https://www.googleapis.com/auth/gmail.readonly"


def seed(vault: FileVault, level: str = "read", scopes: tuple[str, ...] = (READ,)) -> None:
    vault.put("gmail:personal", {
        "connector": "gmail", "account": "personal", "email": "me@example.com",
        "level": level, "asked_level": level, "scopes": list(scopes),
        "created": "2026-09-28T00:00:00Z", "last_used": None,
        "secret": {"client_id": "cid", "client_secret": "shh",
                   "token_url": "https://oauth2.googleapis.com/token",
                   "refresh_token": REFRESH, "access_token": TOKEN,
                   "expires_at": time.time() + 3600}})


def refused(rules: Rules, method: str, path: str, body: bytes = b"") -> bool:
    try:
        rules.check(method, path, body)
    except Refused:
        return True
    return False


class TestTheRules:
    def test_each_gmail_level_reaches_its_own_requests_and_no_further(self):
        gmail = find("gmail")
        read, draft, send = (Rules.of(gmail, lvl) for lvl in ("read", "draft", "send"))
        assert not refused(read, "GET", "/gmail/v1/users/me/threads?q=invoice")
        assert refused(read, "POST", "/gmail/v1/users/me/drafts")
        assert not refused(draft, "POST", "/gmail/v1/users/me/drafts")
        assert refused(draft, "POST", "/gmail/v1/users/me/messages/send")
        assert not refused(send, "POST", "/gmail/v1/users/me/messages/send")
        # nothing at any level deletes, or reaches another user's mailbox
        assert refused(send, "DELETE", "/gmail/v1/users/me/messages/m1")
        assert refused(send, "GET", "/gmail/v1/users/someone@else.test/threads")

    def test_an_unknown_level_is_held_to_the_least_one(self):
        rules = Rules.of(find("gmail"), "everything")
        assert refused(rules, "POST", "/gmail/v1/users/me/drafts")

    def test_home_assistant_control_may_switch_but_never_unlock(self):
        rules = Rules.of(find("homeassistant"), "control")
        assert not refused(rules, "POST", "/api/services/light/turn_on")
        assert refused(rules, "POST", "/api/services/lock/unlock")
        assert refused(rules, "POST", "/api/services/%6Cock/unlock")    # spelt sideways
        assert refused(rules, "POST", "/api/services/Lock/unlock")
        assert not refused(Rules.of(find("homeassistant"), "full"), "POST",
                           "/api/services/lock/unlock")

    def test_home_assistant_see_only_changes_nothing(self):
        rules = Rules.of(find("homeassistant"), "read")
        assert not refused(rules, "GET", "/api/states")
        assert not refused(rules, "POST", "/api/template")
        assert refused(rules, "POST", "/api/services/light/turn_on")

    def test_a_path_that_walks_is_refused(self):
        rules = Rules.of(find("gmail"), "send")
        for path in ("/gmail/v1/users/me/../../other", "/gmail/v1/users/me/%2e%2e/x",
                     "//evil.test/gmail/v1/users/me/x", "gmail/v1/users/me/x"):
            assert refused(rules, "GET", path), path

    def test_the_sites_own_mcp_server_reads_only_at_the_first_level(self):
        bridge = find("homeassistant-mcp")
        see = Rules.of(bridge, "read")

        def call(name: str) -> bytes:
            return json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                               "params": {"name": name}}).encode()

        assert not refused(see, "POST", "/api/mcp", call("GetLiveContext"))
        assert not refused(see, "POST", "/api/mcp", b'{"method": "tools/list", "id": 2}')
        assert refused(see, "POST", "/api/mcp", call("HassTurnOn"))
        assert refused(see, "POST", "/api/mcp", b"[" + call("HassUnlock") + b"]")
        assert not refused(Rules.of(bridge, "control"), "POST", "/api/mcp", call("HassTurnOn"))

    def test_a_manifest_without_rules_may_ask_anything_of_its_host(self):
        m = parse({"id": "ex", "name": "Ex", "road": "api", "auth": "homeassistant",
                   "command": ["ex"], "levels": {"read": {}}})
        assert not refused(Rules.of(m, "read"), "DELETE", "/anything")

    def test_a_rule_that_is_not_a_method_and_path_is_an_error(self):
        from setu.manifest import ManifestError
        with pytest.raises(ManifestError):
            parse({"id": "ex", "name": "Ex", "road": "api", "auth": "homeassistant",
                   "command": ["ex"], "levels": {"read": {}},
                   "requests": {"read": {"allow": ["FETCH everything"]}}})


@pytest.fixture
def upstream():
    fake = FakeGmail()
    base, server = fake.serve()
    yield fake, base
    server.shutdown()


class TestTheForwarder:
    def open(self, home, base, level="read"):
        vault = FileVault()
        seed(vault, level)
        return Proxy("gmail:personal", find("gmail"), vault=vault, http=httpx.Client(),
                     base=base, log=proxy.log_path("gmail:personal", home))

    def test_a_request_arrives_signed_and_the_connector_never_saw_the_token(self, home,
                                                                            upstream):
        fake, base = upstream
        with self.open(home, base) as p, ProxySource(str(p.socket), p.key).client() as c:
            answer = c.get("/gmail/v1/users/me/threads", params={"q": "invoice"},
                           headers={"Authorization": "Bearer the-connectors-own"})
            assert answer.status_code == 200 and answer.json()["threads"]
            grant = ProxySource(str(p.socket), p.key).get()
        assert fake.calls == ["GET /gmail/v1/users/me/threads"]
        assert grant.scopes == {READ} and grant.access_token == ""
        assert TOKEN not in json.dumps(answer.json())

    def test_a_refused_request_never_leaves_the_computer(self, home, upstream):
        fake, base = upstream
        with self.open(home, base) as p, ProxySource(str(p.socket), p.key).client() as c:
            answer = c.post("/gmail/v1/users/me/messages/send", json={"raw": "x"})
        assert answer.status_code == 403 and "Setu refused" in answer.json()["error"]
        assert fake.calls == []

    def test_the_wrong_key_gets_nothing(self, home, upstream):
        fake, base = upstream
        with self.open(home, base) as p, ProxySource(str(p.socket), "guess").client() as c:
            assert c.get("/gmail/v1/users/me/threads").status_code == 403
            assert c.get(proxy.GRANT_PATH).status_code == 403
        assert fake.calls == []

    def test_the_log_keeps_what_was_asked_but_never_the_query(self, home, upstream):
        _fake, base = upstream
        with self.open(home, base) as p, ProxySource(str(p.socket), p.key).client() as c:
            c.get("/gmail/v1/users/me/threads", params={"q": "my secret search"})
            c.post("/gmail/v1/users/me/drafts", json={})
        log = proxy.log_path("gmail:personal", home).read_text()
        assert "GET /gmail/v1/users/me/threads 200" in log
        assert "POST /gmail/v1/users/me/drafts refused" in log
        assert "secret" not in log

    def test_the_socket_is_gone_when_the_run_ends(self, home, upstream):
        _fake, base = upstream
        with self.open(home, base) as p:
            folder = p.folder
            assert oct(folder.stat().st_mode & 0o777) == "0o700"
        assert not folder.exists()


SPY = r"""
import json, os, socket, sys
import httpx
import setu
out = {"env": dict(os.environ)}
try:
    out["threads"] = setu.http().get("/gmail/v1/users/me/threads").status_code
    out["send"] = setu.http().post("/gmail/v1/users/me/messages/send", json={}).status_code
    out["scopes"] = sorted(setu.granted_scopes())
except Exception as exc:
    out["error"] = repr(exc)
try:
    out["vault"] = open(sys.argv[2]).read()
except OSError as exc:
    out["vault"] = "unreadable"
host, port = sys.argv[3].rsplit(":", 1)
try:
    socket.create_connection((host.split("//")[1], int(port)), timeout=2)
    out["direct"] = "connected"
except OSError:
    out["direct"] = "no route"
print(json.dumps(out))
"""


def run_spy(home, base, capfd, confine):
    vault = FileVault()
    seed(vault)
    manifest = find("gmail")
    from dataclasses import replace
    spy = replace(manifest, command=(sys.executable, "-c", SPY, "x",
                                     str(vault.path), base))
    env = dict(os.environ, SETU_API_BASE=base,
               SETU_ACCESS_TOKEN="a-token-the-parent-happened-to-have")
    with httpx.Client() as http:
        code = helper.run_proxied("gmail:personal", spy, vault=vault, http=http, env=env,
                                  confine=confine)
    assert code == 0
    return json.loads(capfd.readouterr().out.strip().splitlines()[-1])


@pytest.mark.skipif(not sandbox.available(), reason="bubblewrap cannot sandbox here")
def test_in_the_sandbox_the_connector_has_no_key_no_vault_and_no_network(home, upstream,
                                                                         capfd):
    fake, base = upstream
    seen = run_spy(home, base, capfd, confine=True)
    assert seen["threads"] == 200 and seen["send"] == 403, seen
    assert seen["scopes"] == [READ]
    everything = json.dumps(seen)
    assert TOKEN not in everything and REFRESH not in everything
    assert "a-token-the-parent-happened-to-have" not in everything
    assert seen["vault"] == "unreadable"
    assert seen["direct"] == "no route"
    assert fake.calls == ["GET /gmail/v1/users/me/threads"]


def test_without_the_sandbox_the_key_still_stays_out(home, upstream, capfd):
    _fake, base = upstream
    seen = run_spy(home, base, capfd, confine=False)
    assert seen["threads"] == 200 and seen["send"] == 403
    everything = json.dumps(seen["env"])
    assert TOKEN not in everything and "SETU_TOKEN_FD" not in seen["env"]


def test_the_sandbox_hides_the_home_folder_but_keeps_this_python(tmp_path):
    home = str(tmp_path.resolve())
    argv = sandbox.wrap([sys.executable, "-c", "pass"], keep=[tmp_path / "sock"],
                        hide=[tmp_path / "setu"], home=tmp_path)
    pairs = list(zip(argv, argv[1:], strict=False))
    assert argv[:3] == ["bwrap", "--ro-bind", "/"] and "--unshare-net" in argv
    # the home is emptied, Setu's folder too, and only then the socket bound in
    assert pairs.index(("--tmpfs", home)) < pairs.index(("--tmpfs", f"{home}/setu")) \
        < pairs.index(("--bind", f"{home}/sock"))
    assert argv[-3:] == [sys.executable, "-c", "pass"]


def test_the_sandbox_is_tried_with_the_wall_every_connector_gets(monkeypatch):
    """A network-only try passes in a rootless container whose /proc is
    masked, where the real wrap cannot mount a fresh /proc: then the card
    would claim a wall and every connector would fail to start."""
    tried = []

    def run(argv, **kw):
        tried.append(argv)
        return type("Done", (), {"returncode": 0})()

    monkeypatch.delenv(sandbox.ENV_SANDBOX, raising=False)
    monkeypatch.setattr(sandbox.shutil, "which", lambda name: "/usr/bin/bwrap")
    monkeypatch.setattr(sandbox.subprocess, "run", run)
    sandbox.available.cache_clear()
    try:
        assert sandbox.available()
    finally:
        sandbox.available.cache_clear()
    real = sandbox.wrap(["true"], keep=[])
    for flag in ("--proc", "--dev", "--unshare-net", "--unshare-pid", "--unshare-ipc"):
        assert flag in tried[0] and flag in real
