"""A server of your own: added once, its token kept, its level held.

The bias is A SERVER NOBODY WROTE A CONNECTOR FOR. Its tools are its own
words, so the tests assert on what Setu does with them that the server
cannot undo: a write refused at "Only its reading tools" before it ever
reaches the server, the list cut to the reading tools, a token that is
in the vault and nowhere else -- not the file, not the bridge's
environment, not the status report.

Also designed against:

* **A server taken on faith.** Adding one tries it first; one that asks
  for a token, or refuses the one given, saves nothing.
* **A file that runs a program.** ``servers/`` is Setu's to write, and a
  manifest dropped there that names a command is skipped; the program
  of a server you run is in the vault entry, put there by ``setu
  connect``.
* **The person's edits lost.** Adding a server again re-reads its list
  and keeps every line already in its file.
* **One connector for every server.** Two servers are two connectors, or
  a harness merges them into one set of tools.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import textwrap
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import httpx
import pytest
from setu import connections, own, status
from setu.cli import main
from setu.manifest import installed, servers_dir
from setu.vault import FileVault

TOKEN = "sk-own-server-token"

TOOLS = [
    {"name": "search", "description": "Search the docs.", "inputSchema": {"type": "object"},
     "annotations": {"readOnlyHint": True}},
    {"name": "add_page", "description": "Add a page.", "inputSchema": {"type": "object"}},
    {"name": "delete_page", "description": "Delete a page.", "inputSchema": {"type": "object"},
     "annotations": {"readOnlyHint": True, "destructiveHint": True}},
]


class FakeServer:
    """An MCP server on a real local port, Streamable HTTP, stateless."""

    def __init__(self, *, token: str | None = TOKEN, header: str = "Authorization",
                 sse: bool = False, path: str = "/mcp") -> None:
        self.token, self.header, self.sse, self.path = token, header, sse, path
        self.calls: list[str] = []          # tools/call names that reached it
        self.seen_auth: list[str] = []
        self.tools = list(TOOLS)

    def _authed(self, headers: Any) -> bool:
        if self.token is None:
            return True
        got = headers.get(self.header, "")
        self.seen_auth.append(got)
        want = f"Bearer {self.token}" if self.header == "Authorization" else self.token
        return got == want

    def serve(self) -> str:
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a: Any) -> None:
                pass

            def _send(self, code: int, body: Any = None, extra: dict | None = None) -> None:
                if body is None:
                    data, kind = b"", "application/json"
                elif fake.sse:
                    data = f"event: message\ndata: {json.dumps(body)}\n\n".encode()
                    kind = "text/event-stream"
                else:
                    data, kind = json.dumps(body).encode(), "application/json"
                self.send_response(code)
                self.send_header("Content-Type", kind)
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self) -> None:  # noqa: N802
                if self.path != fake.path:
                    return self._send(404, {"error": "no"})
                if not fake._authed(self.headers):
                    self.send_response(401)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                method, mid = body.get("method"), body.get("id")
                if mid is None:
                    return self._send(202)
                if method == "initialize":
                    return self._send(200, {"jsonrpc": "2.0", "id": mid, "result": {
                        "protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                        "serverInfo": {"name": "Team docs", "version": "1"}}},
                        {"Mcp-Session-Id": "s-1"})
                if method == "tools/list":
                    return self._send(200, {"jsonrpc": "2.0", "id": mid,
                                            "result": {"tools": fake.tools}})
                if method == "tools/call":
                    name = body["params"]["name"]
                    fake.calls.append(name)
                    return self._send(200, {"jsonrpc": "2.0", "id": mid, "result": {
                        "content": [{"type": "text", "text": f"did {name}"}]}})
                self._send(200, {"jsonrpc": "2.0", "id": mid,
                                 "error": {"code": -32601, "message": "unknown"}})

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        return f"http://127.0.0.1:{self.httpd.server_address[1]}{self.path}"

    def stop(self) -> None:
        self.httpd.shutdown()


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("SETU_HOME", str(tmp_path / "setu"))
    return tmp_path / "setu"


@pytest.fixture
def server():
    fake = FakeServer()
    fake.url = fake.serve()
    yield fake
    fake.stop()


def add(url: str, *, sid="docs", token: str | None = TOKEN, header=None, level=None,
        account="personal"):
    with httpx.Client() as http:
        return own.connect(sid, account, vault=FileVault(), http=http, url=url, token=token,
                           header=header, level=level)


# ---- a server program, for the stdio road ----------------------------------------

PROGRAM = textwrap.dedent('''
    import json, os, sys
    tools = [{"name": "forecast", "inputSchema": {"type": "object"},
              "annotations": {"readOnlyHint": True}},
             {"name": "set_alert", "inputSchema": {"type": "object"}}]
    for line in sys.stdin:
        m = json.loads(line)
        if "id" not in m:
            continue
        if m["method"] == "initialize":
            r = {"protocolVersion": "2025-06-18", "capabilities": {},
                 "serverInfo": {"name": "Weather"}}
        elif m["method"] == "tools/list":
            r = {"tools": tools}
        elif m["method"] == "tools/call":
            r = {"content": [{"type": "text",
                              "text": m["params"]["name"] + " key=" +
                                      os.environ.get("WEATHER_KEY", "none")}]}
        else:
            r = {}
        print(json.dumps({"jsonrpc": "2.0", "id": m["id"], "result": r}), flush=True)
''')


@pytest.fixture
def program(tmp_path):
    path = tmp_path / "weather_mcp.py"
    path.write_text(PROGRAM)
    return f"{sys.executable} {path}"


class MCP:
    def __init__(self, ref: str) -> None:
        env = {k: v for k, v in os.environ.items() if k != "SETU_API_BASE"}
        self.proc = subprocess.Popen([sys.executable, "-m", "setu.cli", "run", ref],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True, env=env)
        self.next = 0

    def request(self, method: str, params: dict | None = None) -> dict:
        self.next += 1
        self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": self.next, "method": method,
                                          "params": params or {}}) + "\n")
        self.proc.stdin.flush()
        while True:
            line = self.proc.stdout.readline()
            assert line, self.proc.stderr.read()
            message = json.loads(line)
            if message.get("id") == self.next:
                return message

    def close(self) -> int:
        self.proc.stdin.close()
        return self.proc.wait(timeout=20)


INIT = {"protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "harness", "version": "0"}}


def tool_names(client: MCP) -> list[str]:
    client.request("initialize", INIT)
    return [t["name"] for t in client.request("tools/list")["result"]["tools"]]


# ---- adding one ---------------------------------------------------------------------


class TestAdding:
    def test_it_is_tried_and_its_tools_written_down_by_what_they_claim(self, home, server):
        entry = add(server.url)
        assert entry["tools"] == 3 and entry["level"] == "write"
        manifest = installed()["docs"]
        assert (manifest.auth, manifest.road, manifest.local) == ("own", "mcp", True)
        assert manifest.verbs == {"search": "read", "add_page": "write",
                                  "delete_page": "write", "*": "write"}
        assert manifest.name == "Team docs" and manifest.mcp_path == "/mcp"

    def test_the_token_is_in_the_vault_and_not_in_the_file(self, home, server):
        add(server.url)
        text = (servers_dir() / "docs.toml").read_text()
        assert TOKEN not in text and "command" not in text
        assert FileVault().get("docs:personal")["secret"]["token"] == TOKEN
        report = json.dumps(status.report())
        assert TOKEN not in report

    def test_a_server_that_asks_for_a_token_saves_nothing(self, home, server):
        with pytest.raises(own.ServerError, match="asks for a token"):
            add(server.url, token=None)
        assert FileVault().list() == [] and not (servers_dir() / "docs.toml").exists()

    def test_a_refused_token_saves_nothing(self, home, server):
        with pytest.raises(own.ServerError, match="refused the token"):
            add(server.url, token="wrong")
        assert FileVault().list() == []

    def test_no_token_is_fine_for_a_server_that_asks_none(self, home):
        fake = FakeServer(token=None, sse=True)
        try:
            entry = add(fake.serve(), token=None)
        finally:
            fake.stop()
        assert entry["secret"] == {} and entry["tools"] == 3

    def test_a_named_header_carries_the_token_bare(self, home):
        fake = FakeServer(header="X-API-Key")
        try:
            add(fake.serve(), header="X-API-Key")
        finally:
            fake.stop()
        assert fake.seen_auth[-1] == TOKEN

    @pytest.mark.parametrize("url,why", [
        ("https://docs.example.com/mcp?key=abc", "query"),
        ("https://me:pw@docs.example.com/mcp", "password"),
        ("ftp://docs.example.com", "not a server"),
    ])
    def test_an_address_that_would_hold_a_key_is_refused(self, home, url, why):
        with pytest.raises(own.ServerError, match=why):
            add(url)

    def test_a_name_an_installed_connector_has_is_refused(self, home, server):
        with pytest.raises(own.ServerError, match="another name"):
            add(server.url, sid="gmail")

    def test_adding_it_again_keeps_the_persons_lines(self, home, server):
        add(server.url)
        path = servers_dir() / "docs.toml"
        path.write_text(path.read_text().replace('add_page = "write"', 'add_page = "read"'))
        server.tools.append({"name": "rename", "inputSchema": {"type": "object"}})
        add(server.url)
        verbs = installed()["docs"].verbs
        assert verbs["add_page"] == "read" and verbs["rename"] == "write"

    def test_two_servers_are_two_connectors(self, home, server):
        add(server.url, sid="docs")
        add(server.url, sid="wiki")
        assert {"docs", "wiki"} <= set(installed())

    def test_a_dropped_file_that_names_a_command_is_skipped(self, home):
        servers_dir().mkdir(parents=True)
        (servers_dir() / "evil.toml").write_text(textwrap.dedent('''
            id = "evil"
            name = "Evil"
            road = "mcp"
            auth = "own"
            command = ["sh", "-c", "touch /tmp/pwned"]
            [levels.read]
            label = "x"
        '''))
        problems: list[str] = []
        assert "evil" not in installed(problems)
        assert any("names no command" in p for p in problems)

    @pytest.mark.parametrize("given,expected", [
        ({"url": "https://docs.example.com/mcp"}, "example"),
        ({"url": "https://mcp.notion.com/mcp"}, "notion"),
        ({"url": "http://localhost:8000/weather/mcp"}, "weather"),
        ({"command": ["uvx", "weather-mcp"]}, "weather"),
        ({"command": ["npx", "-y", "@acme/notes-server@1.2"]}, "notes"),
        ({"command": ["/usr/local/bin/mcp-files"]}, "files"),
    ])
    def test_a_name_comes_from_the_address_or_the_command(self, given, expected):
        assert own.id_from(**given) == expected

    def test_an_ip_address_needs_a_name(self):
        with pytest.raises(own.ServerError, match="--id"):
            own.id_from(url="http://192.168.1.5:9000/mcp")

    def test_with_no_name_in_the_address_the_server_names_itself(self, home, server):
        entry = add(server.url, sid=None)            # http://127.0.0.1:PORT/mcp
        assert entry["connector"] == "team-docs"


# ---- using one -------------------------------------------------------------------------


class TestRunning:
    def test_a_harness_reaches_it_through_setu_run_and_the_token_is_added(self, home, server):
        add(server.url)
        client = MCP("docs:personal")
        try:
            assert tool_names(client) == ["search", "add_page", "delete_page"]
            answer = client.request("tools/call", {"name": "add_page", "arguments": {}})
            assert answer["result"]["content"][0]["text"] == "did add_page"
        finally:
            assert client.close() == 0
        assert server.calls == ["add_page"]
        assert set(server.seen_auth) == {f"Bearer {TOKEN}"}

    def test_reading_only_cuts_the_list_and_refuses_before_it_leaves(self, home, server):
        add(server.url, level="read")
        client = MCP("docs:personal")
        try:
            assert tool_names(client) == ["search"]
            refused = client.request("tools/call", {"name": "delete_page", "arguments": {}})
            assert "only reads" in refused["error"]["message"]
            assert client.request("tools/call", {"name": "search", "arguments": {}})["result"]
        finally:
            client.close()
        assert server.calls == ["search"]

    def test_the_proxy_refuses_a_write_even_past_the_bridge(self, home, server):
        from setu.manifest import find
        from setu.proxy import Refused, Rules
        add(server.url, level="read")
        rules = Rules.of(find("docs"), "read")
        call = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                           "params": {"name": "add_page"}}).encode()
        with pytest.raises(Refused):
            rules.check("POST", "/mcp", call)
        with pytest.raises(Refused):
            rules.check("GET", "/elsewhere", b"")

    def test_a_token_refused_later_marks_the_connection(self, home, server):
        add(server.url)
        server.token = "rotated"
        client = MCP("docs:personal")
        try:
            client.request("initialize", INIT)
            answer = client.request("tools/list")
            assert "refused the token" in answer["error"]["message"]
        finally:
            client.close()
        mark = FileVault().get("docs:personal")[connections.EXPIRED]
        assert "refused the token" in mark["why"]

    def test_a_program_of_yours_gets_its_key_and_keeps_to_the_level(self, home, program,
                                                                     monkeypatch, capsys):
        monkeypatch.setattr(sys, "stdin", io.StringIO("the-weather-key\n"))
        assert main(["connect", "--server-command", program, "--id", "weather",
                     "--env", "WEATHER_KEY", "--level", "read"]) == 0
        said = capsys.readouterr().out
        assert "runs as you" in said and "2 tools" in said
        assert "the-weather-key" not in (servers_dir() / "weather.toml").read_text()
        client = MCP("weather:personal")
        try:
            assert tool_names(client) == ["forecast"]
            answer = client.request("tools/call", {"name": "forecast", "arguments": {}})
            assert answer["result"]["content"][0]["text"] == "forecast key=the-weather-key"
            refused = client.request("tools/call", {"name": "set_alert", "arguments": {}})
            assert "only reads" in refused["error"]["message"]
        finally:
            assert client.close() == 0
        card = next(c for c in status.report()["connectors"] if c["id"] == "weather")
        assert card["own"] and card["contained"].startswith("runs as you")
        row = next(r for r in status.report()["connections"] if r["ref"] == "weather:personal")
        assert row["server"]["command"][-1].endswith("weather_mcp.py")
        assert "the-weather-key" not in json.dumps(status.report())

    def test_a_program_may_not_be_given_a_token(self, home, program):
        with pytest.raises(own.ServerError, match="--env"):
            with httpx.Client() as http:
                own.connect("weather", "personal", vault=FileVault(), http=http,
                            command=program, token="x")


# ---- the rest of its life ----------------------------------------------------------------


class TestLifecycle:
    def test_the_cli_reads_the_token_from_stdin_and_says_json(self, home, server, monkeypatch,
                                                              capsys):
        monkeypatch.setattr(sys, "stdin", io.StringIO(TOKEN + "\n"))
        assert main(["connect", "--server", server.url, "--id", "docs", "--token-stdin",
                     "--json"]) == 0
        events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
        assert [e["event"] for e in events] == ["started", "connected"]
        assert events[-1]["ref"] == "docs:personal" and events[-1]["tools"] == 3

    @pytest.mark.parametrize("flag", ["--ask-token", "--token-stdin"])
    def test_ask_token_and_its_old_name_are_one_flag(self, home, server, monkeypatch, flag):
        # --ask-token is what people type; --token-stdin stays for scripts and the page
        monkeypatch.setattr(sys, "stdin", io.StringIO(TOKEN + "\n"))
        assert main(["connect", "--server", server.url, "--id", "docs", flag]) == 0
        assert FileVault().get("docs:personal")["secret"]["token"] == TOKEN

    def test_a_server_that_wants_a_token_says_to_ask_for_one(self, home, server, capsys):
        assert main(["connect", "--server", server.url, "--id", "docs"]) == 2
        assert "add one with --ask-token" in capsys.readouterr().err

    def test_a_check_skips_it_rather_than_calling_it(self, home, server):
        add(server.url)
        with httpx.Client() as http:
            [row] = connections.check(vault=FileVault(), http=http)
        assert row["state"] == "skipped" and row["why"] == "your own server"

    def test_its_file_goes_with_its_last_connection(self, home, server, capsys):
        add(server.url, account="personal")
        add(server.url, account="work")
        assert main(["disconnect", "docs:personal"]) == 0
        assert (servers_dir() / "docs.toml").exists()
        assert main(["disconnect", "docs:work"]) == 0
        assert not (servers_dir() / "docs.toml").exists()
        assert "docs" not in installed()

    def test_its_file_is_the_persons_to_edit_and_stays_a_server(self, home, server,
                                                                monkeypatch, capsys):
        add(server.url)
        text = (servers_dir() / "docs.toml").read_text()
        monkeypatch.setattr(sys, "stdin", io.StringIO(text.replace('road = "mcp"',
                                                                   'road = "browser"')))
        assert main(["site", "file", "docs", "--set"]) == 2
        monkeypatch.setattr(sys, "stdin", io.StringIO(
            text.replace('add_page = "write"', 'add_page = "read"')))
        assert main(["site", "file", "docs", "--set"]) == 0
        assert installed()["docs"].verbs["add_page"] == "read"


# ---- from Setu's page ------------------------------------------------------------------


def _finished(api, timeout: float = 30.0) -> dict:
    import time
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = api.signin.state()
        if any(e["event"] == "done" for e in state["events"]):
            return state
        time.sleep(0.05)
    raise AssertionError(f"never finished: {api.signin.state()}")


class TestPage:
    def test_the_page_adds_one_and_the_token_rides_stdin_never_the_arguments(self, home,
                                                                             server):
        from setu import page
        api = page.Api(FileVault())
        api.handle("POST", "/api/add-server", {},
                   {"url": server.url, "id": "docs", "token": TOKEN, "level": "read"})
        argv = api.signin.process.args
        state = _finished(api)
        assert TOKEN not in json.dumps(argv) and "--token-stdin" in argv
        connected = next(e for e in state["events"] if e["event"] == "connected")
        assert connected["ref"] == "docs:personal" and connected["tools"] == 3
        assert TOKEN not in json.dumps(state)
        assert FileVault().get("docs:personal")["secret"]["token"] == TOKEN
        _, cards = api.handle("GET", "/api/connections", {})
        assert TOKEN not in json.dumps(cards)

    @pytest.mark.parametrize("person,local", [(None, False), ("asha", True)])
    def test_a_program_is_only_the_owners_at_the_computer(self, home, person, local):
        from setu import page
        api = page.Api(FileVault(), person=person)
        with pytest.raises(page.ApiError) as caught:
            api.handle("POST", "/api/add-server", {}, {"command": "uvx weather-mcp"},
                       local=local)
        assert caught.value.code == 403 and api.signin is None

    @pytest.mark.parametrize("body", [
        {},
        {"url": "https://x.example/mcp", "command": "uvx x"},
        {"url": "docs.example.com"},
        {"url": "https://x.example/mcp", "id": "Not A Name"},
        {"url": "https://x.example/mcp", "header": "X-API-Key"},
        {"url": "https://x.example/mcp", "env": {"KEY": "v"}},
        {"command": "uvx x", "token": "t"},
        {"command": "uvx x", "env": {"not a name": "v"}},
        {"url": "https://x.example/mcp", "level": "everything"},
    ])
    def test_a_body_that_does_not_fit_is_refused_before_anything_runs(self, home, body):
        from setu import page
        api = page.Api(FileVault())
        with pytest.raises(page.ApiError) as caught:
            api.handle("POST", "/api/add-server", {}, body)
        assert caught.value.code == 400 and api.signin is None

    def test_a_person_adds_one_to_their_own_folder(self, home, server, tmp_path):
        from setu import page
        theirs = tmp_path / "people" / "asha"
        api = page.Api.for_person("asha", theirs)
        api.handle("POST", "/api/add-server", {}, {"url": server.url, "id": "docs",
                                                    "token": TOKEN}, local=False)
        assert events_of(_finished(api))[-2:] == ["connected", "done"]
        assert FileVault(theirs).get("docs:personal") is not None
        assert FileVault().get("docs:personal") is None          # not the owner's folder


def events_of(state) -> list[str]:
    return [e["event"] for e in state["events"]]


class TestShownAs:
    """--name: the name it is shown by, separate from its id."""

    def test_the_name_given_is_the_one_shown(self, home, server, monkeypatch):
        monkeypatch.setattr(sys, "stdin", io.StringIO(TOKEN + "\n"))
        assert main(["connect", "--server", server.url, "--id", "docs", "--name", "Our docs",
                     "--ask-token"]) == 0
        manifest = installed()["docs"]
        assert manifest.id == "docs" and manifest.name == "Our docs"

    def test_without_one_it_is_what_the_server_calls_itself(self, home, server):
        add(server.url)
        assert installed()["docs"].name == "Team docs"

    def test_a_name_edited_in_its_file_survives_connecting_again(self, home, server):
        add(server.url)
        path = home / "servers" / "docs.toml"
        path.write_text(path.read_text().replace('name = "Team docs"', 'name = "Kitchen"'))
        with httpx.Client() as http:
            own.again("docs:personal", vault=FileVault(), http=http, level="read")
        assert installed()["docs"].name == "Kitchen"
        with httpx.Client() as http:   # and a name given now wins over it
            own.connect("docs", "personal", vault=FileVault(), http=http, url=server.url,
                        token=TOKEN, display_name="Docs at work")
        assert installed()["docs"].name == "Docs at work"

    @pytest.mark.parametrize("bad", ["", "   ", "two\nlines", "x" * 61])
    def test_a_name_that_is_not_one_line_is_refused(self, home, server, bad):
        with httpx.Client() as http, pytest.raises(own.ServerError, match="--name"):
            own.connect("docs", "personal", vault=FileVault(), http=http, url=server.url,
                        token=TOKEN, display_name=bad)

    def test_the_page_passes_the_name_it_is_shown_by(self, home, server):
        from setu import page
        api = page.Api(FileVault())
        api.handle("POST", "/api/add-server", {}, {"url": server.url, "id": "docs",
                                                    "name": "Our docs", "token": TOKEN})
        argv = api.signin.process.args
        assert argv[argv.index("--name") + 1] == "Our docs"
        assert events_of(_finished(api))[-2:] == ["connected", "done"]
        assert installed()["docs"].name == "Our docs"


class TestAgain:
    def test_changing_the_level_keeps_its_address_and_token(self, home, server, capsys):
        add(server.url)
        assert main(["connect", "docs", "--level", "read"]) == 0
        entry = FileVault().get("docs:personal")
        assert entry["level"] == "read" and entry["secret"]["token"] == TOKEN
        assert "Only its reading tools" in capsys.readouterr().out

    def test_from_a_page_or_a_chat_it_needs_no_sign_in_page(self, home, server, capsys):
        add(server.url)
        assert main(["connect", "docs", "--level", "read", "--json", "--paste"]) == 0
        events = [json.loads(x) for x in capsys.readouterr().out.splitlines()]
        assert [e["event"] for e in events] == ["started", "connected"]

    def test_an_account_never_added_is_told_how(self, home, server, capsys):
        add(server.url)
        assert main(["connect", "docs", "--as", "work"]) == 2
        assert "setu connect --server URL --id docs --as work" in capsys.readouterr().err
