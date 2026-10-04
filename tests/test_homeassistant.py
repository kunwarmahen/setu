"""Home Assistant: the person's own server, signed in to two ways, reached two ways.

The bias is A LEVEL NOBODY HOLDS. Google enforces a scope whatever the
connector does; a Home Assistant token carries every right of its user,
so "See only" is true only if the connector makes it true. These tests
assert on what is NOT offered and NOT sent: no change tool at See only,
a lock refused by the ordinary tool, a See-only bridge that refuses a
switch before the request ever leaves the machine.

Also designed against:

* **The garage door as a light switch.** ``cover.open_cover`` on a
  garage is a way into the house; the connector looks at what Home
  Assistant says the cover is, not at the model's word.
* **A sign-in that cannot refresh.** Home Assistant binds a refresh
  token to the client id that earned it, and Setu's client id carries a
  random port -- so the client id must be kept, and used.
* **A pasted token taken on faith.** It is tried against the server
  before it is kept, and a refused one saves nothing.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from conftest import person
from setu import config, connections, homeassistant, status
from setu.cli import main
from setu.client import EnvSource
from setu.client import http as setu_http
from setu.manifest import ManifestError, find, parse
from setu.vault import FileVault
from setu_homeassistant.bridge import Bridge
from setu_homeassistant.ha import AREA_MAP, HomeAssistant, HomeAssistantError
from setu_homeassistant.server import build

LONG_LIVED = "eyJ-long-lived"

STATES = [
    {"entity_id": "light.kitchen", "state": "off",
     "attributes": {"friendly_name": "Kitchen light"}, "last_changed": "2026-10-03T08:00:00Z"},
    {"entity_id": "fan.master_bedroom_ceiling", "state": "on",
     "attributes": {"friendly_name": "Bedroom fan", "percentage": 40},
     "last_changed": "2026-10-03T07:00:00Z"},
    {"entity_id": "sensor.living_temperature", "state": "21.5",
     "attributes": {"friendly_name": "Living room temperature",
                    "unit_of_measurement": "°C"}, "last_changed": "2026-10-03T08:10:00Z"},
    {"entity_id": "lock.front_door", "state": "locked",
     "attributes": {"friendly_name": "Front door"}, "last_changed": "2026-10-03T06:00:00Z"},
    {"entity_id": "cover.garage", "state": "closed",
     "attributes": {"friendly_name": "Garage door", "device_class": "garage"},
     "last_changed": "2026-10-03T06:00:00Z"},
    {"entity_id": "cover.office_blind", "state": "open",
     "attributes": {"friendly_name": "Office blind", "device_class": "blind"},
     "last_changed": "2026-10-03T06:00:00Z"},
]

MCP_TOOLS = [{"name": "homeassistant__GetLiveContext", "description": "states",
              "inputSchema": {"type": "object"}},
             {"name": "HassTurnOn", "description": "turn on", "inputSchema": {"type": "object"}},
             {"name": "HassTurnOff", "description": "turn off",
              "inputSchema": {"type": "object"}}]


class FakeHA:
    """A Home Assistant on a real local port: login, tokens, REST, MCP."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.posts: list[tuple[str, dict[str, Any]]] = []
        self.issued = 0
        self.valid = {LONG_LIVED}
        self.refreshes: dict[str, str] = {}       # refresh token -> client id
        self.revoked: list[str] = []

    def serve(self) -> str:
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a: Any) -> None:
                pass

            def _send(self, code: int, body: Any = None, kind="application/json") -> None:
                data = b"" if body is None else (body if isinstance(body, bytes)
                                                 else json.dumps(body).encode())
                self.send_response(code)
                self.send_header("Content-Type", kind)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _authed(self) -> bool:
                token = self.headers.get("Authorization", "").removeprefix("Bearer ")
                if token not in fake.valid:
                    self._send(401, {"message": "Unauthorized"})
                    return False
                return True

            def do_GET(self) -> None:  # noqa: N802
                url = urlparse(self.path)
                fake.calls.append(f"GET {url.path}")
                if not self._authed():
                    return
                if url.path == "/api/config":
                    return self._send(200, {"location_name": "Home", "version": "2026.10.0"})
                if url.path == "/api/states":
                    return self._send(200, STATES)
                if url.path.startswith("/api/states/"):
                    eid = url.path.rsplit("/", 1)[1]
                    st = next((s for s in STATES if s["entity_id"] == eid), None)
                    return self._send(200, st) if st else self._send(404, {"message": "no"})
                if url.path == "/api/services":
                    return self._send(200, [{"domain": "light", "services": {
                        "turn_on": {"name": "Turn on", "fields": {"brightness_pct": {}}}}}])
                if url.path.startswith("/api/history/period/"):
                    return self._send(200, [[{"state": "off", "last_changed": "t1"},
                                             {"state": "off", "last_changed": "t2"},
                                             {"state": "on", "last_changed": "t3"}]])
                self._send(404, {"message": "no"})

            def do_POST(self) -> None:  # noqa: N802
                url = urlparse(self.path)
                raw = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
                fake.calls.append(f"POST {url.path}")
                if url.path == "/auth/token":
                    form = {k: v[0] for k, v in parse_qs(raw).items()}
                    if form["grant_type"] == "authorization_code":
                        fake.issued += 1
                        access, refresh = f"access-{fake.issued}", f"refresh-{fake.issued}"
                        fake.valid.add(access)
                        fake.refreshes[refresh] = form["client_id"]
                        return self._send(200, {"access_token": access, "expires_in": 1800,
                                                "refresh_token": refresh,
                                                "token_type": "Bearer"})
                    if fake.refreshes.get(form.get("refresh_token")) != form.get("client_id"):
                        return self._send(400, {"error": "invalid_grant"})
                    fake.issued += 1
                    access = f"access-{fake.issued}"
                    fake.valid.add(access)
                    return self._send(200, {"access_token": access, "expires_in": 1800,
                                            "token_type": "Bearer"})
                if url.path == "/auth/revoke":
                    fake.revoked.append(parse_qs(raw)["token"][0])
                    return self._send(200)
                if not self._authed():
                    return
                body = json.loads(raw or "{}")
                fake.posts.append((url.path, body))
                if url.path.startswith("/api/services/"):
                    return self._send(200, [{**STATES[0], "state": "on"}])
                if url.path == "/api/template":
                    # Home Assistant renders a template to plain text; this
                    # fake knows only the connector's one fixed template
                    if body.get("template") != AREA_MAP:
                        return self._send(400, {"message": "unknown template"})
                    lines = []
                    for area_id, (name, ids) in AREAS.items():
                        lines += ([f"{area_id}\t{name}\t{e}" for e in ids]
                                  or [f"{area_id}\t{name}"])
                    return self._send(200, ("\n".join(lines) + "\n").encode(), "text/plain")
                if url.path == "/api/mcp":
                    if "id" not in body:
                        return self._send(202)
                    if body["method"] == "initialize":
                        result = {"protocolVersion": body["params"]["protocolVersion"],
                                  "capabilities": {"tools": {}},
                                  "serverInfo": {"name": "home-assistant"}}
                    elif body["method"] == "tools/list":
                        result = {"tools": MCP_TOOLS}
                    else:
                        result = {"content": [{"type": "text", "text": "done"}]}
                    return self._send(200, {"jsonrpc": "2.0", "id": body["id"],
                                            "result": result})
                self._send(404, {"message": "no"})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        return self.base


@pytest.fixture
def ha():
    fake = FakeHA()
    fake.serve()
    yield fake
    fake.server.shutdown()


def sign_in(fake: FakeHA, account="home", level=None, seen=None, connector="homeassistant",
            token=None):
    def browser(url: str) -> None:
        if seen is not None:
            seen.append(url)
        person(url)
    with httpx.Client() as http:
        return connections.connect_homeassistant(
            find(connector), account, level=level, base_url=fake.base, vault=FileVault(),
            http=http, long_lived=token, open_browser=browser, timeout=10)


AREAS = {"kitchen": ("Kitchen", ["light.kitchen"]),
         "living_room": ("Living Room", ["sensor.living_temperature"]),
         "garage": ("Garage", [])}


def rest(fake: FakeHA, token=LONG_LIVED) -> HomeAssistant:
    return HomeAssistant(setu_http(fake.base, tokens=EnvSource(token)))


# ---- the manifest -----------------------------------------------------------------


class TestManifest:
    def test_a_site_without_scopes_may_have_levels_without_them(self):
        m = find("homeassistant")
        assert [lv.name for lv in m.levels] == ["read", "control", "full"]
        assert not m.scoped and m.default_level.name == "read"

    def test_google_levels_still_need_scopes(self):
        with pytest.raises(ManifestError, match="names no scopes"):
            parse({"id": "x", "name": "X", "road": "api", "auth": "google",
                   "command": ["x"], "levels": {"read": {}}})

    def test_star_classes_the_unlisted_and_may_never_be_read(self):
        m = find("homeassistant-mcp")
        assert m.verb("homeassistant__GetLiveContext") == "read"
        assert m.verb("llm__GetDateTime") == "read" and m.verb("todo__get_items") == "read"
        assert m.verb("HassTurnOn") == "write"
        with pytest.raises(ManifestError, match="never read"):
            parse({"id": "x", "name": "X", "road": "mcp", "auth": "homeassistant",
                   "command": ["x"], "levels": {"read": {}}, "verbs": {"*": "read"}})


# ---- signing in -------------------------------------------------------------------


class TestSignIn:
    def test_the_login_page_names_setu_as_its_own_client(self, home, ha):
        urls: list[str] = []
        entry = sign_in(ha, seen=urls)
        query = parse_qs(urlparse(urls[0]).query)
        assert urls[0].startswith(f"{ha.base}/auth/authorize?")
        assert query["client_id"] == query["redirect_uri"]
        assert query["client_id"][0].startswith("http://127.0.0.1:")
        assert entry["email"] == f"Home ({ha.base.removeprefix('http://')})"
        assert entry["base_url"] == ha.base and entry["level"] == "read"
        assert entry["secret"]["client_id"] == query["client_id"][0]

    def test_the_refresh_uses_the_client_id_that_earned_it(self, home, ha):
        sign_in(ha)
        vault = FileVault()
        entry = vault.get("homeassistant:home")
        entry["secret"]["expires_at"] = time.time() - 10
        vault.put("homeassistant:home", entry)
        with httpx.Client() as http:
            got = connections.token("homeassistant:home", vault=vault, http=http)
        assert got.access_token == "access-2" and got.level == "read"

    def test_a_pasted_token_is_tried_first_and_a_bad_one_saves_nothing(self, home, ha):
        with pytest.raises(homeassistant.HomeAssistantError, match="refused the token"):
            sign_in(ha, token="wrong")
        assert FileVault().list() == []
        entry = sign_in(ha, token=LONG_LIVED, level="control")
        assert entry["secret"] == {"kind": "long_lived", "access_token": LONG_LIVED}
        assert "POST /auth/token" not in ha.calls

    def test_a_pasted_token_is_never_refreshed(self, home, ha):
        sign_in(ha, token=LONG_LIVED)
        with httpx.Client() as http:
            got = connections.token("homeassistant:home", vault=FileVault(), http=http)
            assert got.access_token == LONG_LIVED
            with pytest.raises(connections.ConnectionFailed, match="cannot be refreshed"):
                connections.token("homeassistant:home", vault=FileVault(), http=http,
                                  force=True)

    def test_disconnect_revokes_a_sign_in_and_says_so_for_a_token(self, home, ha, capsys):
        sign_in(ha)
        assert main(["disconnect", "homeassistant:home"]) == 0
        assert ha.revoked == ["refresh-1"] and "asked to revoke" in capsys.readouterr().out
        sign_in(ha, token=LONG_LIVED)
        assert main(["disconnect", "homeassistant:home"]) == 0
        assert "delete it in your profile" in capsys.readouterr().out
        assert ha.revoked == ["refresh-1"]

    def test_signing_in_again_revokes_the_one_it_replaced(self, home, ha):
        sign_in(ha)
        sign_in(ha, level="control")
        assert ha.revoked == ["refresh-1"]
        assert FileVault().get("homeassistant:home")["level"] == "control"

    def test_the_cli_reads_a_token_from_stdin_never_argv(self, home, ha, monkeypatch, capsys):
        monkeypatch.setattr(sys, "stdin", __import__("io").StringIO(LONG_LIVED + "\n"))
        assert main(["connect", "homeassistant", "--as", "home", "--url", ha.base,
                     "--token-stdin"]) == 0
        assert "connected homeassistant:home to Home" in capsys.readouterr().out
        assert main(["list"]) == 0
        assert LONG_LIVED not in capsys.readouterr().out

    def test_an_address_with_a_path_is_refused(self):
        assert homeassistant.normalise_url("homeassistant.local:8123/") == \
            "http://homeassistant.local:8123"
        with pytest.raises(homeassistant.HomeAssistantError, match="without a path"):
            homeassistant.normalise_url("http://ha.local:8123/lovelace")


class TestTheAddressIsKept:
    def test_the_first_address_used_is_remembered(self, home, ha, monkeypatch):
        monkeypatch.setattr(sys, "stdin", __import__("io").StringIO(LONG_LIVED + "\n"))
        assert main(["connect", "homeassistant", "--as", "home", "--url", ha.base,
                     "--token-stdin"]) == 0
        assert config.homeassistant_url() == ha.base

    def test_signing_in_again_uses_the_connections_own_address(self, home, ha, monkeypatch,
                                                               capsys):
        sign_in(ha, token=LONG_LIVED)            # made without remembering anything
        assert config.homeassistant_url() is None
        row = next(c for c in status.report()["connectors"] if c["id"] == "homeassistant")
        assert row["ready"]                       # the page may offer "change access"
        monkeypatch.setattr(sys, "stdin", __import__("io").StringIO(LONG_LIVED + "\n"))
        assert main(["connect", "homeassistant", "--as", "home", "--level", "control",
                     "--token-stdin"]) == 0
        assert FileVault().get("homeassistant:home")["level"] == "control"


class TestTheReport:
    def test_no_address_means_not_ready_and_says_which_setting(self, home):
        ha_row = next(c for c in status.report()["connectors"] if c["id"] == "homeassistant")
        assert not ha_row["ready"] and ha_row["needs_setup"] == "homeassistant_url"
        assert ha_row["enforced_by_site"] is False

    def test_a_remembered_address_makes_it_ready(self, home, ha):
        assert main(["config", "homeassistant-url", ha.base]) == 0
        data = status.report()
        assert data["setup"]["homeassistant_url"] == ha.base
        assert next(c for c in data["connectors"] if c["id"] == "homeassistant")["ready"]
        assert config.homeassistant_url() == ha.base

    def test_the_connection_row_carries_its_server_and_no_secret(self, home, ha):
        sign_in(ha)
        data = status.report()
        row = data["connections"][0]
        assert row["base_url"] == ha.base and row["level_label"] == "See only"
        assert "refresh-1" not in json.dumps(data)


# ---- the REST road ----------------------------------------------------------------


def tool_names(level: str, fake: FakeHA) -> set[str]:
    return {t.name for t in asyncio.run(build(rest(fake), level).list_tools())}


class TestRest:
    def test_tools_follow_the_level(self, ha):
        reads = {"list_entities", "list_areas", "get_state", "get_history", "list_services"}
        assert tool_names("read", ha) == reads
        assert tool_names("control", ha) == reads | {"call_service"}
        assert tool_names("full", ha) == reads | {"call_service", "call_secure_service"}
        assert tool_names("", ha) == reads          # unknown is the least

    def test_see_only_says_how_to_allow_more(self, ha):
        text = build(rest(ha), "read", "home").instructions
        assert "--as home --level control" in text
        assert "See only" not in build(rest(ha), "control").instructions

    def test_a_listing_is_one_line_each_and_filters(self, ha):
        out = rest(ha).list_entities(domain="fan")
        assert out == ("1 entities:\nfan.master_bedroom_ceiling — Bedroom fan: on")
        assert "21.5 °C" in rest(ha).list_entities(search="temperature")
        assert "and 4 more" in rest(ha).list_entities(limit=2)

    def test_history_is_its_changes(self, ha):
        out = rest(ha).get_history("light.kitchen", 6)
        assert "2 changes" in out and "t2" not in out

    def test_the_ordinary_tool_refuses_what_guards_the_home(self, ha):
        h = rest(ha)
        with pytest.raises(HomeAssistantError, match="call_secure_service"):
            h.call_service("lock", "unlock", "lock.front_door")
        with pytest.raises(HomeAssistantError, match="call_secure_service"):
            h.call_service("cover", "open_cover", "cover.garage")
        with pytest.raises(HomeAssistantError, match="call_secure_service"):
            h.call_service("cover", "open_cover", "")      # every cover, doors included
        assert not [p for p, _ in ha.posts if p.startswith("/api/services")]

    def test_a_blind_is_not_a_door_and_a_light_just_works(self, ha):
        h = rest(ha)
        h.call_service("cover", "open_cover", "cover.office_blind")
        out = h.call_service("light", "turn_on", "light.kitchen", {"brightness_pct": 40})
        assert "light.kitchen — Kitchen light: on" in out
        assert ha.posts[-1] == ("/api/services/light/turn_on",
                                {"brightness_pct": 40, "entity_id": "light.kitchen"})

    def test_the_secure_tool_does_the_secure_thing(self, ha):
        rest(ha).call_service("lock", "unlock", "lock.front_door", secure_ok=True)
        assert ha.posts[-1][0] == "/api/services/lock/unlock"


# ---- the MCP road -----------------------------------------------------------------


def bridge(fake: FakeHA, level: str) -> Bridge:
    return Bridge(setu_http(fake.base, tokens=EnvSource(LONG_LIVED)), level)


class TestBridge:
    def test_see_only_shows_only_the_reading_tools(self, ha):
        [answer] = bridge(ha, "read").handle({"jsonrpc": "2.0", "id": 1,
                                              "method": "tools/list"})
        assert [t["name"] for t in answer["result"]["tools"]] == \
            ["homeassistant__GetLiveContext"]

    def test_see_only_refuses_a_switch_before_it_leaves_the_machine(self, ha):
        [answer] = bridge(ha, "read").handle({"jsonrpc": "2.0", "id": 2,
                                              "method": "tools/call",
                                              "params": {"name": "HassTurnOn"}})
        assert "See only" in answer["error"]["message"]
        assert ha.posts == []

    def test_control_passes_everything_through(self, ha):
        b = bridge(ha, "control")
        [listed] = b.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert len(listed["result"]["tools"]) == 3
        [done] = b.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                           "params": {"name": "HassTurnOn", "arguments": {"name": "fan"}}})
        assert done["result"]["content"][0]["text"] == "done"
        assert b.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) == []

    def test_no_mcp_server_says_which_integration_to_add(self, ha):
        b = bridge(ha, "read")
        b.http = setu_http(ha.base + "/nothing", tokens=EnvSource(LONG_LIVED))
        [answer] = b.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert "Model Context Protocol Server" in answer["error"]["message"]


# ---- the whole road ---------------------------------------------------------------


class MCP:
    def __init__(self, argv: list[str], env: dict[str, str]) -> None:
        self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True, env=env)
        self.next = 0

    def request(self, method: str, params: dict | None = None) -> dict:
        self.next += 1
        self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": self.next, "method": method,
                                          "params": params or {}}) + "\n")
        self.proc.stdin.flush()
        while True:
            line = json.loads(self.proc.stdout.readline())
            if line.get("id") == self.next:
                return line

    def notify(self, method: str) -> None:
        self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method}) + "\n")
        self.proc.stdin.flush()

    def close(self) -> int:
        self.proc.stdin.close()
        return self.proc.wait(timeout=10)


INIT = {"protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "harness", "version": "0"}}


@pytest.mark.parametrize("connector,first_tool", [
    ("homeassistant", "list_entities"), ("homeassistant-mcp", "homeassistant__GetLiveContext")])
def test_a_harness_reaches_the_home_through_setu_run(home, ha, connector, first_tool):
    sign_in(ha, connector=connector)
    env = {k: v for k, v in os.environ.items() if k != "SETU_API_BASE"}
    client = MCP([sys.executable, "-m", "setu.cli", "run", f"{connector}:home"], env)
    try:
        assert "result" in client.request("initialize", INIT)
        client.notify("notifications/initialized")
        names = [t["name"] for t in client.request("tools/list")["result"]["tools"]]
        assert names[0] == first_tool
        assert not {"call_service", "HassTurnOn"} & set(names)       # See only
        answer = client.request("tools/call", {"name": first_tool, "arguments": {}})
        assert answer["result"]["content"][0]["text"]
    finally:
        assert client.close() == 0
    assert "refresh-1" not in json.dumps(ha.posts)


# ---- rooms ---------------------------------------------------------------------


class TestAreas:
    """Asked by room; Home Assistant's REST has no area endpoint, so one
    fixed template maps areas to entities (nothing a tool was given is in it)."""

    def test_the_areas_with_their_counts(self, ha):
        out = rest(ha).list_areas()
        assert out.startswith("3 areas:")
        assert "kitchen — Kitchen: 1 entity" in out and "garage — Garage: 0 entities" in out

    def test_entities_in_a_room_by_name_or_id(self, ha):
        client = rest(ha)
        for named in ("Living Room", "living_room", "living-room"):
            out = client.list_entities(area=named)
            assert "sensor.living_temperature" in out and "light.kitchen" not in out
        assert "light.kitchen" in client.list_entities(domain="light", area="kitchen")
        assert client.list_entities(area="Garage") == "no entities in area 'Garage'"

    def test_an_unknown_area_names_the_known_ones(self, ha):
        with pytest.raises(HomeAssistantError, match="Kitchen, Living Room, Garage"):
            rest(ha).list_entities(area="attic")

    def test_what_was_asked_is_never_in_the_template(self, ha):
        with pytest.raises(HomeAssistantError):
            rest(ha).list_entities(area="{% for x in states %}{{x}}{% endfor %}")
        assert all(body.get("template") == AREA_MAP
                   for path, body in ha.posts if path == "/api/template")

    def test_list_areas_is_a_read_at_every_level(self):
        manifest = find("homeassistant")
        assert manifest.verb("list_areas") == "read"
