"""The catalog server: serves what the maintainer signed, and nothing else.

The bias is A SERVER TAKEN AT ITS WORD. The server is the one piece of
Setu on someone else's machine, so these tests treat it as the thing an
attacker gets: an upload without the maintainer's token, one signed by
a stranger, one with a byte changed, one OLDER than what is served (an
old index can bring back a withdrawn version) -- each refused, with the
served index unchanged. And on the client: a server that serves an old
index is refused there too, and a server that is down costs only
freshness, never the last good copy.
"""

from __future__ import annotations

import base64
import json
import socket
import threading
import time
from datetime import UTC, datetime, timedelta

import pytest
from setu import catalog
from setu.cli import main
from setu.status import report
from setu_catalog_server.app import INDEX, SIG, make_app
from starlette.testclient import TestClient

TOKEN = "maintainer-token"


def doc(issued="2026-10-04T00:00:00Z", **over):
    d = {"format": catalog.FORMAT, "issued": issued,
         "connectors": [{"id": "gmail", "name": "Gmail", "label": "by-setu",
                         "author": "Setu", "package": "setu-gmail", "version": "0.1.0",
                         "installs": 3, "yanked": {}}],
         "recipes": []}
    d.update(over)
    return d


@pytest.fixture
def keys(tmp_path):
    pub, kid = catalog.keygen(tmp_path / "keys" / "setu.key")
    return tmp_path / "keys" / "setu.key", catalog.load_public(pub)


@pytest.fixture
def server(tmp_path, keys):
    data = tmp_path / "server-data"
    catalog.trust(keys[1], home=data)
    return data, TestClient(make_app(data, TOKEN))


def signed(d: dict, key) -> tuple[bytes, dict]:
    raw = json.dumps(d).encode()
    return raw, catalog.sign(raw, key)


def upload(client, raw, sig, token=TOKEN):
    return client.post("/publish", json={"index": base64.b64encode(raw).decode(), "sig": sig},
                       headers={"Authorization": f"Bearer {token}"})


class TestTheServer:
    def test_nothing_is_served_before_a_publish(self, server):
        assert server[1].get("/index.json").status_code == 404

    def test_a_signed_index_is_served_byte_for_byte(self, server, keys):
        data, client = server
        raw, sig = signed(doc(), keys[0])
        answer = upload(client, raw, sig)
        assert answer.status_code == 200 and answer.json()["connectors"] == 1
        assert client.get("/index.json").content == raw
        assert client.get("/index.json.sig").json() == sig
        assert client.get("/health").json()["issued"] == "2026-10-04T00:00:00Z"

    def test_no_token_no_publish(self, server, keys):
        raw, sig = signed(doc(), keys[0])
        assert upload(server[1], raw, sig, token="").status_code == 401
        assert upload(server[1], raw, sig, token="guess").status_code == 401
        assert server[1].get("/index.json").status_code == 404

    def test_a_strangers_key_or_a_changed_byte_is_refused(self, server, keys, tmp_path):
        data, client = server
        catalog.keygen(tmp_path / "stranger.key")
        raw, sig = signed(doc(), tmp_path / "stranger.key")
        assert upload(client, raw, sig).status_code == 409
        raw, sig = signed(doc(), keys[0])
        answer = upload(client, raw.replace(b'"installs": 3', b'"installs": 9'), sig)
        assert answer.status_code == 409 and "does not match" in answer.json()["error"]
        assert not (data / INDEX).exists()

    def test_an_older_index_never_replaces_a_newer_one(self, server, keys):
        data, client = server
        assert upload(client, *signed(doc(issued="2026-10-04T00:00:00Z"), keys[0])).status_code \
            == 200
        older = doc(issued="2026-10-01T00:00:00Z",
                    connectors=[{**doc()["connectors"][0], "yanked": {}}])
        answer = upload(client, *signed(older, keys[0]))
        assert answer.status_code == 409 and "older" in answer.json()["error"]
        assert json.loads((data / INDEX).read_bytes())["issued"] == "2026-10-04T00:00:00Z"

    def test_the_signing_key_is_never_on_the_server(self, server, keys):
        data, client = server
        upload(client, *signed(doc(), keys[0]))
        names = {p.name for p in data.rglob("*")}
        assert "setu.key" not in names and not any("private" in n for n in names)


# ---- the client, against a real server on a real port -------------------------------


@pytest.fixture
def live(tmp_path, keys, home):
    """The server on a local port; the person trusts the maintainer's key."""
    import uvicorn

    data = tmp_path / "live-data"
    catalog.trust(keys[1], home=data)
    catalog.trust(keys[1])                               # the person's Setu
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    srv = uvicorn.Server(uvicorn.Config(make_app(data, TOKEN), host="127.0.0.1", port=port,
                                        log_level="error"))
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not srv.started and time.monotonic() < deadline:
        time.sleep(0.02)
    yield f"http://127.0.0.1:{port}", data
    srv.should_exit = True
    thread.join(5)


class TestTheClient:
    def test_use_an_address_and_the_report_says_so(self, live, keys, tmp_path):
        address, data = live
        (data / INDEX).write_bytes(raw := json.dumps(doc()).encode())
        (data / SIG).write_text(json.dumps(catalog.sign(raw, keys[0])))
        index = catalog.use(address)
        assert index.source == address and "gmail" in index.connectors
        assert report()["catalog"]["source"] == address

    def test_publish_from_the_cli(self, live, keys, tmp_path, monkeypatch, capsys):
        address, data = live
        path = tmp_path / "index.json"
        path.write_text(json.dumps(doc()))
        assert main(["catalog", "sign", str(path), "--key", str(keys[0])]) == 0
        monkeypatch.setenv("SETU_CATALOG_TOKEN", TOKEN)
        assert main(["catalog", "publish", str(path), "--to", address]) == 0
        assert "published" in capsys.readouterr().out
        assert (data / INDEX).read_bytes() == path.read_bytes()

    def test_a_server_serving_an_old_index_is_refused_here_too(self, live, keys):
        address, data = live
        for issued in ("2026-10-04T00:00:00Z", "2026-10-01T00:00:00Z"):
            raw = json.dumps(doc(issued=issued)).encode()
            (data / INDEX).write_bytes(raw)      # the server's files, rolled back by hand
            (data / SIG).write_text(json.dumps(catalog.sign(raw, keys[0])))
            if issued.startswith("2026-10-04"):
                catalog.use(address)
        with pytest.raises(catalog.CatalogError, match="before the one kept"):
            catalog.use(address)
        assert catalog.kept().data["issued"] == "2026-10-04T00:00:00Z"

    def test_asked_again_daily_and_a_down_server_costs_only_freshness(self, live, keys):
        address, data = live
        raw = json.dumps(doc()).encode()
        (data / INDEX).write_bytes(raw)
        (data / SIG).write_text(json.dumps(catalog.sign(raw, keys[0])))
        catalog.use(address)
        newer = json.dumps(doc(issued="2026-10-05T00:00:00Z")).encode()
        (data / INDEX).write_bytes(newer)
        (data / SIG).write_text(json.dumps(catalog.sign(newer, keys[0])))
        fresh, note = catalog.current()
        assert fresh.data["issued"] == "2026-10-04T00:00:00Z" and note == ""   # under a day
        tomorrow = datetime.now(UTC) + timedelta(days=1, minutes=1)
        fresh, note = catalog.current(now=tomorrow)
        assert fresh.data["issued"] == "2026-10-05T00:00:00Z"
        (data / INDEX).unlink()                          # the server loses its files
        fresh, note = catalog.current(now=tomorrow + timedelta(days=1, minutes=1))
        assert fresh.data["issued"] == "2026-10-05T00:00:00Z"
        assert note.startswith("catalog: using the copy kept")
