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


# ---- install counts -------------------------------------------------------------------


class TestCounting:
    def test_one_per_address_per_connector_per_day(self, server):
        from setu_catalog_server.app import Catalog
        data, _ = server
        cat = Catalog(data, TOKEN)
        assert cat.install("gmail", "0.1.0", "10.0.0.1", day="2026-10-04")
        assert not cat.install("gmail", "0.1.0", "10.0.0.1", day="2026-10-04")
        assert cat.install("gmail", "0.1.0", "10.0.0.2", day="2026-10-04")
        assert cat.install("amazon", "0.1.0", "10.0.0.1", day="2026-10-04")
        assert cat.install("gmail", "0.2.0", "10.0.0.1", day="2026-10-05")   # a new day
        totals = cat.totals()
        assert totals["gmail"] == {"total": 3, "versions": {"0.1.0": 2, "0.2.0": 1}}

    def test_no_address_is_kept_and_the_salt_is_new_each_day(self, server):
        from setu_catalog_server.app import TODAY, Catalog
        data, _ = server
        cat = Catalog(data, TOKEN)
        cat.install("gmail", "0.1.0", "203.0.113.9", day="2026-10-04")
        first = json.loads((data / TODAY).read_text())["salt"]
        cat.install("gmail", "0.1.0", "203.0.113.9", day="2026-10-05")
        assert json.loads((data / TODAY).read_text())["salt"] != first
        on_disk = "".join(p.read_text() for p in data.glob("*.json"))
        assert "203.0.113.9" not in on_disk

    def test_one_address_cannot_pump_the_counts(self, server):
        from setu_catalog_server.app import PINGS_PER_DAY, Catalog
        data, _ = server
        cat = Catalog(data, TOKEN)
        counted = sum(cat.install(f"c{i}", "1", "10.0.0.1", day="2026-10-04")
                      for i in range(PINGS_PER_DAY + 20))
        assert counted == PINGS_PER_DAY

    def test_the_route_takes_an_id_and_a_version_only(self, server):
        _, client = server
        assert client.post("/installs", json={"id": "gmail", "version": "0.1.0"}).json() \
            == {"counted": True}
        assert client.post("/installs", json={"id": "../etc", "version": "1"}).status_code == 400
        assert client.post("/installs", json={"id": "gmail"}).status_code == 400
        assert client.get("/installs.json").json()["gmail"]["total"] == 1


class TestThePing:
    def kept(self, live, keys):
        address, data = live
        listed = doc(connectors=[
            {"id": "gmail", "name": "Gmail", "label": "by-setu", "package": "setu-gmail",
             "version": "0.1.0", "yanked": {}},
            {"id": "notion", "name": "Notion", "label": "partner", "package": "setu-notion",
             "version": "1.0.0", "yanked": {}}])
        raw = json.dumps(listed).encode()
        (data / INDEX).write_bytes(raw)
        (data / SIG).write_text(json.dumps(catalog.sign(raw, keys[0])))
        return catalog.use(address), data

    def test_listed_and_installed_only_and_once_per_version(self, live, keys):
        index, data = self.kept(live, keys)
        assert catalog.ping_installs(index) == 1          # gmail; notion isn't installed
        assert catalog.ping_installs(index) == 0          # said already
        totals = json.loads((data / "installs.json").read_text())
        assert list(totals) == ["gmail"]                  # nothing unlisted ever sent

    def test_off_sends_nothing(self, live, keys, capsys):
        index, data = self.kept(live, keys)
        assert main(["config", "share-installs", "off"]) == 0
        assert catalog.ping_installs(index) == 0
        assert not (data / "installs.json").exists()

    def test_the_report_pings_and_never_fails_for_it(self, live, keys):
        index, data = self.kept(live, keys)
        report()
        assert json.loads((data / "installs.json").read_text())["gmail"]["total"] == 1

    def test_first_use_says_what_is_shared(self, live, keys, capsys):
        address, data = live
        raw = json.dumps(doc()).encode()
        (data / INDEX).write_bytes(raw)
        (data / SIG).write_text(json.dumps(catalog.sign(raw, keys[0])))
        assert main(["catalog", "use", address]) == 0
        assert "share-installs off" in capsys.readouterr().out

    def test_the_maintainer_folds_the_totals_in(self, live, keys, tmp_path, capsys):
        address, data = live
        (data / "installs.json").write_text(json.dumps({"gmail": {"total": 12,
                                                                  "versions": {}}}))
        path = tmp_path / "index.json"
        path.write_text(json.dumps(doc()))
        assert main(["catalog", "counts", str(path), "--to", address]) == 0
        assert json.loads(path.read_text())["connectors"][0]["installs"] == 12


# ---- submissions ----------------------------------------------------------------------


COMMIT = "a" * 40


class TestSubmissions:
    def recipe(self, tmp_path):
        folder = tmp_path / "ha-fan-speed"
        (folder / "scripts").mkdir(parents=True)
        (folder / "SKILL.md").write_text("---\nname: ha-fan-speed\n---\nSet the fan.\n")
        (folder / "scripts" / "fan.py").write_text("print('fan')\n")
        return folder

    def test_a_recipe_from_its_folder_waits_for_review(self, live, tmp_path, capsys,
                                                       monkeypatch):
        address, data = live
        assert main(["catalog", "submit", str(self.recipe(tmp_path)), "--to", address,
                     "--author", "priya", "--contact", "priya@example.com"]) == 0
        sid = capsys.readouterr().out.split("submitted: ")[1].split(" ")[0]
        assert main(["catalog", "submission", sid, "--to", address]) == 0
        assert "recipe ha-fan-speed -- open" in capsys.readouterr().out
        # nothing is served because of it
        assert not (data / INDEX).exists()
        monkeypatch.setenv("SETU_CATALOG_TOKEN", TOKEN)
        assert main(["catalog", "review", "--to", address]) == 0
        assert "ha-fan-speed" in capsys.readouterr().out
        assert main(["catalog", "review", sid, "--to", address]) == 0
        full = json.loads(capsys.readouterr().out)
        assert full["files"]["scripts/fan.py"] == "print('fan')\n"
        assert full["contact"] == "priya@example.com" and "who" not in full
        assert main(["catalog", "close", sid, "--verdict", "declined", "--reason",
                     "the script needs a test", "--to", address]) == 0
        capsys.readouterr()
        assert main(["catalog", "submission", sid, "--to", address]) == 0
        assert "declined: the script needs a test" in capsys.readouterr().out

    def test_the_author_sees_the_verdict_never_the_contents(self, server):
        _, client = server
        sid = client.post("/submissions", json={
            "kind": "recipe", "id": "x", "author": "a", "contact": "secret@example.com",
            "files": {"SKILL.md": "hi"}}).json()["submission"]
        seen = client.get(f"/submissions/{sid}").json()
        assert seen["status"] == "open" and "contact" not in seen and "files" not in seen
        assert client.get(f"/submissions/{sid}?full").status_code == 401
        assert client.get("/submissions").status_code == 401

    def test_a_connector_is_source_at_an_exact_commit(self, server):
        _, client = server
        good = {"kind": "connector", "id": "notion", "author": "a",
                "repo": "https://github.com/someone/setu-notion", "commit": COMMIT}
        assert client.post("/submissions", json=good).status_code == 201
        for bad in ({"commit": "main"}, {"repo": "http://example.com/x"},
                    {"repo": "file:///etc/passwd"}, {"id": "../x"}, {"author": ""}):
            assert client.post("/submissions", json={**good, **bad}).status_code == 400

    def test_a_recipe_is_its_files_and_nothing_else(self, server):
        _, client = server
        base = {"kind": "recipe", "id": "r", "author": "a"}
        assert client.post("/submissions", json={**base, "files": {
            "SKILL.md": "x", "../../etc/cron.d/x": "y"}}).status_code == 400
        assert client.post("/submissions", json={**base, "files": {
            "scripts/run.py": "x"}}).status_code == 400          # no SKILL.md

    def test_a_few_a_day_from_one_address(self, server):
        from setu_catalog_server.app import SUBMISSIONS_PER_DAY
        _, client = server
        codes = [client.post("/submissions", json={
            "kind": "recipe", "id": f"r{i}", "author": "a",
            "files": {"SKILL.md": "x"}}).status_code for i in range(SUBMISSIONS_PER_DAY + 2)]
        assert codes.count(201) == SUBMISSIONS_PER_DAY and codes[-1] == 429


# ---- install by hash ------------------------------------------------------------------


class TestInstallByHash:
    def listed(self, tmp_path, keys, wheel_bytes=b"PK fake wheel", **entry):
        import hashlib
        wheel = tmp_path / "setu_notion-1.0.0-py3-none-any.whl"
        wheel.write_bytes(wheel_bytes)
        connector = {"id": "notion", "name": "Notion", "label": "partner", "author": "you",
                     "package": "setu-notion", "version": "1.0.0", "yanked": {},
                     "wheel": {"url": f"file://{wheel}",
                               "sha256": hashlib.sha256(b"PK fake wheel").hexdigest()}}
        connector.update(entry)
        catalog.trust(keys[1])
        path = tmp_path / "index.json"
        path.write_text(json.dumps(doc(connectors=[connector])))
        path.with_name("index.json.sig").write_text(
            json.dumps(catalog.sign(path.read_bytes(), keys[0])))
        catalog.use(path)
        ran = []

        def run(argv, **kw):
            ran.append(argv)
            return type("Done", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        return ran, run

    def test_the_wheel_the_index_names_is_installed(self, home, tmp_path, keys):
        ran, run = self.listed(tmp_path, keys)
        assert catalog.install("notion", run=run) == "1.0.0"
        assert ran and ran[0][-1].endswith("setu_notion-1.0.0-py3-none-any.whl")

    def test_a_different_wheel_is_never_installed(self, home, tmp_path, keys):
        ran, run = self.listed(tmp_path, keys, wheel_bytes=b"PK something else")
        with pytest.raises(catalog.CatalogError, match="not installed"):
            catalog.install("notion", run=run)
        assert ran == []

    def test_a_withdrawn_version_is_refused(self, home, tmp_path, keys):
        ran, run = self.listed(tmp_path, keys, yanked={"1.0.0": "sent mail to a stranger"})
        with pytest.raises(catalog.CatalogError, match="withdrawn: sent mail"):
            catalog.install("notion", run=run)
        assert ran == []

    def test_only_https_and_only_listed(self, home, tmp_path, keys):
        ran, run = self.listed(tmp_path, keys, wheel={"url": "http://x/a.whl",
                                                      "sha256": "0" * 64})
        with pytest.raises(catalog.CatalogError, match="https"):
            catalog.install("notion", run=run)
        with pytest.raises(catalog.CatalogError, match="does not list"):
            catalog.install("shopify", run=run)
        assert ran == []
