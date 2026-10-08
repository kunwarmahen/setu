"""A person's own page: a one-time link, a session, their folder alone.

The bias is A LINK THAT OPENS MORE THAN ONE FOLDER, OR OPENS IT TWICE.
The link travels through a chat, where it can be read later, forwarded,
or guessed at; the server is shared with the owner, whose folder holds
their own sign-ins. So the tests claim a link twice, late, for a folder
that walks out of the people's place, and with a person's session ask
for the owner's parts -- and switch people's pages off under a session
that is already open.
"""

from __future__ import annotations

import json
import stat
import sys

import httpx
import pytest
from setu import config, page, people
from setu.cli import main
from setu.vault import FileVault

OWNER = "the-owners-page-token-1234"


@pytest.fixture
def place(tmp_path, home):
    """People's folders, one of them Asha's with a connection, and the
    owner's own folder (``home``) with another."""
    root = tmp_path / "people"
    asha = root / "asha"
    asha.mkdir(parents=True)
    FileVault(asha).put("gmail:personal", {
        "connector": "gmail", "account": "personal", "email": "asha@example.com",
        "level": "read", "secret": {"refresh_token": "asha-secret"}})
    FileVault(home).put("gmail:owner", {
        "connector": "gmail", "account": "owner", "email": "owner@example.com",
        "level": "send", "secret": {"refresh_token": "owner-secret"}})
    return root


@pytest.fixture
def served(place):
    server = page.PageServer(page.Api(FileVault()), OWNER, port=0, people_dir=place)
    server.start()
    yield server
    server.stop()


def call(server, path, token=None, body=None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    url = server.url.rstrip("/") + path
    if body is None:
        return httpx.get(url, headers=headers, timeout=5)
    return httpx.post(url, headers=headers, json=body, timeout=5)


def claim(server, link):
    return call(server, "/api/people/claim", body={"link": link})


def test_a_link_opens_the_persons_own_folder_and_nobody_elses(served, place):
    link, _ = people.make_link(place / "asha")
    res = claim(served, link)
    assert res.status_code == 200
    token = res.json()["token"]
    rows = call(served, "/api/connections", token).json()["connections"]
    assert [r["ref"] for r in rows] == ["gmail:personal"]
    assert "owner@example.com" not in call(served, "/api/connections", token).text
    st = call(served, "/api/status", token).json()
    assert st["person"] == "asha" and str(place) not in json.dumps(st)


def test_a_link_works_once(served, place):
    link, _ = people.make_link(place / "asha")
    assert claim(served, link).status_code == 200
    second = claim(served, link)
    assert second.status_code == 403 and "used" in second.json()["detail"]


def test_a_link_works_for_ten_minutes(place):
    link, expires = people.make_link(place / "asha", now=1000.0)
    assert expires == 1000.0 + people.LINK_SECONDS
    with pytest.raises(people.PeopleError, match="ten minutes"):
        people.claim(place, link, now=expires + 1)
    with pytest.raises(people.PeopleError):          # and late is still used up
        people.claim(place, link, now=1001.0)


def test_a_new_link_replaces_one_not_yet_used(place):
    old, _ = people.make_link(place / "asha")
    new, _ = people.make_link(place / "asha")
    with pytest.raises(people.PeopleError):
        people.claim(place, old)
    assert people.claim(place, new)[0] == "asha"


@pytest.mark.parametrize("link", ["../asha.x", "asha", ".x", "nobody.abc", "asha/..",
                                  "", "..%2f.abc"])
def test_a_link_that_names_no_folder_of_theirs_is_nobody(served, place, link):
    assert claim(served, link).status_code == 403


def test_sessions_and_links_are_kept_only_as_hashes_for_the_owner_alone(served, place):
    link, _ = people.make_link(place / "asha")
    token = claim(served, link).json()["token"]
    kept = (place / "asha" / people.SESSIONS_FILE).read_text()
    assert token.split(".", 2)[2] not in kept
    assert stat.S_IMODE((place / "asha" / people.SESSIONS_FILE).stat().st_mode) == 0o600


def test_a_persons_page_has_none_of_the_owners_parts(served, place):
    link, _ = people.make_link(place / "asha")
    token = claim(served, link).json()["token"]
    for path in ("/api/catalog", "/api/certifiers", "/api/settings"):
        assert call(served, path, token).status_code == 403
    for path, body in (("/api/install", {"connector": "gmail", "sha256": "x"}),
                       ("/api/settings", {"name": "people-page", "value": "on"}),
                       ("/api/add-site", {"site": "example.com"}),
                       ("/api/certifiers/remove", {"id": "x"})):
        assert call(served, path, token, body).status_code == 403


def test_a_session_cannot_be_turned_into_another_persons(served, place):
    (place / "ravi").mkdir()
    link, _ = people.make_link(place / "asha")
    token = claim(served, link).json()["token"]
    forged = token.replace("p.asha.", "p.ravi.")
    assert call(served, "/api/connections", forged).status_code == 401


def test_the_owners_switch_turns_every_persons_page_off_at_once(served, place, home):
    link, _ = people.make_link(place / "asha")
    token = claim(served, link).json()["token"]
    config.save("people_page", "off")
    res = call(served, "/api/connections", token)
    assert res.status_code == 403 and "turned this page off" in res.json()["detail"]
    fresh, _ = people.make_link(place / "asha")
    assert claim(served, fresh).status_code == 403
    assert call(served, "/api/connections", OWNER).status_code == 200   # not the owner's
    config.save("people_page", None)
    assert call(served, "/api/connections", token).status_code == 200


def test_closing_the_page_ends_that_session_only(served, place):
    tokens = []
    for _ in range(2):
        link, _ = people.make_link(place / "asha")
        tokens.append(claim(served, link).json()["token"])
    assert call(served, "/api/session/close", tokens[0], {}).status_code == 200
    assert call(served, "/api/status", tokens[0]).status_code == 401
    assert call(served, "/api/status", tokens[1]).status_code == 200
    assert people.close_all(place / "asha") == 1
    assert call(served, "/api/status", tokens[1]).status_code == 401


def test_without_a_people_folder_there_are_no_peoples_pages(home, place):
    server = page.PageServer(page.Api(FileVault()), OWNER, port=0)
    server.start()
    try:
        link, _ = people.make_link(place / "asha")
        assert claim(server, link).status_code == 404
    finally:
        server.stop()


def test_a_persons_sign_in_runs_in_their_folder(place, tmp_path, monkeypatch):
    script = tmp_path / "env.py"
    script.write_text("import json, os, sys\n"
                      "open(sys.argv[0] + '.env', 'w').write(json.dumps("
                      "{k: os.environ.get(k) for k in ('SETU_HOME', 'SETU_VAULT_KEY')}))\n"
                      "print('disconnected')\n")
    monkeypatch.setenv("SETU_VAULT_KEY", "the-owners-key")
    monkeypatch.setenv("SETU_GOOGLE_CLIENT_FILE", str(tmp_path / "client.json"))
    api = page.Api.for_person("asha", place / "asha", [sys.executable, str(script)])
    api.handle("POST", "/api/disconnect", {}, {"ref": "gmail:personal"})
    seen = json.loads((tmp_path / "env.py.env").read_text())
    assert seen == {"SETU_HOME": str(place / "asha"), "SETU_VAULT_KEY": None}


def test_page_link_prints_a_link_for_this_folder(place, monkeypatch, capsys):
    monkeypatch.setenv("SETU_HOME", str(place / "asha"))
    monkeypatch.delenv("SETU_PAGE_URL", raising=False)
    monkeypatch.delenv("SETU_WINDOW_HOST", raising=False)
    assert main(["page-link", "--json"]) == 2               # nowhere a phone could open
    assert "SETU_PAGE_URL" in capsys.readouterr().err
    monkeypatch.setenv("SETU_WINDOW_HOST", "100.64.0.7")
    assert main(["page-link", "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["person"] == "asha"
    assert out["url"].startswith("http://100.64.0.7:8775/#link=asha.")
    assert people.claim(place, out["url"].split("#link=")[1])[0] == "asha"


def test_a_people_folder_not_made_yet_is_nobody_yet(tmp_path):
    assert page.people_dir(str(tmp_path / "later")) == (tmp_path / "later").resolve()
    (tmp_path / "file").write_text("x")
    with pytest.raises(ValueError):
        page.people_dir(str(tmp_path / "file"))


PHONE = ("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
         "(KHTML, like Gecko) Chrome/155.0.0.0 Mobile Safari/537.36")


def test_the_owner_sees_who_has_a_page_open_and_no_key(served, place):
    (place / "ravi").mkdir()
    link, _ = people.make_link(place / "asha")
    res = httpx.post(served.url + "api/people/claim", json={"link": link},
                     headers={"User-Agent": PHONE}, timeout=5)
    secret = res.json()["token"].rsplit(".", 1)[1]
    people.make_link(place / "ravi")
    listed = call(served, "/api/people", OWNER)
    assert listed.status_code == 200
    data = listed.json()
    assert data["served"] and data["on"]
    asha, ravi = data["people"]
    assert asha["person"] == "asha" and asha["link"] is None
    assert [p["device"] for p in asha["pages"]] == ["Android · Chrome"]
    assert asha["pages"][0]["since"]
    assert ravi["pages"] == [] and ravi["link"]["expires_at"]
    kept = (place / "asha" / people.SESSIONS_FILE).read_text()
    assert secret not in listed.text and json.loads(kept)[0]["sha256"] not in listed.text


def test_a_person_can_neither_list_nor_close_anybodys_pages(served, place):
    link, _ = people.make_link(place / "asha")
    token = claim(served, link).json()["token"]
    for res in (call(served, "/api/people", token),
                call(served, "/api/people/close", token, {"person": "asha"})):
        assert res.status_code == 403 and "owner's" in res.json()["detail"]
    assert call(served, "/api/status", token).status_code == 200


def test_the_owner_closes_one_persons_pages_and_nobody_elses(served, place):
    (place / "ravi").mkdir()
    asha = claim(served, people.make_link(place / "asha")[0]).json()["token"]
    ravi = claim(served, people.make_link(place / "ravi")[0]).json()["token"]
    done = call(served, "/api/people/close", OWNER, {"person": "asha"})
    assert done.json() == {"person": "asha", "closed": 1}
    assert call(served, "/api/status", asha).status_code == 401
    assert call(served, "/api/status", ravi).status_code == 200
    for nobody in ("../asha", "zed"):
        assert call(served, "/api/people/close", OWNER, {"person": nobody}).status_code == 404


def test_with_no_people_folder_the_list_says_so(home):
    server = page.PageServer(page.Api(FileVault()), OWNER, port=0)
    server.start()
    try:
        assert call(server, "/api/people", OWNER).json() == {
            "served": False, "on": False, "people": []}
    finally:
        server.stop()


IPHONE = ("Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 "
          "(KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1")


def test_a_long_user_agent_keeps_the_browser_s_name(served, place):
    """Safari names itself past the 120th character: kept to 120, an
    iPhone listed as plain "iPhone"."""
    link, _ = people.make_link(place / "asha")
    httpx.post(served.url + "api/people/claim", json={"link": link},
               headers={"User-Agent": IPHONE}, timeout=5)
    listed = call(served, "/api/people", OWNER).json()["people"]
    assert listed[0]["pages"][0]["device"] == "iPhone · Safari"


@pytest.mark.parametrize("agent, said", [
    (PHONE, "Android · Chrome"),
    (IPHONE, "iPhone · Safari"),
    ("Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
     "Linux · Firefox"),
    ("", "a device that didn't say"),
])
def test_a_device_is_named_in_two_words(agent, said):
    assert people.device_name(agent) == said
