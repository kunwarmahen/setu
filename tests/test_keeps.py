"""`setu keeps`: where Setu keeps your accounts, for a backup.

The bias: A BACKUP THAT RESTORES HALF A SIGN-IN. Sarathi packs what
these places say and nothing else, so the failures designed against are
the folder resolved from the wrong place (SETU_HOME ignored), the Google
client file left behind on a Desktop, and the browser caches carried
(gigabytes, no sign-in) or a profile's own data left out with them.
"""

from __future__ import annotations

import json

from setu import config, keeps
from setu.cli import main


def _places():
    return {p["id"]: p for p in keeps.report()["keeps"]}


def test_the_folder_is_setu_home(tmp_path, monkeypatch):
    monkeypatch.setenv("SETU_HOME", str(tmp_path / "setu"))
    monkeypatch.delenv("SETU_GOOGLE_CLIENT_FILE", raising=False)
    places = _places()
    assert places["home"]["path"] == str(tmp_path / "setu")
    assert places["home"]["exists"] is False
    assert "google-client" not in places


def test_a_client_file_outside_the_folder_is_its_own_place(tmp_path, monkeypatch):
    monkeypatch.setenv("SETU_HOME", str(tmp_path / "setu"))
    (tmp_path / "client.json").write_text("{}")
    monkeypatch.setenv("SETU_GOOGLE_CLIENT_FILE", str(tmp_path / "client.json"))
    assert _places()["google-client"] == {
        "id": "google-client", "path": str(tmp_path / "client.json"),
        "what": "the Google client file Gmail sign-ins are made with",
        "leave_out": [], "exists": True}


def test_a_client_file_inside_the_folder_is_not_twice(tmp_path, monkeypatch):
    monkeypatch.setenv("SETU_HOME", str(tmp_path))
    monkeypatch.setenv("SETU_GOOGLE_CLIENT_FILE", str(tmp_path / "client.json"))
    assert "google-client" not in _places()
    assert config.google_client_file() == str(tmp_path / "client.json")


def test_caches_and_chromes_locks_are_left_out_never_a_profile(tmp_path, monkeypatch):
    monkeypatch.setenv("SETU_HOME", str(tmp_path))
    leave_out = _places()["home"]["leave_out"]
    assert {"Cache", "Code Cache", "Singleton*", "logs"} <= set(leave_out)
    assert not {"profiles", "vault.json", "Cookies", "Local Storage"} & set(leave_out)


def test_keeps_json_names_its_format(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SETU_HOME", str(tmp_path))
    assert main(["keeps", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["format"] == "setu.keeps.v1"


# -- a new home ---------------------------------------------------------------------
# The bias: EVERY SIGN-IN SIGNED OUT AFTER A RESTORE. The vault names each
# browser profile by its whole path; restored under another home, each one
# points at a folder that isn't there.


def _restored(tmp_path, monkeypatch):
    home = tmp_path / "new" / ".local" / "state" / "setu"
    home.mkdir(parents=True)
    old = "/home/old"
    (home / "vault.json").write_text(json.dumps({"connections": [
        {"ref": "amazon-personal", "profile": f"{old}/.local/state/setu/profiles/"
                                              "amazon-personal",
         "secret": {"sealed": "AAAA"}},
        {"ref": "work", "profile": "/media/usb/profiles/work"}]}))
    (home / "config.json").write_text(json.dumps({"google_client_file":
                                                  f"{old}/Desktop/client.json",
                                                  "level": "read"}))
    monkeypatch.setenv("SETU_HOME", str(home))
    return home, old


def test_a_restore_on_a_new_home_moves_setus_own_paths(tmp_path, monkeypatch):
    home, old = _restored(tmp_path, monkeypatch)
    new = str(tmp_path / "new")
    changed = keeps.rehome(old, new)
    assert [(r["file"].rsplit("/", 1)[1], r["paths"]) for r in changed] == [
        ("vault.json", 1), ("config.json", 1)]
    vault = json.loads((home / "vault.json").read_text())["connections"]
    assert vault[0]["profile"] == f"{new}/.local/state/setu/profiles/amazon-personal"
    assert vault[0]["secret"] == {"sealed": "AAAA"}             # sealed left as it was
    assert vault[1]["profile"] == "/media/usb/profiles/work"     # not under the old home
    assert json.loads((home / "config.json").read_text())["google_client_file"] == \
        f"{new}/Desktop/client.json"
    assert keeps.rehome(old, new) == []                          # twice is nothing


def test_rehome_from_the_command_line_and_said_in_keeps(tmp_path, monkeypatch, capsys):
    _, old = _restored(tmp_path, monkeypatch)
    assert keeps.report()["rehome"] is True
    assert main(["keeps", "--rehome", old, str(tmp_path / "new"), "--json"]) == 0
    assert [r["paths"] for r in json.loads(capsys.readouterr().out)["rehomed"]] == [1, 1]
    assert main(["keeps", "--rehome", "old", "new"]) == 2        # whole paths only
    assert "two whole paths" in capsys.readouterr().err
    # a folder that only starts with the same letters isn't under it
    assert keeps._moved({"p": "/home/older/x", "q": "/home/old"}, "/home/old", "/n") == (
        {"p": "/home/older/x", "q": "/n"}, 1)
