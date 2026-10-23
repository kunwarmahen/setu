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
