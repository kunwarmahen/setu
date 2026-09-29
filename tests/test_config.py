"""Remembering the client file, and signing in for a harness's page.

The bias is A PAGE THAT GUESSES. A harness drives ``setu connect --json``
from a web page and must never scrape prose to learn the sign-in address
or whether it worked -- every step is one JSON line, and every failure
is one too, never a traceback. And the remembered setting must stay a
PATH: the client file holds a client secret, so it is read at connect
time and never copied into anything Setu keeps.

Also designed against: a wrong file remembered today and discovered at
sign-in next week. A Web client, or a missing file, is refused when it
is set.
"""

from __future__ import annotations

import json

import pytest
from setu import cli, config
from setu.status import report


def desktop(tmp_path, name="client.json"):
    path = tmp_path / name
    path.write_text(json.dumps({"installed": {"client_id": "cid", "client_secret": "shh"}}))
    return path


def lines(capsys) -> list[dict]:
    return [json.loads(line) for line in capsys.readouterr().out.splitlines() if line]


class TestRemembering:
    def test_the_path_is_remembered_and_the_file_is_not_copied(self, home, tmp_path):
        path = desktop(tmp_path)
        assert cli.main(["config", "client-file", str(path)]) == 0
        assert config.google_client_file() == str(path)
        saved = (home / config.CONFIG_FILE).read_text()
        assert "shh" not in saved and str(path) in saved

    def test_a_web_client_is_refused_when_it_is_set(self, home, tmp_path, capsys):
        path = tmp_path / "web.json"
        path.write_text(json.dumps({"web": {"client_id": "x", "client_secret": "y"}}))
        assert cli.main(["config", "client-file", str(path)]) == 2
        assert "Desktop app" in capsys.readouterr().err
        assert config.google_client_file() is None

    def test_the_flag_beats_the_environment_beats_the_file(self, home, tmp_path, monkeypatch):
        config.save("google_client_file", "/remembered.json")
        assert config.google_client_file() == "/remembered.json"
        monkeypatch.setenv(config.ENV_CLIENT_FILE, "/from-env.json")
        assert config.google_client_file() == "/from-env.json"
        assert config.google_client_file("/flag.json") == "/flag.json"

    def test_unset_forgets_it(self, home, tmp_path):
        cli.main(["config", "client-file", str(desktop(tmp_path))])
        cli.main(["config", "client-file", "--unset"])
        assert config.google_client_file() is None

    def test_the_report_says_whether_a_sign_in_can_start(self, home, tmp_path):
        gmail = next(c for c in report()["connectors"] if c["id"] == "gmail")
        assert gmail["ready"] is False and "client-file" in gmail["not_ready"]
        cli.main(["config", "client-file", str(desktop(tmp_path))])
        data = report()
        gmail = next(c for c in data["connectors"] if c["id"] == "gmail")
        assert gmail["ready"] is True and gmail["not_ready"] == ""
        assert data["setup"]["google_client_file"].endswith("client.json")

    def test_a_broken_config_is_a_problem_not_an_empty_one(self, home):
        home.mkdir(parents=True, exist_ok=True)
        (home / config.CONFIG_FILE).write_text("{not json")
        assert any("not valid JSON" in p for p in report()["problems"])


class TestConnectForAPage:
    def test_the_sign_in_is_three_lines_of_json(self, home, tmp_path, monkeypatch, capsys):
        cli.main(["config", "client-file", str(desktop(tmp_path))])
        capsys.readouterr()
        seen = {}

        def connect(manifest, account, *, level, client, vault, http,
                    open_browser, on_url, **_):
            seen["open_browser"] = open_browser
            on_url("https://accounts.google.com/o/oauth2/auth?x=1")
            return {"connector": "gmail", "account": account, "email": "me@example.com",
                    "level": level, "asked_level": level}

        monkeypatch.setattr(cli.connections, "connect", connect)
        assert cli.main(["connect", "gmail", "--as", "work", "--json"]) == 0
        events = lines(capsys)
        assert [e["event"] for e in events] == ["started", "url", "connected"]
        assert events[0]["ref"] == "gmail:work" and events[0]["level"] == "read"
        assert events[1]["url"].startswith("https://accounts.google.com/")
        assert events[2]["email"] == "me@example.com"
        assert seen["open_browser"] is None      # the page opens it, not Setu

    def test_no_client_file_is_an_error_line_that_names_the_fix(self, home, capsys):
        assert cli.main(["connect", "gmail", "--json"]) == 2
        (event,) = lines(capsys)
        assert event["event"] == "error" and event["setup"] == "google_client_file"

    def test_any_failure_is_a_line_never_a_traceback(self, home, tmp_path, monkeypatch,
                                                     capsys):
        cli.main(["config", "client-file", str(desktop(tmp_path))])
        capsys.readouterr()

        def boom(*_a, **_k):
            raise RuntimeError("the redirect never came")

        monkeypatch.setattr(cli.connections, "connect", boom)
        assert cli.main(["connect", "gmail", "--json"]) == 2
        events = lines(capsys)
        assert events[-1] == {"event": "error", "message": "the redirect never came"}

    @pytest.mark.parametrize("level", ["nonsense"])
    def test_an_unknown_level_is_an_error_line(self, home, tmp_path, capsys, level):
        cli.main(["config", "client-file", str(desktop(tmp_path))])
        capsys.readouterr()
        assert cli.main(["connect", "gmail", "--level", level, "--json"]) == 2
        assert lines(capsys)[-1]["event"] == "error"
