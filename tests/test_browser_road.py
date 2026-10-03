"""The browser road: a site with no API, signed in to in a window of its own.

The bias is A CLOSED WINDOW IS NOT A SIGN-IN. A person can close the
window before signing in, and the profile still fills with cookies --
so these tests demand that only the manifest's sign-in cookie names
count, and that nothing is saved without one.

Also designed against:

* **A manifest that cannot say where it may go** -- no hosts, no sign-in
  cookie, a click classed as a read: refused when it is read.
* **A browser road mistaken for a server.** It has no program; ``setu
  run`` and ``mcp-config`` say so, and the status report carries no
  ``mcp`` for it, so a harness starts nothing.
* **A disconnect that deletes the wrong directory.** Only a profile under
  Setu's own ``profiles/`` is ever removed, whatever the vault says.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from setu import browser as site_browser
from setu import connections, status
from setu.cli import main
from setu.manifest import ManifestError, find, parse
from setu.vault import FileVault

BASE = {
    "id": "shop", "name": "Shop", "road": "browser", "auth": "browser",
    "hosts": ["shop.test"],
    "browser": {"start_url": "https://www.shop.test/", "signed_in": ["at-*"]},
    "levels": {"read": {"label": "Read only"}, "write": {"label": "Read and act"}},
    "verbs": {"open": "read", "click": "write"},
}


def write_cookies(profile: Path, rows: list[tuple[str, str]]) -> None:
    """A Chromium cookie store with these (host, name) rows -- values are
    never read, so none are written."""
    (profile / "Default").mkdir(parents=True, exist_ok=True)
    (profile / "Local State").write_text("{}")
    conn = sqlite3.connect(profile / "Default" / "Cookies")
    conn.execute("create table cookies (host_key text, name text, encrypted_value blob)")
    conn.executemany("insert into cookies values (?, ?, x'00')", rows)
    conn.commit()
    conn.close()


def a_person(rows: list[tuple[str, str]]):
    """The window, and what the person did in it before closing it."""
    seen = {}

    def window(browser: str, profile: Path, url: str) -> None:
        seen.update(browser=browser, profile=profile, url=url)
        write_cookies(profile, rows)
    return window, seen


class TestTheManifest:
    def test_a_browser_road_needs_no_program(self):
        manifest = parse(BASE)
        assert manifest.command == ()
        assert manifest.browser.login_url == "https://www.shop.test/"

    @pytest.mark.parametrize("change, said", [
        ({"hosts": []}, "hosts"),
        ({"browser": {"start_url": "https://www.shop.test/"}}, "signed_in"),
        ({"verbs": {"click": "read"}}, "never read"),
        ({"verbs": {"buy": "spend"}}, "not a browser tool"),
        ({"levels": {"full": {}}}, "read and write"),
        ({"auth": "homeassistant"}, "auth"),
    ])
    def test_one_that_cannot_say_where_it_goes_is_refused(self, change, said):
        with pytest.raises(ManifestError, match=said):
            parse({**BASE, **change})

    def test_a_browser_table_on_another_road_is_refused(self):
        with pytest.raises(ManifestError, match="belongs to"):
            parse({**BASE, "road": "api", "auth": "homeassistant", "command": ["x"]})

    def test_amazon_and_x_are_installed_and_keep_buying_to_the_person(self):
        amazon, x = find("amazon"), find("x")
        assert "buy now" in amazon.browser.spend_words
        assert "/gp/buy/*" in amazon.browser.spend_pages
        assert x.browser.pace >= 3 and x.browser.max_actions <= 10
        for manifest in (amazon, x):
            assert manifest.default_level.name == "read"
            assert manifest.verb("click") == "write" and manifest.verb("open") == "read"


class TestSigningIn:
    def test_a_sign_in_cookie_makes_a_connection(self, home):
        window, seen = a_person([(".amazon.in", "session-id"), (".amazon.in", "at-acbin")])
        entry = connections.connect_browser(find("amazon"), "personal", level=None,
                                            vault=FileVault(), browser="/usr/bin/chrome",
                                            window=window)
        assert seen["url"] == "https://www.amazon.com/gp/css/order-history"
        assert seen["profile"] == home / "profiles" / "amazon-personal"
        assert entry["home"] == "https://www.amazon.in/"     # the store signed in to
        assert entry["browser"] == "/usr/bin/chrome" and entry["level"] == "read"
        assert entry["secret"] == {}

    def test_a_window_closed_before_signing_in_saves_nothing(self, home):
        window, _ = a_person([(".amazon.com", "session-id"), (".amazon.com", "ubid-main")])
        with pytest.raises(connections.ConnectionFailed, match="not signed you in"):
            connections.connect_browser(find("amazon"), "personal", level=None,
                                        vault=FileVault(), browser="chrome", window=window)
        assert FileVault().get("amazon:personal") is None

    def test_a_sign_in_cookie_of_another_site_does_not_count(self, home):
        window, _ = a_person([(".evil.test", "auth_token")])
        with pytest.raises(connections.ConnectionFailed):
            connections.connect_browser(find("x"), "personal", level=None,
                                        vault=FileVault(), browser="chrome", window=window)

    def test_a_browser_that_wrote_nothing_is_said_loudly(self, home, tmp_path):
        class Done:
            def wait(self):
                return 0
        with pytest.raises(site_browser.BrowserSignInFailed, match="without writing"):
            site_browser.window("chrome", tmp_path / "p", "https://x.com/",
                                popen=lambda argv, **kw: Done())

    def test_the_window_is_plain_and_names_the_cookie_key(self, home, tmp_path):
        seen = {}

        class Done:
            def wait(self):
                write_cookies(tmp_path / "p", [])
                return 0

        def popen(argv, **kw):
            seen.update(argv=argv, kw=kw)
            return Done()
        site_browser.window("chrome", tmp_path / "p", "https://x.com/", popen=popen)
        assert "--password-store=basic" in seen["argv"]
        assert f"--user-data-dir={tmp_path / 'p'}" in seen["argv"]
        assert seen["kw"]["start_new_session"] is True
        assert (tmp_path / "p").stat().st_mode & 0o777 == 0o700


def connected(home, connector="x", rows=((".x.com", "auth_token"),)):
    window, _ = a_person(list(rows))
    return connections.connect_browser(find(connector), "personal", level="write",
                                       vault=FileVault(), browser="chrome", window=window)


class TestWhatAHarnessIsTold:
    def test_no_server_and_the_profile_to_open(self, home):
        connected(home)
        report = status.report()
        row = next(r for r in report["connections"] if r["ref"] == "x:personal")
        assert row["mcp"] is None
        assert row["browser"]["profile"].endswith("profiles/x-personal")
        assert row["browser"]["home"] == "https://x.com/home"
        card = next(c for c in report["connectors"] if c["id"] == "x")
        assert card["browser"]["pace"] == 3.0 and "delete" in card["browser"]["spend_words"]
        assert card["road"] == "browser"

    def test_no_browser_anywhere_is_not_ready(self, home, monkeypatch):
        monkeypatch.setattr(site_browser, "find_browser", lambda explicit=None: None)
        card = next(c for c in status.report()["connectors"] if c["id"] == "amazon")
        assert not card["ready"] and card["needs_setup"] == "browser"

    def test_run_and_mcp_config_say_there_is_no_server(self, home, capsys):
        connected(home)
        assert main(["run", "x:personal"]) == 2
        assert main(["mcp-config", "x:personal"]) == 2
        assert "no server" in capsys.readouterr().err

    def test_there_is_no_token_to_hand_out(self, home):
        connected(home)
        with pytest.raises(connections.ConnectionFailed, match="browser profile"):
            connections.token("x:personal", vault=FileVault(), http=None)


class TestSigningOut:
    def test_disconnect_deletes_the_profile(self, home, capsys):
        entry = connected(home)
        assert Path(entry["profile"]).exists()
        assert main(["disconnect", "x:personal"]) == 0
        assert not Path(entry["profile"]).exists()
        assert FileVault().get("x:personal") is None
        assert "signed out" in capsys.readouterr().out

    def test_only_a_profile_under_setus_own_directory_is_removed(self, home, tmp_path):
        outside = tmp_path / "precious"
        outside.mkdir()
        assert site_browser.remove_profile(outside) is False
        assert outside.exists()
        assert site_browser.remove_profile(home / "profiles" / ".." / ".." / "precious") is False
        assert outside.exists()
