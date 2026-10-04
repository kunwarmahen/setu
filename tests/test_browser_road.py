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
* **A dropped file that runs a program, or shadows a real connector.** A
  site added by hand in ``sites/`` must be a browser road; an installed
  connector of the same id wins; a broken file is reported and skipped,
  never taking the installed connectors down with it.
"""

from __future__ import annotations

import re
import sqlite3
import tomllib
from pathlib import Path

import pytest
from setu import browser as site_browser
from setu import connections, status
from setu.cli import main
from setu.manifest import ManifestError, find, installed, parse
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
    conn.execute("create table if not exists cookies (host_key text, name text, "
                 "encrypted_value blob)")
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


SHOP_TOML = """
id = "shop"
name = "Shop"
road = "browser"
auth = "browser"
hosts = ["shop.test"]

[browser]
start_url = "https://www.shop.test/"
signed_in = ["sess*"]

[levels.read]
label = "Read only"

[verbs]
open = "read"
"""


def add_site(home: Path, name: str, text: str) -> Path:
    sites = home / "sites"
    sites.mkdir(parents=True, exist_ok=True)
    path = sites / name
    path.write_text(text)
    return path


class TestSitesAddedByHand:
    def test_a_file_in_sites_is_a_connector_made_here(self, home):
        add_site(home, "shop.toml", SHOP_TOML)
        shop = find("shop")
        assert shop.local and shop.browser.signed_in == ("sess*",)
        assert not find("amazon").local
        window, seen = a_person([(".shop.test", "sess-id")])
        entry = connections.connect_browser(shop, "personal", level=None, vault=FileVault(),
                                            browser="chrome", window=window)
        assert entry["connector"] == "shop" and seen["url"] == "https://www.shop.test/"

    def test_the_card_says_it_was_made_here_with_or_without_a_catalog(self, home):
        add_site(home, "shop.toml", SHOP_TOML)
        report = status.report()
        card = next(c for c in report["connectors"] if c["id"] == "shop")
        assert card["label"] == "local" and card["browser"]["start_url"]
        assert next(c for c in report["connectors"] if c["id"] == "amazon")["label"] is None

    def test_a_file_that_runs_a_program_is_refused(self, home):
        add_site(home, "tool.toml", 'id = "tool"\nname = "T"\nroad = "mcp"\nauth = "token"\n'
                 'command = ["rm", "-rf", "~"]\n[levels.read]\nlabel = "R"\n')
        problems: list[str] = []
        assert "tool" not in installed(problems)
        assert any("only a site reached through the browser" in p for p in problems)

    def test_an_installed_connector_of_the_same_id_wins(self, home):
        add_site(home, "amazon.toml", SHOP_TOML.replace('"shop"', '"amazon"'))
        problems: list[str] = []
        assert not installed(problems)["amazon"].local
        assert any("installed already" in p for p in problems)

    def test_a_file_named_for_another_id_is_skipped(self, home):
        add_site(home, "shopping.toml", SHOP_TOML)
        problems: list[str] = []
        assert "shop" not in installed(problems)
        assert any("name the file shop.toml" in p for p in problems)

    def test_a_broken_file_is_reported_and_the_rest_still_load(self, home, capsys):
        add_site(home, "bad.toml", "id = ")
        add_site(home, "shop.toml", SHOP_TOML)
        report = status.report()
        ids = {c["id"] for c in report["connectors"]}
        assert {"shop", "amazon", "x"} <= ids
        assert any("bad.toml" in p for p in report["problems"])
        assert main(["connectors"]) == 0
        out = capsys.readouterr()
        assert "Shop (added on this computer)" in out.out and "bad.toml" in out.err

    def test_the_readme_example_loads_as_written(self, home):
        readme = (Path(__file__).parent.parent / "README.md").read_text()
        block = re.search(r"```toml\n(# ~/.local/state/setu/sites/example.toml.*?)```",
                          readme, re.S)
        assert block is not None
        add_site(home, "example.toml", block.group(1))
        example = find("example")
        assert example.local and example.default_level.name == "read"
        assert tomllib.loads(block.group(1))["browser"]["headed"] is True


SIGNED_IN_PAGE = '<p>Hello, Ana</p><a href="/account/logout">Sign out</a>'
SIGNED_OUT_PAGE = '<a href="/login">Sign in</a><p>Welcome</p>'


def a_site(signed_in_rows, page, *, visitor_rows=(("www.example.com", "consent"),)):
    """The window and the headless look, for a site nobody wrote rules
    for: a signed-out visit gets ``visitor_rows``; the person's profile
    gets ``signed_in_rows``, and its page reads ``page``."""
    window, seen = a_person(list(visitor_rows) + list(signed_in_rows))
    looked = []

    def dump(browser, profile, url):
        looked.append((profile, url))
        if "setu-baseline-" in str(profile):
            write_cookies(profile, list(visitor_rows))
            return SIGNED_OUT_PAGE
        return page
    return window, dump, seen, looked


def site(address="example.com", **kw):
    kw.setdefault("level", None)
    return connections.connect_site(address, "personal", vault=FileVault(),
                                    browser="chrome", **kw)


class TestAnySite:
    def test_a_sign_in_the_page_shows_writes_the_sites_rules(self, home):
        window, dump, seen, looked = a_site([(".example.com", "session_id"),
                                             (".example.com", "_ga")], SIGNED_IN_PAGE)
        entry = site("https://www.example.com/whatever", window=window, dump=dump)
        assert seen["url"] == "https://www.example.com/"
        assert len(looked) == 3                       # two signed-out visits, one after
        manifest = find("example")
        assert manifest.local and manifest.generated
        assert manifest.hosts == ("example.com",)
        assert manifest.browser.signed_in == ("session_id",)   # evidence, not the noise
        assert "buy now" in manifest.browser.spend_words and manifest.browser.headed
        assert entry["level"] == "read" and FileVault().get("example:personal")
        card = next(c for c in status.report()["connectors"] if c["id"] == "example")
        assert card["label"] == "local"

    def test_a_page_still_showing_a_sign_in_leaves_nothing_behind(self, home):
        window, dump, _, _ = a_site([], SIGNED_OUT_PAGE)
        with pytest.raises(connections.ConnectionFailed, match="still shows a sign-in"):
            site(window=window, dump=dump)
        assert not (home / "sites" / "example.toml").exists()
        assert not (home / "profiles" / "example-personal").exists()
        assert FileVault().get("example:personal") is None

    def test_a_page_that_cannot_tell_is_the_persons_to_answer(self, home):
        window, dump, _, _ = a_site([], "<p>a page with nothing to go on</p>")
        with pytest.raises(connections.ConnectionFailed, match="could not tell"):
            site(window=window, dump=dump)                   # nobody to ask: no
        asked = []
        with pytest.raises(connections.ConnectionFailed):
            site(window=window, dump=dump, ask=lambda q: asked.append(q) or False)
        assert "Did you sign in?" in asked[0]
        entry = site(window=window, dump=dump, ask=lambda q: True)
        assert entry["connector"] == "example" and find("example").browser.signed_in == ()

    def test_a_site_setu_already_has_is_pointed_at_its_connector(self, home):
        window, dump, _, _ = a_site([], SIGNED_IN_PAGE)
        with pytest.raises(connections.ConnectionFailed, match="setu connect amazon"):
            site("amazon.in", window=window, dump=dump)
        with pytest.raises(connections.ConnectionFailed, match="setu connect amazon"):
            site("smile.amazon.com", window=window, dump=dump)

    def test_money_stays_read_only_whatever_was_asked(self, home):
        window, dump, _, _ = a_site([], SIGNED_IN_PAGE.replace("<p>", "<title>My Bank</title><p>"))
        entry = site("mybank-online.com", level="write", window=window, dump=dump)
        assert entry["level"] == "read" and "bank" in entry["note"]
        window, dump, _, _ = a_site([], SIGNED_IN_PAGE)
        assert site("recipes.example.org", level="write", window=window,
                    dump=dump)["level"] == "write"

    def test_signing_in_again_keeps_the_persons_edits(self, home):
        window, dump, _, _ = a_site([], SIGNED_IN_PAGE)
        site(window=window, dump=dump)
        path = home / "sites" / "example.toml"
        path.write_text(path.read_text().replace('guide = ""', 'guide = "orders: /orders"'))
        site(window=window, dump=dump, level="write")
        assert find("example").browser.guide == "orders: /orders"
        assert FileVault().get("example:personal")["level"] == "write"

    def test_names_come_from_the_address(self):
        from setu import sites
        assert sites.name_of("www.example.com") == ("example", "example.com")
        assert sites.name_of("news.ycombinator.com") == ("ycombinator", "ycombinator.com")
        assert sites.name_of("www.bbc.co.uk") == ("bbc", "bbc.co.uk")
        with pytest.raises(sites.SiteError):
            sites.draft("not an address")
        assert sites.draft("example.com", "my-shop")["id"] == "my-shop"

    def test_only_a_site_setu_wrote_may_leave_signed_in_to_the_page(self):
        bare = {**BASE, "browser": {**BASE["browser"], "signed_in": []}}
        with pytest.raises(ManifestError, match="signed_in"):
            parse(bare)
        assert parse({**bare, "generated": True}).generated

    def test_the_page_check_never_says_in_beside_a_password_box(self):
        assert site_browser.page_state('<a href="/logout">x</a>') == "in"
        assert site_browser.page_state('<a href="/logout">x</a><input type="password">') == "out"
        assert site_browser.page_state('<script>"<a>Sign out</a>"</script><p>hi</p>') == "unknown"
        assert site_browser.page_state("") == "unknown"

    def test_json_asks_with_an_event_and_reads_the_answer(self, home, monkeypatch, capsys):
        import io
        import json as jsonlib
        window, dump, _, _ = a_site([], "<p>nothing to go on</p>")
        real = connections.connect_site
        monkeypatch.setattr(connections, "connect_site",
                            lambda *a, **kw: real(*a, **kw, window=window, dump=dump))
        monkeypatch.setattr(site_browser, "find_browser", lambda explicit=None: "chrome")
        monkeypatch.setattr("sys.stdin", io.StringIO("yes\n"))
        assert main(["connect", "--site", "example.com", "--json"]) == 0
        events = [jsonlib.loads(line) for line in capsys.readouterr().out.splitlines()]
        kinds = [e["event"] for e in events]
        assert kinds[:2] == ["started", "window"] and "ask" in kinds
        assert events[-1]["event"] == "connected" and events[-1]["ref"] == "example:personal"


class TestTheGuideGrows:
    def connected(self, home):
        window, dump, _, _ = a_site([], SIGNED_IN_PAGE)
        site(window=window, dump=dump)
        return home / "sites" / "example.toml"

    def test_a_guide_replaces_the_line_and_keeps_the_rest(self, home, capsys):
        path = self.connected(home)
        path.write_text("# my note: keep this\n" + path.read_text())
        assert main(["site", "guide", "example", "--set",
                     'Orders: /account/orders\nSearch: /s?q="WORDS"']) == 0
        assert find("example").browser.guide == 'Orders: /account/orders\nSearch: /s?q="WORDS"'
        assert path.read_text().startswith("# my note: keep this")
        capsys.readouterr()
        assert main(["site", "guide", "example"]) == 0
        assert "Orders: /account/orders" in capsys.readouterr().out

    def test_an_installed_connectors_guide_is_not_setus_to_write(self, home, capsys):
        assert main(["site", "guide", "amazon", "--set", "x"]) == 2
        assert "not a site added on this computer" in capsys.readouterr().err

    def test_a_guide_written_by_hand_across_lines_is_left_alone(self, home):
        from setu import sites
        path = self.connected(home)
        path.write_text(path.read_text().replace('guide = ""', 'guide = """\nmine\n"""'))
        with pytest.raises(sites.SiteError, match="written by hand"):
            sites.set_guide("example", "theirs")
        assert find("example").browser.guide == "mine"

    def test_a_file_with_no_guide_line_gets_one(self, home):
        from setu import sites
        add_site(home, "shop.toml", SHOP_TOML)
        assert sites.set_guide("shop", "Cart: /cart").browser.guide == "Cart: /cart"
        assert find("shop").browser.signed_in == ("sess*",)


class TestLastUsed:
    def test_the_profile_says_when_it_was_last_used(self, home):
        import os
        import time
        entry = connected(home)
        profile = Path(entry["profile"])
        (profile / "Default").mkdir(parents=True, exist_ok=True)
        history = profile / "Default" / "History"
        history.write_text("")
        signed = time.time()
        os.utime(history, (signed, signed))
        assert connections.last_used(entry) is None          # the sign-in's own write
        later = signed + 3600
        os.utime(history, (later, later))
        assert connections.last_used(entry) is not None
        row = next(r for r in status.report()["connections"] if r["ref"] == "x:personal")
        assert row["last_used"] == connections.last_used(entry)

    def test_a_token_connection_keeps_its_stamp(self):
        assert connections.last_used({"auth": "google",
                                      "last_used": "2026-10-01T00:00:00Z"}) \
            == "2026-10-01T00:00:00Z"


class TestHealth:
    """A week of what went wrong, per browser connection (health.py)."""

    def test_events_are_counted_and_shown(self, home, capsys):
        connected(home)
        for kind in ("robot_check", "robot_check", "signed_out"):
            assert main(["site", "event", "x:personal", kind]) == 0
        row = next(r for r in status.report()["connections"] if r["ref"] == "x:personal")
        assert row["health"]["counts"] == {"robot_check": 2, "signed_out": 1}
        capsys.readouterr()
        assert main(["list"]) == 0
        assert "robot check 2×, signed out 1× this week" in capsys.readouterr().out

    def test_older_than_a_week_is_dropped(self, home):
        from setu import health
        health.record("x:personal", "limit", now=1_000_000.0)
        health.record("x:personal", "handoff", now=1_000_000.0 + health.WEEK + 1)
        assert health.week("x:personal", now=1_000_000.0 + health.WEEK + 2)["counts"] \
            == {"handoff": 1}

    def test_unknown_kinds_and_connections_are_refused(self, home, capsys):
        connected(home)
        assert main(["site", "event", "x:personal", "page_text"]) == 2
        assert main(["site", "event", "nobody:here", "limit"]) == 2

    def test_a_broken_file_is_an_empty_record(self, home):
        from setu import health
        health.path().parent.mkdir(parents=True, exist_ok=True)
        health.path().write_text("{not json")
        assert health.week("x:personal") == {}
        health.record("x:personal", "limit")
        assert health.week("x:personal")["counts"] == {"limit": 1}

    def test_disconnect_forgets_it(self, home):
        from setu import health
        connected(home)
        health.record("x:personal", "limit")
        assert main(["disconnect", "x:personal"]) == 0
        assert health.week("x:personal") == {}
