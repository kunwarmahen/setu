"""The phone road: a site's own app on the person's phone, at a level.

The bias is A CONNECTION THAT HOLDS NOTHING STILL SAYS WHAT MAY BE DONE.
The sign-in is the app's, on the phone, so Setu keeps no key and no
profile -- but the level the person chose, the words in the app that
act, and the ones that spend must reach the harness working the phone,
or the phone road is a way round every rule the browser road keeps.

Also designed against:

* **A [phone] table that names no app**, or a level a phone can't keep:
  refused when the manifest is read.
* **A phone connection mistaken for a server or a token.** ``setu run``,
  ``mcp-config`` and ``token`` say so; the status report carries no
  ``mcp`` and no ``browser`` for it.
* **Spend words forgotten on the phone.** With none of its own, the
  app's list is the browser's.
"""

from __future__ import annotations

import pytest
from setu import connections, status
from setu.cli import main
from setu.manifest import ManifestError, find, parse
from setu.vault import FileVault

BASE = {
    "id": "shop", "name": "Shop", "road": "browser", "auth": "browser",
    "hosts": ["shop.test"],
    "browser": {"start_url": "https://www.shop.test/", "signed_in": ["at-*"],
                "spend_words": ["buy now"], "pace": 2.5},
    "levels": {"read": {"label": "Read only"}, "write": {"label": "Read and act"}},
    "verbs": {"open": "read", "click": "write"},
    "phone": {"android": "com.shop.app", "act_words": ["Add to cart"]},
}


class TestTheManifest:
    def test_the_app_and_its_words_and_the_browsers_spend_words_and_pace(self):
        phone = parse(BASE).phone
        assert phone.android == "com.shop.app" and phone.act_words == ("add to cart",)
        assert phone.spend_words == ("buy now",) and phone.pace == 2.5

    @pytest.mark.parametrize("change,said", [
        ({"phone": {"act_words": ["post"]}}, "names the app"),
        ({"phone": {"android": "not a package"}}, "not an app's package name"),
        ({"phone": {"android": "com.shop.app", "colour": "red"}}, "unknown [phone] key"),
        ({"levels": {"read": {"label": "R"}, "control": {"label": "C"}}},
         "levels are read and write"),
    ])
    def test_one_that_cannot_say_which_app_or_what_level_is_refused(self, change, said):
        with pytest.raises(ManifestError, match=said.replace("[", r"\[")):
            parse({**BASE, **change})

    def test_x_and_amazon_name_their_apps(self):
        x, amazon = find("x").phone, find("amazon").phone
        assert x.android == "com.twitter.android" and "like" in x.act_words
        assert "delete" in x.spend_words and x.pace == 3.0
        assert amazon.android == "com.amazon.mShop.android.shopping"
        assert "add to cart" in amazon.act_words and "buy now" in amazon.spend_words


def phone_connected(home, connector="x", level=None):
    return connections.connect_phone(find(connector), "personal", level=level,
                                     vault=FileVault())


class TestTheConnection:
    def test_it_holds_the_app_and_the_level_and_nothing_secret(self, home):
        entry = phone_connected(home, level="write")
        assert entry["auth"] == "phone" and entry["level"] == "write"
        assert entry["phone"] == {"android": "com.twitter.android",
                                  "ios": "com.atebits.Tweetie2"}
        assert entry["secret"] == {} and "profile" not in entry

    def test_the_report_carries_the_app_and_the_rules_never_a_server(self, home):
        phone_connected(home)
        report = status.report(FileVault())
        row = next(r for r in report["connections"] if r["ref"] == "x:personal")
        assert row["phone"]["android"] == "com.twitter.android"
        assert row["mcp"] is None and row["browser"] is None and row["level"] == "read"
        card = next(c for c in report["connectors"] if c["id"] == "x")
        assert "like" in card["phone"]["act_words"] and card["phone"]["pace"] == 3.0

    def test_no_server_and_no_token(self, home, capsys):
        phone_connected(home)
        assert main(["run", "x:personal"]) == 2
        assert "app on your phone" in capsys.readouterr().err
        assert main(["mcp-config", "x:personal"]) == 2
        assert "app on your phone" in capsys.readouterr().err
        with pytest.raises(connections.ConnectionFailed, match="app on the phone"):
            connections.token("x:personal", vault=FileVault(), http=None)

    def test_connect_and_disconnect_say_where_the_sign_in_is(self, home, capsys):
        assert main(["connect", "x", "--phone"]) == 0
        said = capsys.readouterr().out
        assert "connected x:personal on your phone" in said and "Read only" in said
        assert "Sign in to the X app on your phone yourself" in said
        assert main(["list"]) == 0
        assert "phone: com.twitter.android" in capsys.readouterr().out
        assert main(["disconnect", "x:personal"]) == 0
        assert "stays signed in on your phone" in capsys.readouterr().out
        assert FileVault().get("x:personal") is None

    def test_a_site_with_no_app_says_so(self, home, capsys):
        assert main(["connect", "homeassistant", "--phone"]) == 2
        assert "no phone app Setu knows of" in capsys.readouterr().err
