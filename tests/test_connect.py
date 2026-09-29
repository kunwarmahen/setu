"""Signing in, keeping the key, giving it back.

The bias is OVER-ASKING. The failure this file is built against is a
sign-in that quietly takes more than the person chose: a scope added
"while we are there", a level recorded from what was requested rather
than what was granted, an old grant left alive after a new one replaced
it, a local delete that leaves Google still honouring the key.

Also designed against:

* **A connection that dies in an hour.** Without ``access_type=offline``
  and ``prompt=consent`` Google sends no refresh token; a sign-in with
  none must be refused, not stored.
* **Losing every connection to one bad write.** The vault is written
  atomically and is readable by its owner only; a corrupt file is
  reported, never replaced with an empty one.
"""

from __future__ import annotations

import json
import stat
from urllib.parse import parse_qs, urlparse

import pytest
from conftest import REFRESH, FakeGoogle, person
from setu import connections, google
from setu.manifest import find
from setu.vault import FileVault, VaultError

CLIENT = google.Client(client_id="cid.apps.googleusercontent.com", client_secret="shh")
READ = "https://www.googleapis.com/auth/gmail.readonly"
COMPOSE = "https://www.googleapis.com/auth/gmail.compose"


def connect(fake: FakeGoogle, vault: FileVault, level: str | None = None,
            account: str = "personal", seen: list[str] | None = None):
    urls = seen if seen is not None else []

    def browser(url: str) -> None:
        urls.append(url)
        person(url)

    with fake.client() as http:
        return connections.connect(find("gmail"), account, level=level, client=CLIENT,
                                   vault=vault, http=http, open_browser=browser, timeout=10)


class TestTheSignInAsksForExactlyTheLevel:
    def test_read_only_asks_for_readonly_and_nothing_else(self, home):
        urls: list[str] = []
        connect(FakeGoogle(), FileVault(), seen=urls)
        query = parse_qs(urlparse(urls[0]).query)
        assert query["scope"] == [READ]
        assert "include_granted_scopes" not in query

    def test_the_draft_level_adds_compose_and_only_compose(self, home):
        urls: list[str] = []
        connect(FakeGoogle(scope=f"{READ} {COMPOSE}"), FileVault(), level="draft", seen=urls)
        assert parse_qs(urlparse(urls[0]).query)["scope"][0].split() == [READ, COMPOSE]

    def test_it_asks_for_a_refresh_token_every_time(self, home):
        urls: list[str] = []
        connect(FakeGoogle(), FileVault(), seen=urls)
        query = parse_qs(urlparse(urls[0]).query)
        assert query["access_type"] == ["offline"] and query["prompt"] == ["consent"]
        assert query["code_challenge_method"] == ["S256"]

    def test_the_client_secret_goes_to_the_token_endpoint(self, home):
        """Google's rule for desktop clients, PKCE or not."""
        fake = FakeGoogle()
        connect(fake, FileVault())
        exchange = fake.forms[0]
        assert exchange["client_secret"] == "shh" and exchange["code_verifier"]


class TestWhatWasGrantedWins:
    def test_an_unticked_box_records_the_smaller_level(self, home):
        """Asked for draft, allowed only read: the connection is Read only."""
        entry = connect(FakeGoogle(scope=READ), FileVault(), level="draft")
        assert entry["level"] == "read" and entry["asked_level"] == "draft"
        assert entry["scopes"] == [READ]

    def test_less_than_the_least_level_is_refused_and_revoked(self, home):
        fake = FakeGoogle(scope="openid")
        with pytest.raises(connections.ConnectionFailed, match="Nothing was saved"):
            connect(fake, FileVault())
        assert FileVault().list() == []
        assert fake.revoked == [REFRESH]

    def test_no_refresh_token_is_refused_rather_than_stored(self, home):
        fake = FakeGoogle(refresh_token=None)
        with pytest.raises(connections.ConnectionFailed, match="refresh token"):
            connect(fake, FileVault())
        assert FileVault().list() == []

    def test_the_account_address_comes_from_gmail_itself(self, home):
        entry = connect(FakeGoogle(), FileVault())
        assert entry["email"] == "me@example.com"


class TestOneGrantPerAccount:
    """Google keeps one grant per app per account, and revoking any token
    of it ends all of it. Every revoke here must respect that."""

    def test_reconnecting_the_same_account_keeps_its_grant(self, home):
        """Changing level signs in again on the SAME grant; revoking the
        "old" token would sign out the new one."""
        vault = FileVault()
        connect(FakeGoogle(), vault)
        again = FakeGoogle(refresh_token="1//second", scope=f"{READ} {COMPOSE}")
        connect(again, vault, level="draft")
        assert vault.get("gmail:personal")["secret"]["refresh_token"] == "1//second"
        assert vault.get("gmail:personal")["level"] == "draft"
        assert again.revoked == []

    def test_pointing_a_name_at_another_account_revokes_the_old_grant(self, home):
        vault = FileVault()
        connect(FakeGoogle(), vault)
        other = FakeGoogle(refresh_token="1//other", email="someone.else@example.com")
        connect(other, vault)
        assert other.revoked == [REFRESH]

    def test_a_refused_sign_in_does_not_revoke_a_grant_in_use(self, home):
        """Reconnecting, the person unticks everything: the refusal must not
        take the working connection down with it."""
        vault = FileVault()
        connect(FakeGoogle(), vault)
        refused = FakeGoogle(scope="openid")
        with pytest.raises(connections.ConnectionFailed):
            connect(refused, vault)
        assert refused.revoked == []
        assert vault.get("gmail:personal")["level"] == "read"

    def test_disconnecting_revokes_at_google_then_forgets(self, home):
        vault = FileVault()
        connect(FakeGoogle(), vault)
        fake = FakeGoogle()
        with fake.client() as http:
            existed, revoked = connections.disconnect("gmail:personal", vault=vault, http=http)
        assert (existed, revoked) == (True, True)
        assert fake.revoked == [REFRESH] and vault.list() == []

    def test_a_second_name_for_the_same_account_keeps_the_grant_alive(self, home):
        vault = FileVault()
        connect(FakeGoogle(), vault, account="personal")
        connect(FakeGoogle(), vault, account="also-me")
        fake = FakeGoogle()
        with fake.client() as http:
            existed, revoked = connections.disconnect("gmail:also-me", vault=vault, http=http)
        assert (existed, revoked) == (True, None)
        assert fake.revoked == [] and vault.list() == ["gmail:personal"]

    def test_two_accounts_are_two_grants(self, home):
        vault = FileVault()
        connect(FakeGoogle(), vault, account="personal")
        connect(FakeGoogle(refresh_token="1//work", email="me@work.test"), vault, account="work")
        fake = FakeGoogle()
        with fake.client() as http:
            connections.disconnect("gmail:work", vault=vault, http=http)
        assert fake.revoked == ["1//work"]

    def test_an_account_name_with_a_colon_is_refused(self, home):
        with pytest.raises(connections.ConnectionFailed):
            connections.ref_for("gmail", "a:b")


class TestTokens:
    def test_a_due_token_is_refreshed_with_the_stored_client(self, home):
        vault = FileVault()
        connect(FakeGoogle(), vault)
        entry = vault.get("gmail:personal")
        entry["secret"]["expires_at"] = 0
        vault.put("gmail:personal", entry)
        fake = FakeGoogle(access_token="ya29.fresh")
        with fake.client() as http:
            got = connections.token("gmail:personal", vault=vault, http=http)
        assert got.access_token == "ya29.fresh"
        assert fake.forms[0]["grant_type"] == "refresh_token"
        assert fake.forms[0]["client_secret"] == "shh"

    def test_a_live_token_is_not_refreshed(self, home):
        vault = FileVault()
        connect(FakeGoogle(), vault)
        fake = FakeGoogle()
        with fake.client() as http:
            connections.token("gmail:personal", vault=vault, http=http)
        assert fake.forms == []


class TestTheVault:
    def test_the_file_is_readable_by_its_owner_only(self, home):
        vault = FileVault()
        vault.put("x:y", {"secret": {"refresh_token": "r"}})
        assert stat.S_IMODE(vault.path.stat().st_mode) == 0o600
        assert stat.S_IMODE(vault.home.stat().st_mode) == 0o700

    def test_a_corrupt_file_is_reported_not_replaced(self, home):
        vault = FileVault()
        vault.put("x:y", {})
        vault.path.write_text("{not json")
        with pytest.raises(VaultError):
            vault.put("a:b", {})
        assert vault.path.read_text() == "{not json"

    def test_two_writers_at_once_lose_nothing(self, home):
        """Two connectors refreshing together: each write must keep the
        other's entry."""
        import threading
        vault = FileVault()
        writers = [threading.Thread(target=vault.put, args=(f"gmail:a{i}", {"n": i}))
                   for i in range(20)]
        for writer in writers:
            writer.start()
        for writer in writers:
            writer.join()
        assert len(FileVault().list()) == 20

    def test_list_never_shows_a_secret(self, home):
        entry = connect(FakeGoogle(), FileVault())
        assert "secret" not in connections.public(entry)
        assert REFRESH not in json.dumps(connections.public(entry))


class TestTheClientFile:
    def test_a_web_client_is_refused_with_what_to_make_instead(self, tmp_path):
        path = tmp_path / "client.json"
        path.write_text(json.dumps({"web": {"client_id": "x", "client_secret": "y"}}))
        with pytest.raises(google.GoogleAuthError, match="Desktop app"):
            google.client_from_file(path)

    def test_a_desktop_client_is_read(self, tmp_path):
        path = tmp_path / "client.json"
        path.write_text(json.dumps({"installed": {"client_id": "x", "client_secret": "y"}}))
        assert google.client_from_file(path) == google.Client("x", "y")

    def test_a_redirect_with_the_wrong_state_is_never_redeemed(self):
        listener = google.RedirectListener()
        try:
            import threading

            import httpx
            threading.Thread(target=lambda: httpx.get(
                f"{listener.redirect_uri}?code=c&state=forged", timeout=5), daemon=True).start()
            with pytest.raises(google.GoogleAuthError, match="wrong state"):
                listener.wait("expected", timeout=5)
        finally:
            listener.close()
