"""A folder locked with a passphrase: nothing usable on disk without it.

The bias: THE KEY IS THE PERSON'S, AND SEALING NEVER WAITS FOR IT. Locked,
no refresh token and no cookie can be read back from the folder by
anyone without the passphrase -- the owner browsing files, a backup;
sealing anew needs only the folder's public half, so a restart can put a
profile away without asking anybody; and the key, once given to Setu,
goes no further -- not to a connector, not to a browser.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time

import httpx
import pytest
from conftest import REFRESH, TOKEN
from setu import connections, helper, seal
from setu.manifest import find
from setu.vault import FileVault

PHRASE = "correct horse battery"


def seed(vault: FileVault) -> None:
    vault.put("gmail:personal", {
        "connector": "gmail", "account": "personal", "email": "me@example.com",
        "level": "read", "scopes": [], "secret": {
            "client_id": "cid", "client_secret": "shh", "refresh_token": REFRESH,
            "access_token": TOKEN, "expires_at": time.time() + 3600}})


def profile(vault: FileVault, name: str = "amazon-personal") -> None:
    folder = vault.home / "profiles" / name / "Default"
    (folder / "Cache").mkdir(parents=True)
    (folder / "Cookies").write_text("session-id=COOKIE")
    (folder / "Cache" / "blob").write_text("x" * 4096)


def everything_on_disk(home) -> str:
    return "".join(p.read_text(errors="replace") for p in home.rglob("*") if p.is_file())


@pytest.fixture
def locked(home, monkeypatch):
    monkeypatch.delenv(seal.ENV_KEY, raising=False)
    vault = FileVault()
    seed(vault)
    profile(vault)
    private = seal.create(vault.home, PHRASE)
    monkeypatch.setenv(seal.ENV_KEY, base64.b64encode(private).decode())
    for ref in vault.list():
        vault.put(ref, vault.get(ref))
    monkeypatch.delenv(seal.ENV_KEY)
    seal.seal_profiles(vault.home, vault.home / "profiles")
    return vault, private


def hold(monkeypatch, private: bytes) -> None:
    monkeypatch.setenv(seal.ENV_KEY, base64.b64encode(private).decode())


class TestAtRest:
    def test_nothing_secret_can_be_read_from_the_folder(self, locked):
        vault, _ = locked
        disk = everything_on_disk(vault.home)
        assert REFRESH not in disk and TOKEN not in disk and "shh" not in disk
        assert "COOKIE" not in disk
        assert not (vault.home / "profiles" / "amazon-personal").exists()

    def test_what_was_chosen_stays_readable_and_the_key_does_not(self, locked):
        vault, _ = locked
        entry = vault.get("gmail:personal")
        assert entry["email"] == "me@example.com" and entry["level"] == "read"
        assert entry["secret"] is None and entry["locked"] is True

    def test_a_token_is_refused_in_words_while_locked(self, locked):
        with httpx.Client() as http, pytest.raises(connections.ConnectionFailed,
                                                   match="is locked"):
            connections.token("gmail:personal", vault=locked[0], http=http)

    def test_writing_back_an_entry_read_while_locked_keeps_its_key(self, locked, monkeypatch):
        vault, private = locked
        entry = vault.get("gmail:personal")
        vault.put("gmail:personal", {**entry, "last_used": "now"})
        hold(monkeypatch, private)
        assert vault.get("gmail:personal")["secret"]["refresh_token"] == REFRESH


class TestOpening:
    def test_the_held_key_opens_secrets_and_profiles_without_their_caches(self, locked,
                                                                         monkeypatch):
        vault, private = locked
        hold(monkeypatch, private)
        assert vault.get("gmail:personal")["secret"]["refresh_token"] == REFRESH
        opened = seal.open_profiles(vault.home, vault.home / "profiles", private)
        default = vault.home / "profiles" / "amazon-personal" / "Default"
        assert opened == ["amazon-personal"]
        assert (default / "Cookies").read_text() == "session-id=COOKIE"
        assert not (default / "Cache").exists()

    def test_only_the_passphrase_gives_the_key(self, locked):
        vault, private = locked
        assert seal.unlock_key(vault.home, PHRASE) == private
        with pytest.raises(seal.WrongPassphrase):
            seal.unlock_key(vault.home, "Correct horse battery")

    def test_another_folders_key_opens_nothing(self, locked, monkeypatch, tmp_path):
        vault, _ = locked
        other = seal.create(tmp_path / "other", PHRASE)
        hold(monkeypatch, other)
        assert vault.get("gmail:personal")["locked"] is True

    def test_a_sealed_secret_moved_to_another_entry_will_not_open(self, locked, monkeypatch):
        vault, private = locked
        data = json.loads(vault.path.read_text())
        data["gmail:work"] = dict(data["gmail:personal"])
        vault.path.write_text(json.dumps(data))
        hold(monkeypatch, private)
        with pytest.raises(seal.Locked, match="sealed with another key, or changed"):
            vault.get("gmail:work")

    def test_a_new_sign_in_is_sealed_with_no_key_held(self, locked):
        vault, _ = locked
        vault.put("gmail:work", {"connector": "gmail", "secret": {"refresh_token": "NEW-RT"}})
        assert "NEW-RT" not in vault.path.read_text()

    def test_sealing_a_profile_left_open_needs_no_key(self, locked, monkeypatch):
        vault, private = locked
        seal.open_profiles(vault.home, vault.home / "profiles", private)
        monkeypatch.delenv(seal.ENV_KEY, raising=False)
        assert seal.seal_profiles(vault.home, vault.home / "profiles") == ["amazon-personal"]
        assert "COOKIE" not in everything_on_disk(vault.home)


class TestPassphrase:
    def test_a_changed_passphrase_keeps_the_same_key(self, locked):
        vault, private = locked
        seal.change(vault.home, PHRASE, "a different long one")
        assert seal.unlock_key(vault.home, "a different long one") == private
        with pytest.raises(seal.WrongPassphrase):
            seal.unlock_key(vault.home, PHRASE)

    def test_a_short_passphrase_is_refused(self, home, tmp_path):
        with pytest.raises(seal.WrongPassphrase, match="at least 8"):
            seal.create(tmp_path / "f", "short")


def setu(*argv, stdin: str = "", env=None) -> tuple[int, str]:
    import subprocess
    done = subprocess.run([sys.executable, "-m", "setu.cli", *argv], input=stdin,
                          capture_output=True, text=True, env=env or dict(os.environ))
    return done.returncode, done.stdout + done.stderr


def test_the_commands_lock_unlock_seal_and_remove(home, monkeypatch):
    monkeypatch.delenv(seal.ENV_KEY, raising=False)
    vault = FileVault()
    seed(vault)
    profile(vault)
    code, out = setu("lock", "set", "--passphrase-stdin", stdin=PHRASE + "\n")
    assert code == 0 and "1 connection(s) sealed, browser sign-ins packed" in out
    assert REFRESH not in everything_on_disk(vault.home)
    code, out = setu("lock", "unlock", "--passphrase-stdin", "--json", stdin="nope-nope\n")
    assert code == 2 and "not this folder's passphrase" in out
    code, out = setu("lock", "unlock", "--passphrase-stdin", "--json", stdin=PHRASE + "\n")
    got = json.loads(out)
    assert got["profiles"] == ["amazon-personal"]
    env = {**os.environ, seal.ENV_KEY: got["key"]}
    status = json.loads(setu("status", "--json", env=env)[1])
    assert status["lock"] == {"locked": True, "open": True}
    assert setu("lock", "seal")[0] == 0
    assert "COOKIE" not in everything_on_disk(vault.home)
    code, out = setu("lock", "remove", "--passphrase-stdin", stdin=PHRASE + "\n")
    assert code == 0 and not seal.lock_path(vault.home).exists()
    assert REFRESH in vault.path.read_text()
    assert (vault.home / "profiles" / "amazon-personal" / "Default" / "Cookies").exists()


SPY = r"""
import json, os, sys
print(json.dumps({"key": os.environ.get("SETU_VAULT_KEY")}))
"""


def test_the_key_never_reaches_a_connector(locked, monkeypatch, capfd):
    vault, private = locked
    hold(monkeypatch, private)
    from dataclasses import replace
    spy = replace(find("gmail"), command=(sys.executable, "-c", SPY))
    with httpx.Client() as http:
        assert helper.run_proxied("gmail:personal", spy, vault=vault, http=http,
                                  api_base="http://127.0.0.1:9", confine=False) == 0
    assert json.loads(capfd.readouterr().out.strip().splitlines()[-1]) == {"key": None}
