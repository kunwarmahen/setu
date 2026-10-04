"""The report a harness reads -- by import or by command -- and what it leaves out.

The bias is A SECRET IN THE WRONG PLACE. A harness puts this report in
logs, on pages, and partly in a prompt, so the one thing it must never
carry is anything from a connection's ``secret``. The tests put known
secrets in the vault and look for them in every form the report takes.

The other promise: THE TWO ROADS SAY THE SAME THING. ``report()`` and
``setu status --json`` are one answer, not two that happen to agree.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time

from conftest import REFRESH, TOKEN
from setu.status import FORMAT, report
from setu.vault import FileVault

SEND = ["https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/gmail.compose",
        "https://www.googleapis.com/auth/gmail.send"]


def seed(vault: FileVault, account: str = "personal", level: str = "send") -> None:
    vault.put(f"gmail:{account}", {
        "connector": "gmail", "account": account, "email": f"{account}@example.com",
        "level": level, "asked_level": level, "scopes": SEND,
        "created": "2026-09-28T00:00:00Z", "last_used": None,
        "secret": {"client_id": "cid", "client_secret": "shh-secret",
                   "token_url": "https://oauth2.googleapis.com/token",
                   "refresh_token": REFRESH, "access_token": TOKEN,
                   "expires_at": time.time() + 3600}})


def test_the_report_carries_no_secret(home):
    seed(FileVault())
    text = json.dumps(report())
    for secret in (REFRESH, TOKEN, "shh-secret", "cid"):
        assert secret not in text


def test_a_connection_says_its_level_and_how_to_start_it(home):
    seed(FileVault())
    row = report()["connections"][0]
    assert row["ref"] == "gmail:personal" and row["level_label"] == "Read, draft and send"
    assert row["mcp"]["name"] == "gmail-personal"
    assert row["mcp"]["args"] == ["run", "gmail:personal"]


def test_connectors_carry_their_verbs_and_whether_they_are_connected(home):
    data = report()
    gmail = next(c for c in data["connectors"] if c["id"] == "gmail")
    assert gmail["connected"] is False
    assert gmail["verbs"]["send_message"] == "write"
    assert gmail["verbs"]["search_threads"] == "read"
    seed(FileVault())
    assert next(c for c in report()["connectors"] if c["id"] == "gmail")["connected"]


def test_a_connection_whose_connector_is_gone_is_a_problem_not_a_crash(home):
    vault = FileVault()
    seed(vault)
    entry = vault.get("gmail:personal")
    entry["connector"] = "outlook"
    vault.put("gmail:personal", entry)
    data = report()
    assert data["connections"][0]["installed"] is False
    assert any("outlook" in problem for problem in data["problems"])


def test_the_command_prints_exactly_the_report(home):
    seed(FileVault())
    out = subprocess.run([sys.executable, "-m", "setu.cli", "status", "--json"],
                         capture_output=True, text=True, check=True).stdout
    printed = json.loads(out)
    assert printed["format"] == FORMAT
    assert printed == report()


def test_the_report_says_where_to_watch(home):
    from setu import status
    vault, sites = status.report()["watch"]
    assert vault.endswith("vault.json") and sites.endswith("sites")
