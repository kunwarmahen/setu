"""What Setu keeps on this computer, for a backup to take.

A backup of the house (Sarathi's ``sarathi backup``) is one file holding
every program's own files, and each program says where its are --
``keeps --json``, asked the way ``status --json`` is -- so the program
that packs it knows nothing of what is inside.

Setu's folder is the whole of it: the vault (each account and the key
that proves it), the settings, the sign-ins of own MCP servers, the
sites' recipes and their browser profiles (Amazon's, X's cookies). One
place, because they die together; a restore that brought back the vault
without the profiles would leave half the accounts signed out.

WHAT IS LEFT OUT: the browser's caches (seal.CACHES -- no sign-in in
them, and most of the bytes: 2.6 GB of profiles here are 0.5 GB without),
the locks a running Chrome leaves (restored, a profile reads as in use),
and the logs.

THE GOOGLE CLIENT FILE, WHEN IT LIVES ELSEWHERE. Setu keeps only its
path, and the file is usually where Google's download put it; without
it, a new Gmail sign-in can't be made, so it is a place of its own.

A LOCKED FOLDER STAYS LOCKED. What is sealed (seal.py) is carried
sealed: the backup holds what the folder holds, and the person's
passphrase still opens it after a restore.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from setu.config import google_client_file
from setu.seal import CACHES
from setu.vault import default_home

FORMAT = "setu.keeps.v1"

#: Beyond the caches: Chrome's own locks, and what is only a record.
LEAVE_OUT = sorted(CACHES) + ["Singleton*", "logs", "vault.lock"]


def report() -> dict[str, Any]:
    home = default_home()
    keeps = [{"id": "home", "path": str(home),
              "what": "your accounts and their keys, settings, own servers' sign-ins, "
                      "sites and their browser profiles",
              "leave_out": LEAVE_OUT}]
    client = google_client_file()
    if client:
        path = Path(client).expanduser()
        if home not in path.parents:
            keeps.append({"id": "google-client", "path": str(path),
                          "what": "the Google client file Gmail sign-ins are made with",
                          "leave_out": []})
    for place in keeps:
        place["exists"] = Path(place["path"]).exists()
    return {"format": FORMAT, "keeps": keeps}
