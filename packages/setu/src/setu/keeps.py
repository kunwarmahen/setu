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

A NEW HOME, SAID BY SETU ITSELF. The vault names each site's browser
profile by its whole path (``/home/old/.local/state/setu/profiles/
amazon-personal``), and the settings name the Google client file. Put
back on a computer whose home is another folder, every browser sign-in
would point at a profile that isn't there. ``setu keeps --rehome OLD
NEW`` moves the paths under OLD to under NEW in Setu's own two files --
``vault.json`` and ``config.json`` -- and says which; a program that
restored them (Sarathi) asks for it, since only Setu knows its files.
``rehome: true`` in ``keeps --json`` says it can. A locked folder's
vault is rewritten too: its paths are in the clear, only the secrets
are sealed.
"""

from __future__ import annotations

import json
import os
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
    return {"format": FORMAT, "keeps": keeps, "rehome": True}


#: Setu's own files that name paths.
REHOMED = ("vault.json", "config.json")


def _moved(value: Any, old: str, new: str) -> tuple[Any, int]:
    """``value`` with every string at or under ``old`` moved under ``new``."""
    if isinstance(value, str):
        if value == old or value.startswith(old.rstrip("/") + "/"):
            return new.rstrip("/") + value[len(old.rstrip("/")):], 1
        return value, 0
    if isinstance(value, dict):
        out, count = {}, 0
        for key, item in value.items():
            out[key], n = _moved(item, old, new)
            count += n
        return out, count
    if isinstance(value, list):
        moved = [_moved(item, old, new) for item in value]
        return [m for m, _ in moved], sum(n for _, n in moved)
    return value, 0


def rehome(old: str, new: str, home: Path | None = None) -> list[dict[str, Any]]:
    """Setu's files with their paths under ``old`` moved under ``new``:
    one row per file changed, ``{"file", "paths"}``. A path elsewhere (a
    Google client file kept on a USB disk) is left as it is."""
    old, new = old.rstrip("/") or "/", new.rstrip("/") or "/"
    if not old.startswith("/") or not new.startswith("/"):
        raise ValueError("--rehome takes two whole paths: the old home and this one")
    home = home or default_home()
    changed = []
    for name in REHOMED:
        path = home / name
        try:
            data = json.loads(path.read_text())
        except (OSError, ValueError):
            continue
        moved, count = _moved(data, old, new)
        if not count:
            continue
        spare = path.with_name(path.name + ".rehoming")
        spare.write_text(json.dumps(moved, indent=2) + "\n")
        os.chmod(spare, path.stat().st_mode & 0o777)
        spare.replace(path)
        changed.append({"file": str(path), "paths": count})
    return changed
