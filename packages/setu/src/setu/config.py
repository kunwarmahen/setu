"""Setu's own settings: small, plain, and never a secret.

Until Setu has its own app registered with Google, signing in needs the
person's "Desktop app" OAuth client file. Asking for its path on every
``setu connect`` is how a terminal gets away with it; a harness's page
cannot keep asking. So the PATH is remembered here -- once, for every
harness -- and the file itself stays where the person keeps it.

WHICH PATH WINS. ``--client-file`` beats ``SETU_GOOGLE_CLIENT_FILE``,
which beats the remembered one: the nearer the person's hand, the
stronger the choice.

ONLY PATHS LIVE HERE. ``config.json`` sits beside the vault, but it is
not the vault: nothing in it is a key, so it is safe to print, and
``setu status --json`` says what it holds. The client file itself holds
a client secret -- which is why it is read at connect time and never
copied in.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from setu.vault import default_home

CONFIG_FILE = "config.json"
ENV_CLIENT_FILE = "SETU_GOOGLE_CLIENT_FILE"

#: The settings ``setu config`` knows, by the name a person types.
KEYS = {"client-file": "google_client_file"}


def path() -> Path:
    return default_home() / CONFIG_FILE


def load() -> dict[str, Any]:
    """The remembered settings; empty when none were ever saved. A file
    that is not JSON is an error, never quietly treated as empty."""
    try:
        text = path().read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path()} is not valid JSON ({exc}); fix or delete it") from None
    return data if isinstance(data, dict) else {}


def save(key: str, value: str | None) -> None:
    """Remember (or, with None, forget) one setting. Atomic, like the vault."""
    data = load()
    if value is None:
        data.pop(key, None)
    else:
        data[key] = value
    target = path()
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, target)


def google_client_file(explicit: str | None = None) -> str | None:
    """The client file to sign in with: flag, then environment, then the
    remembered path. None when none of the three says."""
    return (explicit or os.environ.get(ENV_CLIENT_FILE)
            or load().get("google_client_file") or None)
