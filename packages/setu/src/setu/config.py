"""Setu's own settings: small, plain, and never a secret.

Until Setu has its own app registered with Google, signing in needs the
person's "Desktop app" OAuth client file. Asking for its path on every
``setu connect`` is how a terminal gets away with it; a harness's page
cannot keep asking. So the PATH is remembered here -- once, for every
harness -- and the file itself stays where the person keeps it.

The same goes for the address of the person's Home Assistant: a page
signing in has nowhere to type it, so ``setu config homeassistant-url``
remembers it (an address, not a key). And for sites signed in to in a
browser window, ``setu config browser`` names which browser (a program,
not a key) -- otherwise the first Chrome-like one on PATH.

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

ENV_HA_URL = "SETU_HOMEASSISTANT_URL"
ENV_BROWSER = "SETU_BROWSER"

#: The settings ``setu config`` knows, by the name a person types.
KEYS = {"client-file": "google_client_file", "homeassistant-url": "homeassistant_url",
        "browser": "browser", "share-installs": "share_installs",
        "people-page": "people_page"}
#: The ones that are on or off.
SWITCHES = ("share-installs", "people-page")


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


def homeassistant_url(explicit: str | None = None) -> str | None:
    """The Home Assistant to sign in to: flag, environment, remembered."""
    return (explicit or os.environ.get(ENV_HA_URL)
            or load().get("homeassistant_url") or None)


def browser(explicit: str | None = None) -> str | None:
    """The browser to sign in to browser-road sites with."""
    return (explicit or os.environ.get(ENV_BROWSER)
            or load().get("browser") or None)


def check(name: str, value: str) -> str:
    """The value ``setu config NAME VALUE`` (or Setu's page) would keep,
    checked the way each setting needs: a client file that is a Desktop
    client, a Home Assistant address, a browser that is a program here,
    on or off. One check for the terminal and the page, so neither can
    keep what the other would refuse."""
    from setu import google, homeassistant

    if name not in KEYS:
        raise ValueError(f"unknown setting {name!r} (known: {', '.join(KEYS)})")
    if name == "homeassistant-url":
        return homeassistant.normalise_url(value)
    if name in SWITCHES:
        value = value.strip().lower()
        if value not in ("on", "off"):
            raise ValueError(f"{name} is on or off")
        return value
    if name == "browser":
        import shutil

        found = shutil.which(str(Path(value).expanduser())) or ""
        if not found:
            raise ValueError(f"{value!r} is not a program on this computer")
        return found
    path_ = Path(value).expanduser().resolve()
    google.client_from_file(path_)   # a Web client, or no file, is refused now
    return str(path_)


def share_installs() -> bool:
    """Whether Setu tells the catalog server, anonymously, which listed
    connectors are installed (catalog.ping_installs). On unless turned off."""
    return str(load().get("share_installs") or "on").lower() != "off"


def people_page(home: Path | None = None) -> bool:
    """Whether people may be given a link to their own folder's page
    (page.py). On unless the owner turned it off, in the owner's folder."""
    try:
        data = json.loads(((home or default_home()) / CONFIG_FILE).read_text("utf-8"))
    except (OSError, ValueError):
        data = {}
    return str((data if isinstance(data, dict) else {}).get("people_page")
               or "on").lower() != "off"
