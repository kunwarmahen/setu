"""A person's own page: a one-time link, then a session on one device.

A door like Dvara gives each person a Setu folder of their own
(``<state>/setu/<person>``). The owner's page (page.py) serves the
owner's folder; this lets the same server serve a person theirs, so
they can see their connections, change a level, disconnect, and read
what each one did, from their phone -- without the owner's key and
without seeing anybody else's folder.

THE LINK IS MADE IN THE PERSON'S FOLDER. ``setu page-link``, run with
``SETU_HOME`` at the person's folder (as the door runs every Setu
command for them), writes a one-time code's hash there and prints the
address. The server is told where people's folders live
(``setu serve --people DIR``) and never takes a path from a browser:
the link names a folder by its name under that one place, and a name
that is not a plain word, or not a folder there, is nobody.

ONCE, ON THE FIRST DEVICE, FOR TEN MINUTES. The code is kept only as
its hash. The first device that opens the link trades it for a session
and the link is gone: a second device -- or the same address read off a
chat later -- gets nothing. A new link replaces one not yet used.

THEN A SESSION, UNTIL IT IS CLOSED. The session's secret goes to that
browser once and is kept in the person's folder only as a hash, 0600.
It lasts until the person closes it on the page, the owner closes them
all (``setu page-link --close-all`` in that folder), or the owner turns
people's pages off (``setu config people-page off`` in the owner's
folder) -- which refuses every person's session at once, without
forgetting them.

The secret a browser holds is ``p.<person>.<secret>``: the server can
find whose folder to look in without trying every one, and the owner's
token can never be mistaken for it.

THE OWNER SEES WHO HAS A PAGE OPEN, NEVER A KEY. ``overview`` lists each
person's folder with its open pages (when each began, and the device in
two words: "Android · Chrome") and a link not yet used, until when. No
hash leaves the folder, so nothing listed opens anything. The owner
closes a person's pages from there (``close_all``, as ``setu page-link
--close-all`` does in that folder): one person, not the switch that
turns everybody's off.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

LINK_FILE = "page-link.json"
SESSIONS_FILE = "page-sessions.json"
#: How long a link waits to be opened.
LINK_SECONDS = 600
#: What a person's folder may be called: a plain word, never a path.
PERSON_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
PREFIX = "p."


class PeopleError(Exception):
    """A link or a session that is no good -- said in words a person reads."""


def _hash(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def _write(path: Path, data: Any) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    staged = path.with_suffix(".tmp")
    fd = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as out:
        json.dump(data, out, indent=2)
    os.replace(staged, path)


def _read(path: Path, empty: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return empty


def make_link(home: Path, now: float | None = None,
              seconds: int = LINK_SECONDS) -> tuple[str, float]:
    """A fresh one-time code for the folder at ``home`` (replacing one not
    yet used), and when it stops working."""
    if not PERSON_RE.match(home.name):
        raise PeopleError(f"a person's folder is a plain name, not {home.name!r}")
    code = secrets.token_urlsafe(24)
    expires = (time.time() if now is None else now) + seconds
    _write(home / LINK_FILE, {"sha256": _hash(code), "expires_at": expires})
    return f"{home.name}.{code}", expires


def folder(people: Path, person: str) -> Path:
    """The folder ``person`` names under ``people`` -- or PeopleError."""
    if not PERSON_RE.match(person) or person in (".", ".."):
        raise PeopleError("no such person")
    home = people / person
    if not home.is_dir():
        raise PeopleError("no such person")
    return home


def claim(people: Path, link: str, device: str = "",
          now: float | None = None) -> tuple[str, str]:
    """Trade a link (``person.code``) for a session. Returns the person and
    the secret the browser keeps. The link works once."""
    person, _, code = link.partition(".")
    home = folder(people, person)
    kept = _read(home / LINK_FILE, {})
    now = time.time() if now is None else now
    if not code or not isinstance(kept, dict) or not kept.get("sha256") or \
            not hmac.compare_digest(str(kept["sha256"]), _hash(code)):
        raise PeopleError("that link has been used, or replaced by a newer one -- "
                          "ask for a new one in your chat")
    (home / LINK_FILE).unlink(missing_ok=True)       # once, whatever happens next
    if now > float(kept.get("expires_at") or 0):
        raise PeopleError("that link is more than ten minutes old -- ask for a new one "
                          "in your chat")
    secret = secrets.token_urlsafe(32)
    sessions = _read(home / SESSIONS_FILE, [])
    sessions = sessions if isinstance(sessions, list) else []
    sessions.append({"sha256": _hash(secret), "since": now, "device": device[:400]})
    _write(home / SESSIONS_FILE, sessions)
    return person, f"{PREFIX}{person}.{secret}"


def session(people: Path, token: str) -> str | None:
    """Whose session ``token`` is, or None."""
    if not token.startswith(PREFIX):
        return None
    person, _, secret = token[len(PREFIX):].partition(".")
    try:
        home = folder(people, person)
    except PeopleError:
        return None
    wanted = _hash(secret)
    for row in _read(home / SESSIONS_FILE, []):
        if isinstance(row, dict) and hmac.compare_digest(str(row.get("sha256")), wanted):
            return person
    return None


def close(people: Path, token: str) -> bool:
    """Forget one session (the person closed the page on their device)."""
    person = session(people, token)
    if person is None:
        return False
    home = people / person
    gone = _hash(token[len(PREFIX):].partition(".")[2])
    _write(home / SESSIONS_FILE, [row for row in _read(home / SESSIONS_FILE, [])
                                  if isinstance(row, dict) and row.get("sha256") != gone])
    return True


def close_all(home: Path) -> int:
    """Forget every session for the folder at ``home``, and any link not
    yet used. Returns how many sessions there were."""
    sessions = _read(home / SESSIONS_FILE, [])
    (home / LINK_FILE).unlink(missing_ok=True)
    (home / SESSIONS_FILE).unlink(missing_ok=True)
    return len(sessions) if isinstance(sessions, list) else 0


def count(home: Path) -> int:
    sessions = _read(home / SESSIONS_FILE, [])
    return len(sessions) if isinstance(sessions, list) else 0


#: (what a browser's User-Agent says, what to call it), first match wins.
SYSTEMS = (("iPhone", "iPhone"), ("iPad", "iPad"), ("Android", "Android"),
           ("CrOS", "ChromeOS"), ("Mac OS X", "Mac"), ("Windows", "Windows"),
           ("Linux", "Linux"))
BROWSERS = (("Edg/", "Edge"), ("Firefox/", "Firefox"), ("FxiOS", "Firefox"),
            ("CriOS", "Chrome"), ("Chrome/", "Chrome"), ("Safari/", "Safari"))


def device_name(agent: str) -> str:
    """``Mozilla/5.0 (Linux; Android 14; ...) Chrome/155...`` -> ``Android ·
    Chrome``: enough for the owner to tell a phone from a laptop."""
    agent = agent or ""
    said = [next((name for key, name in table if key in agent), None)
            for table in (SYSTEMS, BROWSERS)]
    if any(said):
        return " · ".join(name for name in said if name)
    return agent[:40] or "a device that didn't say"


def _when(seconds: Any) -> str | None:
    try:
        return datetime.fromtimestamp(float(seconds), UTC).isoformat()
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def overview(people: Path, now: float | None = None) -> list[dict[str, Any]]:
    """Each person's folder under ``people``: their open pages and a link
    not yet used. For the owner's page -- never a hash."""
    now = time.time() if now is None else now
    rows = []
    try:
        homes = sorted(p for p in people.iterdir() if p.is_dir() and PERSON_RE.match(p.name))
    except OSError:
        return []
    for home in homes:
        sessions = _read(home / SESSIONS_FILE, [])
        pages = [{"since": _when(row.get("since")),
                  "device": device_name(str(row.get("device") or ""))}
                 for row in (sessions if isinstance(sessions, list) else [])
                 if isinstance(row, dict)]
        kept = _read(home / LINK_FILE, {})
        expires = float(kept.get("expires_at") or 0) if isinstance(kept, dict) else 0
        rows.append({"person": home.name, "pages": pages,
                     "link": {"expires_at": _when(expires)} if expires > now else None})
    return rows
