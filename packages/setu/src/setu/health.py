"""How a browser connection has been faring: a week of what went wrong.

A site reached through a browser can turn on its visitor slowly: a
robot check that used to be rare starts on every page, a sign-in that
lasted weeks now lasts a day, the action limit is hit every session. A
person notices none of that turn by turn. So the harness's site tools
say when one happens (``setu site event amazon:personal robot_check``),
and Setu keeps a week of them per connection: ``setu list``, the status
report and a harness's page show the counts.

KINDS, NOT DETAILS. An event is a kind and a time -- never the page, the
address or anything on it. What happened on which page is the
harness's to log; this is the shape of it over days.

A WEEK, THEN GONE. Older events are dropped whenever the file is
written, so it never grows past a week of a busy agent.

A bad or missing file is an empty record, never an error: this is a
health line, and nothing may fail because it could not be kept.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from setu.vault import default_home

HEALTH_FILE = "health.json"
#: What a site's tools report, and how a person reads each.
KINDS = {
    "robot_check": "robot check",
    "signed_out": "signed out",
    "refused": "refused to press",
    "limit": "action limit reached",
    "handoff": "handed to you",
}
WEEK = 7 * 24 * 3600


def path() -> Path:
    return default_home() / HEALTH_FILE


def _read() -> dict[str, list[list[Any]]]:
    try:
        data = json.loads(path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def record(ref: str, kind: str, now: float | None = None) -> None:
    """Note one event for ``ref``; a week of them is kept."""
    if kind not in KINDS:
        raise ValueError(f"unknown event {kind!r} (known: {', '.join(KINDS)})")
    now = time.time() if now is None else now
    data = _read()
    kept = {r: [e for e in events if isinstance(e, list) and len(e) == 2
                and now - float(e[0]) < WEEK]
            for r, events in data.items() if isinstance(events, list)}
    kept.setdefault(ref, []).append([now, kind])
    kept = {r: events for r, events in kept.items() if events}
    target = path()
    target.parent.mkdir(parents=True, exist_ok=True)
    handle, staged = tempfile.mkstemp(dir=target.parent, prefix=".health-")
    with os.fdopen(handle, "w", encoding="utf-8") as out:
        json.dump(kept, out)
    os.replace(staged, target)


def week(ref: str, now: float | None = None) -> dict[str, Any]:
    """{kind: count} over the last week for ``ref``, and ``last``: when
    the latest one happened. Empty when nothing did."""
    now = time.time() if now is None else now
    counts: dict[str, int] = {}
    latest = 0.0
    for event in _read().get(ref) or []:
        try:
            at, kind = float(event[0]), str(event[1])
        except (TypeError, ValueError, IndexError):
            continue
        if now - at < WEEK and kind in KINDS:
            counts[kind] = counts.get(kind, 0) + 1
            latest = max(latest, at)
    if not counts:
        return {}
    return {"counts": counts,
            "last": datetime.fromtimestamp(latest, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")}


def line(ref: str) -> str:
    """``robot check 2×, signed out 1× this week`` -- or empty."""
    seen = week(ref)
    if not seen:
        return ""
    parts = [f"{KINDS[k]} {n}×" for k, n in sorted(seen["counts"].items(),
                                                   key=lambda kv: -kv[1])]
    return ", ".join(parts) + " this week"


def forget(ref: str) -> None:
    """A disconnected connection's record goes with it."""
    data = _read()
    if data.pop(ref, None) is not None:
        target = path()
        handle, staged = tempfile.mkstemp(dir=target.parent, prefix=".health-")
        with os.fdopen(handle, "w", encoding="utf-8") as out:
            json.dump(data, out)
        os.replace(staged, target)
