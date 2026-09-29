"""What a connector says about itself, before anyone signs in.

A connector is code. Its MANIFEST is the part a person can read: which
site, which program to run, which hosts it talks to, and -- the part
that matters most -- the access LEVELS it offers, each spelled as the
exact provider scopes it will ask for.

LEVELS ARE WORDS, SCOPES ARE THE CONTRACT. People choose "Read only" or
"Read and draft"; the provider enforces ``gmail.readonly`` and
``gmail.compose``. The manifest is the one place the two are tied
together, so the sign-in asks for exactly what the chosen level names
and nothing a server happens to advertise. (A server that lists
``https://mail.google.com/`` among its scopes is offering full mailbox
access; asking for everything on the list would take it.)

THE FIRST LEVEL IS THE DEFAULT, and it should be the least one.

VERBS CARRY A CLASS -- read, write, spend -- one per tool. A harness uses
it to decide what to ask the person about; a tool the manifest does not
list is a tool nobody agreed to.

Discovery is by entry point: a connector package names its manifest in
the ``setu.connectors`` group, so installing it is registering it.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from importlib.metadata import entry_points
from pathlib import Path
from typing import Any

ENTRY_POINT_GROUP = "setu.connectors"
VERB_CLASSES = ("read", "write", "spend")
KNOWN_KEYS = {"id", "name", "summary", "road", "auth", "command", "api_base",
              "hosts", "whoami", "levels", "verbs"}


class ManifestError(Exception):
    """A manifest that cannot be trusted as written."""


@dataclass(frozen=True, slots=True)
class Level:
    name: str
    label: str
    scopes: tuple[str, ...]
    description: str = ""


@dataclass(frozen=True, slots=True)
class WhoAmI:
    """How to learn which account a fresh token belongs to: GET ``url``
    with the token, read ``field`` from the JSON. Asking the connector's
    own API means no extra identity scope is ever requested."""

    url: str
    field: str


@dataclass(frozen=True, slots=True)
class Manifest:
    id: str
    name: str
    summary: str
    road: str                       # api | mcp | browser
    auth: str                       # google | ...
    command: tuple[str, ...]
    api_base: str
    hosts: tuple[str, ...]
    whoami: WhoAmI | None
    levels: tuple[Level, ...]
    verbs: dict[str, str] = field(default_factory=dict)

    @property
    def default_level(self) -> Level:
        return self.levels[0]

    def level(self, name: str | None) -> Level:
        if name is None:
            return self.default_level
        for level in self.levels:
            if level.name == name:
                return level
        known = ", ".join(level.name for level in self.levels)
        raise ManifestError(f"{self.id} has no level {name!r} (known: {known})")

    def level_for_scopes(self, granted: set[str]) -> Level | None:
        """The richest level whose scopes were ALL granted -- what a
        connection actually holds when a person unticks a box."""
        best = None
        for level in self.levels:
            if set(level.scopes) <= granted:
                best = level
        return best


def parse(data: dict[str, Any], source: str = "manifest") -> Manifest:
    unknown = set(data) - KNOWN_KEYS
    if unknown:
        # Unknown keys are errors, not decoration: a misspelt "hosts" would
        # otherwise read as "talks to nobody".
        raise ManifestError(f"{source}: unknown key(s) {sorted(unknown)}")
    for key in ("id", "name", "road", "auth", "command", "levels"):
        if key not in data:
            raise ManifestError(f"{source}: missing {key!r}")
    command = data["command"]
    if isinstance(command, str):
        command = [command]
    levels = []
    for name, spec in data["levels"].items():
        scopes = spec.get("scopes") or []
        if not scopes:
            raise ManifestError(f"{source}: level {name!r} names no scopes")
        levels.append(Level(name=name, label=spec.get("label", name),
                            scopes=tuple(scopes),
                            description=spec.get("description", "")))
    verbs = dict(data.get("verbs") or {})
    for tool, klass in verbs.items():
        if klass not in VERB_CLASSES:
            raise ManifestError(f"{source}: verb {tool!r} has class {klass!r} "
                                f"(known: {', '.join(VERB_CLASSES)})")
    who = data.get("whoami")
    return Manifest(
        id=data["id"], name=data["name"], summary=data.get("summary", ""),
        road=data["road"], auth=data["auth"], command=tuple(command),
        api_base=data.get("api_base", ""), hosts=tuple(data.get("hosts") or ()),
        whoami=WhoAmI(url=who["url"], field=who["field"]) if who else None,
        levels=tuple(levels), verbs=verbs,
    )


def load(path: Path) -> Manifest:
    with open(path, "rb") as handle:
        return parse(tomllib.load(handle), source=str(path))


def installed() -> dict[str, Manifest]:
    """Every connector installed in this environment, by id."""
    found: dict[str, Manifest] = {}
    for point in entry_points(group=ENTRY_POINT_GROUP):
        manifest = load(Path(point.load()))
        if manifest.id != point.name:
            raise ManifestError(f"entry point {point.name!r} loads a manifest "
                                f"whose id is {manifest.id!r}")
        found[manifest.id] = manifest
    return found


def find(connector_id: str) -> Manifest:
    found = installed()
    if connector_id not in found:
        have = ", ".join(sorted(found)) or "none"
        raise ManifestError(f"no connector {connector_id!r} is installed "
                            f"(installed: {have}); try `uv pip install "
                            f"setu-{connector_id}`")
    return found[connector_id]
