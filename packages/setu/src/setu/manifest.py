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

A PROVIDER WITHOUT SCOPES HAS LEVELS WITHOUT THEM. Home Assistant's
tokens carry the whole of a user's rights; there is nothing finer to
ask for. Such a manifest's levels name no scopes, the level recorded is
the one the person chose, and the connector itself offers only that
level's tools -- an honest line in each level's description says the
provider does not hold it. Google manifests must still name scopes.

VERBS CARRY A CLASS -- read, write, spend -- one per tool. A harness uses
it to decide what to ask the person about; a tool the manifest does not
list is a tool nobody agreed to. One exception, for a bridge to a
server whose tool names are the server's own and change by version
(Home Assistant's): ``"*" = "write"`` classes every tool not listed,
so it is asked about rather than dropped. Only ``write`` or ``spend``
may be the default -- "anything else reads" is a claim nobody can check.

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
#: The verbs key that classes every tool a manifest does not list.
ANY_TOOL = "*"
#: Auth kinds whose provider enforces scopes, so each level must name some.
SCOPED_AUTH = ("google",)
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

    @property
    def scoped(self) -> bool:
        """Whether the provider enforces the levels (it has scopes)."""
        return self.auth in SCOPED_AUTH

    def verb(self, tool: str) -> str | None:
        """A tool's class: listed, else the ``"*"`` default, else None."""
        return self.verbs.get(tool) or self.verbs.get(ANY_TOOL)

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
        if not scopes and data["auth"] in SCOPED_AUTH:
            raise ManifestError(f"{source}: level {name!r} names no scopes")
        levels.append(Level(name=name, label=spec.get("label", name),
                            scopes=tuple(scopes),
                            description=spec.get("description", "")))
    verbs = dict(data.get("verbs") or {})
    for tool, klass in verbs.items():
        if klass not in VERB_CLASSES:
            raise ManifestError(f"{source}: verb {tool!r} has class {klass!r} "
                                f"(known: {', '.join(VERB_CLASSES)})")
    if verbs.get(ANY_TOOL) == "read":
        raise ManifestError(f"{source}: \"*\" may be write or spend, never read")
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
