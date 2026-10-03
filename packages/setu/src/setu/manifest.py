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

A SITE WITH NO API IS A BROWSER ROAD (``road = "browser"``). There is no
program to run and no token to hold: the person signs in by hand in a
window of their own browser, on a profile kept for that one connection,
and the harness drives that profile with its own browser tools. The
``[browser]`` table is everything the harness needs to keep to the
site: where to start, the hosts it may reach, which cookie names mean
"signed in", which pages and buttons spend money (never pressed by the
agent -- handed to the person), how slowly to go, and a short guide to
the site. Its levels are named for the classes they reach (``read``,
``write``), and a click or a typed word is never a read.

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
              "hosts", "whoami", "levels", "verbs", "browser"}
#: The browser road's own keys, in its ``[browser]`` table.
BROWSER_KEYS = {"start_url", "login_url", "signed_in", "home_from_cookie", "spend_pages",
                "spend_words", "pace", "max_actions", "guide", "headed"}
#: The tools a harness offers on a browser profile, and the ones that can
#: change something on the site -- never classed read.
BROWSER_TOOLS = ("open", "follow", "scroll", "search", "click", "fill")
BROWSER_ACTS = ("click", "fill")


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
class Browser:
    """How a harness keeps to a site it reaches through a browser."""

    start_url: str
    login_url: str
    #: Cookie names (``*`` globs) that exist only once someone is signed in.
    signed_in: tuple[str, ...]
    #: Take the connection's home address from the host of the sign-in
    #: cookie -- one Amazon connector, whichever country's store it is.
    home_from_cookie: bool = False
    #: Paths (globs) where pressing anything spends: the person's to do.
    spend_pages: tuple[str, ...] = ()
    #: Words on a button that spend ("buy now", "place your order").
    spend_words: tuple[str, ...] = ()
    #: Seconds between page loads, at least.
    pace: float = 1.0
    #: Clicks and typed text one session may make, at most.
    max_actions: int = 20
    guide: str = ""
    #: The site refuses a headless browser: run it with a window, unseen.
    headed: bool = False


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
    browser: Browser | None = None

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
    road = data.get("road")
    for key in ("id", "name", "road", "auth", "levels",
                *(() if road == "browser" else ("command",))):
        if key not in data:
            raise ManifestError(f"{source}: missing {key!r}")
    command = data.get("command") or []
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
    browser = _browser(data, levels, verbs, source) if road == "browser" else None
    if road != "browser" and "browser" in data:
        raise ManifestError(f"{source}: a [browser] table belongs to road = \"browser\"")
    who = data.get("whoami")
    return Manifest(
        id=data["id"], name=data["name"], summary=data.get("summary", ""),
        road=data["road"], auth=data["auth"], command=tuple(command),
        api_base=data.get("api_base", ""), hosts=tuple(data.get("hosts") or ()),
        whoami=WhoAmI(url=who["url"], field=who["field"]) if who else None,
        levels=tuple(levels), verbs=verbs, browser=browser,
    )


def _browser(data: dict[str, Any], levels: list[Level], verbs: dict[str, str],
             source: str) -> Browser:
    """The ``[browser]`` table, checked: a browser road that cannot say
    where it may go, or when someone is signed in, is not one to trust."""
    if data["auth"] != "browser":
        raise ManifestError(f"{source}: road = \"browser\" signs in with auth = \"browser\"")
    spec = data.get("browser")
    if not isinstance(spec, dict):
        raise ManifestError(f"{source}: road = \"browser\" needs a [browser] table")
    unknown = set(spec) - BROWSER_KEYS
    if unknown:
        raise ManifestError(f"{source}: unknown [browser] key(s) {sorted(unknown)}")
    for key in ("start_url", "signed_in"):
        if not spec.get(key):
            raise ManifestError(f"{source}: [browser] needs {key!r}")
    if not data.get("hosts"):
        raise ManifestError(f"{source}: a browser road names the hosts it may reach")
    for level in levels:
        if level.name not in ("read", "write"):
            raise ManifestError(f"{source}: browser levels are read and write, "
                                f"not {level.name!r}")
    for tool, klass in verbs.items():
        if tool not in BROWSER_TOOLS:
            raise ManifestError(f"{source}: {tool!r} is not a browser tool "
                                f"(known: {', '.join(BROWSER_TOOLS)})")
        if tool in BROWSER_ACTS and klass == "read":
            raise ManifestError(f"{source}: {tool!r} can change the site; it is never read")
    return Browser(
        start_url=spec["start_url"], login_url=spec.get("login_url") or spec["start_url"],
        signed_in=tuple(spec["signed_in"]),
        home_from_cookie=bool(spec.get("home_from_cookie", False)),
        spend_pages=tuple(spec.get("spend_pages") or ()),
        spend_words=tuple(word.lower() for word in spec.get("spend_words") or ()),
        pace=float(spec.get("pace", 1.0)), max_actions=int(spec.get("max_actions", 20)),
        guide=str(spec.get("guide", "")).strip(), headed=bool(spec.get("headed", False)))


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
