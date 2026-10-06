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

REQUESTS ARE CHECKED A SECOND TIME, BY SETU. A connector does not hold
the key: it asks Setu, over a socket, to make each request for it (see
proxy.py). The ``[requests.<level>]`` tables say which requests each
level may make, as ``"METHOD /path"`` with ``*`` globs: ``allow`` adds to
the levels below it, ``deny`` applies to its own level only (a "control"
level that may call services, except locks). A request no rule allows
is refused before it leaves the computer -- underneath the site's own
scopes, and the only check at all where the site has none. A manifest
with no ``[requests]`` lets its connector make any request to its own
host, and says so. ``mcp_path`` names the address of a site's own MCP
server: requests there are read, and a ``tools/call`` at the first level
must name a tool the verbs class as ``read``.

``token_mode = "callback"`` is the exception, for an API that cannot go
through Setu: the connector is handed a short-lived token instead.

Discovery is by entry point: a connector package names its manifest in
the ``setu.connectors`` group, so installing it is registering it.

A SITE CAN ALSO BE ADDED BY HAND. A browser-road manifest needs no code,
so a person may drop one in ``sites/`` beside the vault
(``~/.local/state/setu/sites/example.toml``) and it is listed with the
installed ones, marked as made on this computer. Only the browser road
is accepted there: a manifest naming a program would make a dropped file
a way to run one. An installed connector of the same id wins, the file's
name must be its id, and a file that cannot be read is reported and
skipped -- it never takes the installed connectors down with it.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from dataclasses import replace as _replace
from importlib.metadata import entry_points
from pathlib import Path
from typing import Any

from setu.vault import default_home

ENTRY_POINT_GROUP = "setu.connectors"
#: Where hand-added browser-road manifests live, under Setu's home.
SITES = "sites"
VERB_CLASSES = ("read", "write", "spend")
#: The verbs key that classes every tool a manifest does not list.
ANY_TOOL = "*"
#: Auth kinds whose provider enforces scopes, so each level must name some.
SCOPED_AUTH = ("google",)
KNOWN_KEYS = {"id", "name", "summary", "road", "auth", "command", "api_base",
              "hosts", "whoami", "levels", "verbs", "browser", "generated",
              "requests", "mcp_path", "token_mode"}
TOKEN_MODES = ("proxy", "callback")
#: The methods a ``[requests]`` rule may name.
METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE")
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
class Requests:
    """One level's ``[requests]`` rules, as written."""

    allow: tuple[str, ...] = ()
    deny: tuple[str, ...] = ()


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
    #: Read from ``sites/`` on this computer, not from an installed package.
    local: bool = False
    #: Written by ``setu connect --site`` with cautious defaults: no one
    #: named its sign-in cookies, so a sign-in is proved by the page.
    generated: bool = False
    #: Per level, the requests Setu makes for it; empty = any to its host.
    requests: dict[str, Requests] = field(default_factory=dict)
    mcp_path: str = ""
    token_mode: str = "proxy"

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
    requests = _requests(data, levels, source)
    mode = data.get("token_mode", "proxy")
    if mode not in TOKEN_MODES:
        raise ManifestError(f"{source}: token_mode is {mode!r} (known: "
                            f"{', '.join(TOKEN_MODES)})")
    who = data.get("whoami")
    return Manifest(
        id=data["id"], name=data["name"], summary=data.get("summary", ""),
        road=data["road"], auth=data["auth"], command=tuple(command),
        api_base=data.get("api_base", ""), hosts=tuple(data.get("hosts") or ()),
        whoami=WhoAmI(url=who["url"], field=who["field"]) if who else None,
        levels=tuple(levels), verbs=verbs, browser=browser,
        generated=bool(data.get("generated", False)),
        requests=requests, mcp_path=str(data.get("mcp_path", "")), token_mode=mode,
    )


def _requests(data: dict[str, Any], levels: list[Level], source: str) -> dict[str, Requests]:
    spec = data.get("requests") or {}
    names = {level.name for level in levels}
    found: dict[str, Requests] = {}
    for name, table in spec.items():
        if name not in names:
            raise ManifestError(f"{source}: [requests.{name}] names no level")
        if not isinstance(table, dict) or set(table) - {"allow", "deny"}:
            raise ManifestError(f"{source}: [requests.{name}] takes allow and deny")
        rules = {}
        for key in ("allow", "deny"):
            rules[key] = tuple(table.get(key) or ())
            for rule in rules[key]:
                method, _, path = str(rule).partition(" ")
                if method not in METHODS or not path.startswith("/"):
                    raise ManifestError(f"{source}: [requests.{name}] {key} {rule!r} is "
                                        "not \"METHOD /path\"")
        found[name] = Requests(allow=rules["allow"], deny=rules["deny"])
    if data.get("road") == "browser" and (found or data.get("mcp_path")):
        raise ManifestError(f"{source}: a browser road makes no requests through Setu")
    return found


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
    if not spec.get("start_url"):
        raise ManifestError(f"{source}: [browser] needs 'start_url'")
    if "signed_in" not in spec or (not spec["signed_in"] and not data.get("generated")):
        # a written-by-hand site names what "signed in" means; only one
        # Setu wrote may leave it to the page
        raise ManifestError(f"{source}: [browser] needs 'signed_in'")
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


def sites_dir() -> Path:
    return default_home() / SITES


def local(directory: Path | None = None) -> tuple[dict[str, Manifest], list[str]]:
    """The browser-road manifests added on this computer, by id, and what
    was wrong with the files that were skipped."""
    directory = directory or sites_dir()
    found: dict[str, Manifest] = {}
    problems: list[str] = []
    if not directory.is_dir():
        return found, problems
    for path in sorted(directory.glob("*.toml")):
        try:
            manifest = load(path)
        except (ManifestError, tomllib.TOMLDecodeError, OSError) as exc:
            problems.append(f"{path}: skipped -- {exc}")
            continue
        if manifest.road != "browser":
            problems.append(f"{path}: skipped -- only a site reached through the browser "
                            "may be added here; a connector that runs a program is installed "
                            "as a package")
            continue
        if manifest.id != path.stem:
            problems.append(f"{path}: skipped -- its id is {manifest.id!r}; name the file "
                            f"{manifest.id}.toml")
            continue
        found[manifest.id] = _replace(manifest, local=True)
    return found, problems


def installed(problems: list[str] | None = None) -> dict[str, Manifest]:
    """Every connector installed in this environment, then every site
    added on this computer, by id. What was skipped among the added
    sites is appended to ``problems`` when given."""
    found: dict[str, Manifest] = {}
    for point in entry_points(group=ENTRY_POINT_GROUP):
        manifest = load(Path(point.load()))
        if manifest.id != point.name:
            raise ManifestError(f"entry point {point.name!r} loads a manifest "
                                f"whose id is {manifest.id!r}")
        found[manifest.id] = manifest
    added, skipped = local()
    for cid, manifest in added.items():
        if cid in found:
            skipped.append(f"{sites_dir() / (cid + '.toml')}: skipped -- {cid!r} is "
                           "installed already, and the installed one is used")
            continue
        found[cid] = manifest
    if problems is not None:
        problems.extend(skipped)
    return found


def find(connector_id: str) -> Manifest:
    skipped: list[str] = []
    found = installed(skipped)
    if connector_id not in found:
        have = ", ".join(sorted(found)) or "none"
        why = "".join(f"\n  {line}" for line in skipped if connector_id in line)
        raise ManifestError(f"no connector {connector_id!r} is installed "
                            f"(installed: {have}); try `uv pip install "
                            f"setu-{connector_id}`{why}")
    return found[connector_id]
