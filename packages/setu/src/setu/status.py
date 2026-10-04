"""What Setu can tell a harness: connections, connectors, never a key.

A harness that wants to offer a person's connections needs three things:
which connections exist (and at what level), which connectors are
installed but not connected, and how to start each connection's
connector. ``report()`` is that answer as one plain dict, and
``setu status --json`` prints the same dict.

ONE ANSWER, TWO ROADS. A harness with Setu installed in its own Python
environment calls ``report()`` directly; one without runs the command and
reads the JSON. Both roads go through this function, so they cannot say
different things -- the JSON is the contract, and the import is only a
shortcut to it.

NO SECRET IS IN IT. The report is built from ``connections.public()`` and
the manifests; nothing in the vault's ``secret`` field is read here. A
harness may log this, show it on a page, or put parts of it in a prompt.

THE CATALOG'S WORD RIDES ALONG. When a signed index is kept
(catalog.py), each connector carries its label, author, install count
and -- if the installed version was withdrawn -- why; a withdrawn one is
also a problem, so a harness that reads nothing else still sees it.

A BROWSER ROAD IS A PROFILE, NOT A SERVER. Its connection has no ``mcp``
(nothing to run); it carries ``browser`` instead -- the profile, the
browser that wrote it, where to start -- and its connector card carries
the manifest's ``[browser]`` table: hosts, spending guards, pace, guide.
A profile path is not a secret the way a key is, but it is where the
cookies are, so it is said only to the harness, as the key's location is.

WHERE TO WATCH. ``watch`` names the two places whose change means the
report would change: the vault (every connect, disconnect and level) and
the folder of sites added here (a new site, a kept guide). A harness
mid-session compares their times before each turn and asks again only
when one moved -- cheaper than running ``setu status`` every turn.

The ``format`` field names the shape. A harness should refuse a format it
does not know rather than guess at one.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path
from typing import Any

from setu import __version__, catalog, certify, config, connections, health
from setu import browser as site_browser
from setu.manifest import Manifest, ManifestError, installed, sites_dir
from setu.vault import FileVault, Vault

FORMAT = "setu.status.v1"


def _setu_command() -> str:
    beside = Path(sys.executable).parent / "setu"
    if beside.exists():
        return str(beside)
    return shutil.which("setu") or "setu"


def _not_ready(manifest: Manifest, setup: dict[str, Any]) -> tuple[str, str]:
    """Why this connector cannot be signed in to yet, and the ``setup``
    key that would fix it -- ("", "") when it can."""
    if manifest.auth == "google" and not setup.get("google_client_file"):
        return ("needs a Google 'Desktop app' OAuth client file "
                "(setu config client-file PATH)", "google_client_file")
    if (manifest.auth == "homeassistant" and not setup.get("homeassistant_url")
            and manifest.id not in setup.get("_ha_connected", ())):
        return ("needs your Home Assistant's address "
                "(setu config homeassistant-url URL)", "homeassistant_url")
    if manifest.auth == "browser" and not setup.get("browser"):
        return ("needs Chrome, Chromium, Brave or Edge to sign in with "
                "(setu config browser PATH)", "browser")
    return "", ""


def _browser_card(manifest: Manifest) -> dict[str, Any] | None:
    spec = manifest.browser
    if spec is None:
        return None
    return {"start_url": spec.start_url, "spend_pages": list(spec.spend_pages),
            "spend_words": list(spec.spend_words), "pace": spec.pace,
            "max_actions": spec.max_actions, "guide": spec.guide, "headed": spec.headed}


def _connector(manifest: Manifest, connected: bool,
               setup: dict[str, Any] | None = None,
               index: catalog.Index | None = None) -> dict[str, Any]:
    not_ready, needs = _not_ready(manifest, setup or {})
    if manifest.local:
        # added on this computer: no catalog has a word on it
        card = {"label": catalog.LOCAL, "author": "", "installs": None, "yanked": ""}
    elif index is not None:
        card = index.card(manifest.id)
    else:
        card = {"label": None, "author": "", "installs": None, "yanked": ""}
    return {
        "id": manifest.id,
        "name": manifest.name,
        "summary": manifest.summary,
        "road": manifest.road,
        "hosts": list(manifest.hosts),
        "default_level": manifest.default_level.name,
        "levels": [{"name": level.name, "label": level.label,
                    "description": level.description, "scopes": list(level.scopes)}
                   for level in manifest.levels],
        "verbs": dict(manifest.verbs),
        "auth": manifest.auth,
        # False: the site has no scopes, and the connector keeps the level
        "enforced_by_site": manifest.scoped,
        "connected": connected,
        "ready": not not_ready,
        "not_ready": not_ready,
        "needs_setup": needs,
        # from the signed catalog, when one is kept: who wrote it, how many
        # installed it, and why the installed version was withdrawn
        "label": card["label"],
        "author": card["author"],
        "author_signed": card.get("author_signed", ""),
        "installs": card["installs"],
        "yanked": card["yanked"],
        # the browser road's rules, for the harness that drives the profile
        "browser": _browser_card(manifest),
        # what it can reach if something was missed -- as it is, not as hoped
        "contained": contained(manifest.road, list(manifest.hosts), manifest.name),
    }


def contained(road: str, hosts: list[str], name: str) -> str:
    """One honest line on what a connector can reach. Today a connector
    is its own program holding the connection's key, and Setu does not
    confine its network; the line says that rather than a hope. (Setu
    making the requests itself, so the key never enters the program, is
    the proxy design -- not built.)"""
    where = ", ".join(hosts[:4]) + ("…" if len(hosts) > 4 else "") if hosts else "no host named"
    if road == "browser":
        return (f"a browser profile: the agent's site tools keep to {where}; buying and "
                "paying are handed to you; the pages' own scripts are not limited")
    return (f"runs as its own program with your {name} key; declares {where}; Setu does "
            "not yet limit where it connects")


def report(vault: Vault | None = None) -> dict[str, Any]:
    vault = vault or FileVault()
    try:
        problems: list[str] = []
        manifests = installed(problems)
    except ManifestError as exc:
        manifests, problems = {}, [str(exc)]
    command = _setu_command()
    try:
        setup = {"google_client_file": config.google_client_file(),
                 "homeassistant_url": config.homeassistant_url(),
                 "browser": site_browser.find_browser()}
    except ValueError as exc:
        setup = {"google_client_file": None, "homeassistant_url": None, "browser": None}
        problems.append(str(exc))
    try:
        # a catalog kept from an address is asked again at most daily
        index, stale = catalog.current()
        if stale:
            problems.append(stale)
        if index is not None:
            catalog.ping_installs(index)      # once per version; never raises
    except catalog.CatalogError as exc:
        index = None
        problems.append(f"catalog: {exc}")
    rows = []
    for ref in vault.list():
        entry = connections.public(vault.get(ref) or {})
        manifest = manifests.get(entry.get("connector", ""))
        label = entry.get("level", "")
        if manifest is not None:
            try:
                label = manifest.level(entry.get("level")).label
            except ManifestError:
                pass
        else:
            problems.append(f"{ref}: its connector {entry.get('connector')!r} is not installed")
        rows.append({
            "ref": ref,
            "connector": entry.get("connector", ""),
            "account": entry.get("account", ""),
            "email": entry.get("email", ""),
            "level": entry.get("level", ""),
            "level_label": label,
            "scopes": list(entry.get("scopes") or []),
            "last_used": connections.last_used(entry),
            # a week of what went wrong on a browser connection (health.py)
            "health": health.week(ref) if entry.get("auth") == "browser" else {},
            "installed": manifest is not None,
            "base_url": entry.get("base_url"),
            "mcp": (None if entry.get("auth") == "browser" else
                    {"name": ref.replace(":", "-"), "command": command, "args": ["run", ref]}),
            "browser": ({"profile": entry.get("profile", ""),
                         "executable": entry.get("browser", ""), "home": entry.get("home", "")}
                        if entry.get("auth") == "browser" else None),
        })
    connected = {row["connector"] for row in rows}
    # a connection already knows its server, so signing in again needs no
    # remembered address (cli._ha_base); private key, not in the report
    ready_setup = {**setup, "_ha_connected": {r["connector"] for r in rows if r["base_url"]}}
    return {
        "format": FORMAT,
        "version": __version__,
        "command": command,
        "connections": rows,
        "connectors": (cards := [{**_connector(m, m.id in connected, ready_setup, index),
                                  "certified": certify.certified(index, "connector", m.id)}
                                 for m in manifests.values()]),
        "setup": setup,
        "catalog": ({"source": index.source, "key": index.key,
                     "issued": index.data.get("issued", ""),
                     "recipes": [{**r, "author_signed": catalog.author_line(r),
                                  "works_line": catalog.works_line(r),
                                  "certified": certify.certified(index, "recipe",
                                                                 r.get("name", ""))}
                                 for r in index.recipes],
                     # listed but not here: what a page may offer to install
                     "connectors": [
                         {**{k: c.get(k) for k in ("id", "name", "summary", "label",
                                                   "author", "installs", "version")},
                          "author_signed": catalog.author_line(c),
                          "contained": contained(str(c.get("road") or "api"),
                                                 list(c.get("hosts") or []),
                                                 str(c.get("name") or cid)),
                          "certified": certify.certified(index, "connector", cid)}
                         for cid, c in index.connectors.items()
                         if cid not in manifests and (c.get("wheel") or {}).get("sha256")]}
                    if index is not None else None),
        "problems": problems + [f"{c['id']}: withdrawn by Setu -- {c['yanked']}"
                                for c in cards if c["yanked"]],
        "watch": [str(getattr(vault, "path", "")) or None, str(sites_dir())],
    }
