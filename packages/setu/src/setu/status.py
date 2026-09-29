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

The ``format`` field names the shape. A harness should refuse a format it
does not know rather than guess at one.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path
from typing import Any

from setu import __version__, config, connections
from setu.manifest import Manifest, ManifestError, installed
from setu.vault import FileVault, Vault

FORMAT = "setu.status.v1"


def _setu_command() -> str:
    beside = Path(sys.executable).parent / "setu"
    if beside.exists():
        return str(beside)
    return shutil.which("setu") or "setu"


def _not_ready(manifest: Manifest, client_file: str | None) -> str:
    """Why this connector cannot be signed in to yet, or "" when it can."""
    if manifest.auth == "google" and not client_file:
        return ("needs a Google 'Desktop app' OAuth client file "
                "(setu config client-file PATH)")
    return ""


def _connector(manifest: Manifest, connected: bool,
               client_file: str | None = None) -> dict[str, Any]:
    not_ready = _not_ready(manifest, client_file)
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
        "connected": connected,
        "ready": not not_ready,
        "not_ready": not_ready,
    }


def report(vault: Vault | None = None) -> dict[str, Any]:
    vault = vault or FileVault()
    try:
        manifests = installed()
        problems: list[str] = []
    except ManifestError as exc:
        manifests, problems = {}, [str(exc)]
    command = _setu_command()
    try:
        client_file = config.google_client_file()
    except ValueError as exc:
        client_file = None
        problems.append(str(exc))
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
            "last_used": entry.get("last_used"),
            "installed": manifest is not None,
            "mcp": {"name": ref.replace(":", "-"), "command": command, "args": ["run", ref]},
        })
    connected = {row["connector"] for row in rows}
    return {
        "format": FORMAT,
        "version": __version__,
        "command": command,
        "connections": rows,
        "connectors": [_connector(m, m.id in connected, client_file)
                       for m in manifests.values()],
        "setup": {"google_client_file": client_file},
        "problems": problems,
    }
