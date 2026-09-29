"""`setu`: connect a site, see what is connected, run a connector.

    setu connectors                      what is installed, and its levels
    setu connect gmail --client-file F   sign in (browser), Read only by default
    setu list                            your connections -- never a key
    setu run gmail:personal              start the connector (an MCP server)
    setu mcp-config gmail:personal       the snippet a harness needs
    setu disconnect gmail:personal       revoke at Google, then forget
    setu status --json                   the same, for a harness to read

Every command a harness needs is ``setu run``: it is what goes in an MCP
config's ``command``, so the harness starts Setu, Setu starts the
connector, and the key stays with Setu.

``--client-file`` is the "Desktop app" OAuth client JSON downloaded from
the Google Cloud console. It is read once, at connect time; what the
refresh needs is kept in the vault with the connection.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import webbrowser
from pathlib import Path

import httpx

from setu import connections, google, helper
from setu.manifest import ManifestError, find, installed
from setu.vault import FileVault, VaultError

ENV_CLIENT_FILE = "SETU_GOOGLE_CLIENT_FILE"


def _connectors(_args: argparse.Namespace) -> int:
    found = installed()
    if not found:
        print("no connectors installed (try: uv pip install setu-gmail)")
        return 0
    for manifest in found.values():
        print(f"{manifest.id} — {manifest.name}: {manifest.summary}")
        for level in manifest.levels:
            mark = " (default)" if level is manifest.default_level else ""
            print(f"    {level.name:<8} {level.label}{mark}")
            for scope in level.scopes:
                print(f"             {scope}")
    return 0


def _connect(args: argparse.Namespace) -> int:
    manifest = find(args.connector)
    path = args.client_file or os.environ.get(ENV_CLIENT_FILE)
    if not path:
        print(f"error: {manifest.name} needs a Google 'Desktop app' OAuth client. "
              f"Pass --client-file PATH (or set {ENV_CLIENT_FILE}); the README "
              "walks through making one.", file=sys.stderr)
        return 2
    client = google.client_from_file(Path(path))
    level = manifest.level(args.level)
    ref = connections.ref_for(manifest.id, args.account)
    print(f"connecting {ref} at '{level.label}'. Google will ask you to allow:")
    for scope in level.scopes:
        print(f"    {scope}")
    print("A browser window is opening. Sign in there, then come back here.")
    with httpx.Client() as http:
        entry = connections.connect(
            manifest, args.account, level=level.name, client=client,
            vault=FileVault(), http=http,
            open_browser=None if args.no_browser else webbrowser.open,
            on_url=lambda url: print(f"\nIf no window opened, open this address:\n{url}\n"))
    held = manifest.level(entry["level"])
    print(f"connected {ref} as {entry['email'] or '(address unknown)'} — {held.label}")
    if entry["level"] != entry["asked_level"]:
        print(f"note: you asked for '{level.label}' but Google granted less, so this "
              f"connection is '{held.label}'.")
    print(f"next: setu mcp-config {ref}")
    return 0


def _list(_args: argparse.Namespace) -> int:
    vault = FileVault()
    refs = vault.list()
    if not refs:
        print("no connections yet (setu connect gmail --client-file ...)")
        return 0
    known = installed()
    for ref in refs:
        entry = connections.public(vault.get(ref) or {})
        manifest = known.get(entry.get("connector", ""))
        label = entry.get("level", "?")
        if manifest is not None:
            try:
                label = manifest.level(entry.get("level")).label
            except ManifestError:
                pass
        used = entry.get("last_used") or "never"
        print(f"{ref:<22} {entry.get('email') or '':<30} {label:<16} last used {used}")
    print(f"\nkeys live in {vault.path} (readable by you only); no command prints them")
    return 0


def _run(args: argparse.Namespace) -> int:
    vault = FileVault()
    entry = vault.get(args.ref)
    if entry is None:
        print(f"error: no connection {args.ref!r} (setu list)", file=sys.stderr)
        return 2
    manifest = find(entry["connector"])
    with httpx.Client() as http:
        return helper.run(args.ref, manifest.command, vault=vault, http=http,
                          api_base=manifest.api_base)


def _mcp_config(args: argparse.Namespace) -> int:
    if FileVault().get(args.ref) is None:
        print(f"error: no connection {args.ref!r} (setu list)", file=sys.stderr)
        return 2
    name = args.ref.replace(":", "-")
    # The FULL path: a harness starts this with its own PATH, which need
    # not include wherever Setu was installed.
    server = {"command": _setu_path(), "args": ["run", args.ref]}
    key = "mcpServers" if args.target == "claude" else "servers"
    print(json.dumps({key: {name: server}}, indent=2))
    return 0


def _setu_path() -> str:
    beside = Path(sys.executable).parent / "setu"
    if beside.exists():
        return str(beside)
    return shutil.which("setu") or "setu"


def _status(args: argparse.Namespace) -> int:
    from setu.status import report

    data = report()
    if args.json:
        print(json.dumps(data, indent=2))
        return 0
    for row in data["connections"]:
        print(f"{row['ref']:<22} {row['email']:<30} {row['level_label']}")
    for connector in data["connectors"]:
        if not connector["connected"]:
            print(f"{connector['id']:<22} (installed, not connected)")
    for problem in data["problems"]:
        print(f"problem: {problem}")
    return 0


def _disconnect(args: argparse.Namespace) -> int:
    with httpx.Client() as http:
        existed, revoked = connections.disconnect(args.ref, vault=FileVault(), http=http)
    if not existed:
        print(f"no connection {args.ref!r}")
        return 1
    if revoked is None:
        print(f"disconnected {args.ref} and deleted its key. Google access is kept, because "
              "another connection uses the same Google account; disconnect that one too to "
              "remove it at Google")
    elif revoked:
        print(f"disconnected {args.ref}: Google revoked the grant, and the key is deleted")
    else:
        print(f"disconnected {args.ref} here, but Google could not confirm the revoke -- "
              "check https://myaccount.google.com/connections and remove it there")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="setu", description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("connectors", help="installed connectors and their access levels")

    connect = sub.add_parser("connect", help="sign in to a site")
    connect.add_argument("connector", help="e.g. gmail")
    connect.add_argument("--as", dest="account", default="personal",
                         help="your name for this account (default: personal)")
    connect.add_argument("--level", help="access level (default: the least one)")
    connect.add_argument("--client-file", help="the Desktop app OAuth client JSON")
    connect.add_argument("--no-browser", action="store_true",
                         help="print the address instead of opening a browser")

    sub.add_parser("list", help="your connections")

    run = sub.add_parser("run", help="start a connector for a connection")
    run.add_argument("ref", help="e.g. gmail:personal")

    config = sub.add_parser("mcp-config", help="print the MCP config for a harness")
    config.add_argument("ref")
    config.add_argument("--for", dest="target", choices=["yantra", "claude"],
                        default="yantra")

    status = sub.add_parser("status", help="connections and connectors, for a harness")
    status.add_argument("--json", action="store_true", help="machine-readable, no secrets")

    disconnect = sub.add_parser("disconnect", help="revoke and forget a connection")
    disconnect.add_argument("ref")
    return parser


COMMANDS = {"connectors": _connectors, "connect": _connect, "list": _list,
            "run": _run, "mcp-config": _mcp_config, "status": _status,
            "disconnect": _disconnect}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return COMMANDS[args.command](args)
    except (connections.ConnectionFailed, google.GoogleAuthError, ManifestError,
            VaultError) as exc:
        # `setu run` speaks MCP on stdout, so every complaint goes to stderr.
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\n(cancelled -- nothing saved)", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
