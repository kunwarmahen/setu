"""`setu`: connect a site, see what is connected, run a connector.

    setu connectors                      what is installed, and its levels
    setu connect gmail --client-file F   sign in (browser), Read only by default
    setu list                            your connections -- never a key
    setu run gmail:personal              start the connector (an MCP server)
    setu mcp-config gmail:personal       the snippet a harness needs
    setu disconnect gmail:personal       revoke at Google, then forget
    setu status --json                   the same, for a harness to read
    setu config client-file PATH         remember the client file, for every harness
    setu connect homeassistant --as home   your Home Assistant's own login page
    setu connect homeassistant --token-stdin   or a long-lived token, pasted
    setu config homeassistant-url URL    remember where your Home Assistant is

Every command a harness needs is ``setu run``: it is what goes in an MCP
config's ``command``, so the harness starts Setu, Setu starts the
connector, and the key stays with Setu.

``--client-file`` is the "Desktop app" OAuth client JSON downloaded from
the Google Cloud console. It is read once, at connect time; what the
refresh needs is kept in the vault with the connection. ``setu config
client-file PATH`` remembers its path, so neither a person nor a
harness has to pass it again (config.py).

``setu connect --json`` is the same sign-in for a harness's page: one
JSON object per line on stdout -- ``started``, ``url`` (the address to
open), then ``connected`` or ``error`` -- so nothing reads prose.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import webbrowser
from pathlib import Path

import httpx

from setu import config, connections, google, helper, homeassistant
from setu.manifest import ManifestError, find, installed
from setu.vault import FileVault, VaultError

ENV_CLIENT_FILE = config.ENV_CLIENT_FILE


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
        if not manifest.scoped:
            print("    (the site has no scopes: the connector keeps to the level)")
    return 0


def _emit(event: str, **fields: object) -> None:
    """One line of ``connect --json``: flushed, so a harness sees it now."""
    print(json.dumps({"event": event, **fields}), flush=True)


def _connect(args: argparse.Namespace) -> int:
    if args.json:
        try:
            return _connect_json(args)
        except Exception as exc:     # every failure is a line, never a traceback
            _emit("error", message=str(exc) or type(exc).__name__)
            return 2
    manifest = find(args.connector)
    if manifest.auth == "homeassistant":
        return _connect_homeassistant(manifest, args)
    path = config.google_client_file(args.client_file)
    if not path:
        print(f"error: {manifest.name} needs a Google 'Desktop app' OAuth client. "
              f"Pass --client-file PATH, set {ENV_CLIENT_FILE}, or remember it with "
              "`setu config client-file PATH`; the README walks through making one.",
              file=sys.stderr)
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


def _ha_base(_manifest, args: argparse.Namespace) -> str | None:
    return config.homeassistant_url(args.url)


def _read_token(args: argparse.Namespace) -> str | None:
    """A pasted long-lived token, from stdin -- never from argv, where
    every process on the machine could read it."""
    if not args.token_stdin:
        return None
    if sys.stdin.isatty():
        import getpass
        token = getpass.getpass("Home Assistant long-lived token (not shown): ")
    else:
        token = sys.stdin.readline()
    token = token.strip()
    if not token:
        raise connections.ConnectionFailed("no token was given on stdin")
    return token


def _connect_homeassistant(manifest, args: argparse.Namespace) -> int:
    base = _ha_base(manifest, args)
    if not base:
        print(f"error: {manifest.name} needs your Home Assistant's address. Pass --url URL, "
              f"set {config.ENV_HA_URL}, or remember it with `setu config "
              "homeassistant-url URL`.", file=sys.stderr)
        return 2
    level = manifest.level(args.level)
    ref = connections.ref_for(manifest.id, args.account)
    token = _read_token(args)
    print(f"connecting {ref} at '{level.label}' on {base}.")
    print(f"    {level.description}")
    if token is None:
        print("A browser window is opening on your Home Assistant's login page. "
              "Sign in there, then come back here.")
    with httpx.Client() as http:
        entry = connections.connect_homeassistant(
            manifest, args.account, level=level.name, base_url=base, vault=FileVault(),
            http=http, long_lived=token,
            open_browser=None if args.no_browser else webbrowser.open,
            on_url=lambda url: print(f"\nIf no window opened, open this address:\n{url}\n"))
    print(f"connected {ref} to {entry['email']} — {level.label}")
    print(f"next: setu mcp-config {ref}")
    return 0


def _connect_json(args: argparse.Namespace) -> int:
    """The sign-in, as events. The browser is never opened from here: the
    harness shows the address to the person, in the page they are using."""
    manifest = find(args.connector)
    if manifest.auth == "homeassistant":
        return _connect_homeassistant_json(manifest, args)
    path = config.google_client_file(args.client_file)
    if not path:
        _emit("error", message=f"{manifest.name} needs a Google 'Desktop app' OAuth "
              "client file: `setu config client-file PATH`", setup="google_client_file")
        return 2
    client = google.client_from_file(Path(path))
    level = manifest.level(args.level)
    ref = connections.ref_for(manifest.id, args.account)
    _emit("started", ref=ref, level=level.name, level_label=level.label,
          scopes=list(level.scopes))
    with httpx.Client() as http:
        entry = connections.connect(
            manifest, args.account, level=level.name, client=client,
            vault=FileVault(), http=http, open_browser=None,
            on_url=lambda url: _emit("url", url=url))
    held = manifest.level(entry["level"])
    _emit("connected", ref=ref, email=entry.get("email") or "", level=held.name,
          level_label=held.label, asked_level=entry.get("asked_level", held.name))
    return 0


def _connect_homeassistant_json(manifest, args: argparse.Namespace) -> int:
    base = _ha_base(manifest, args)
    if not base:
        _emit("error", message=f"{manifest.name} needs your Home Assistant's address: "
              "`setu config homeassistant-url URL`", setup="homeassistant_url")
        return 2
    level = manifest.level(args.level)
    ref = connections.ref_for(manifest.id, args.account)
    token = _read_token(args)
    _emit("started", ref=ref, level=level.name, level_label=level.label, scopes=[],
          base_url=homeassistant.normalise_url(base))
    with httpx.Client() as http:
        entry = connections.connect_homeassistant(
            manifest, args.account, level=level.name, base_url=base, vault=FileVault(),
            http=http, long_lived=token, open_browser=None,
            on_url=lambda url: _emit("url", url=url))
    _emit("connected", ref=ref, email=entry["email"], level=level.name,
          level_label=level.label, asked_level=level.name)
    return 0


def _config(args: argparse.Namespace) -> int:
    """``setu config`` shows the settings; ``setu config KEY VALUE`` sets
    one; ``setu config KEY --unset`` forgets it."""
    if not args.key:
        data = config.load()
        for name, key in config.KEYS.items():
            print(f"{name}: {data.get(key) or '(not set)'}")
        return 0
    key = config.KEYS.get(args.key)
    if key is None:
        print(f"error: unknown setting {args.key!r} (known: {', '.join(config.KEYS)})",
              file=sys.stderr)
        return 2
    if args.unset:
        config.save(key, None)
        print(f"{args.key}: forgotten")
        return 0
    if not args.value:
        print(f"{args.key}: {config.load().get(key) or '(not set)'}")
        return 0
    if key == "homeassistant_url":
        value = homeassistant.normalise_url(args.value)
    else:
        path = Path(args.value).expanduser().resolve()
        google.client_from_file(path)   # a Web client, or no file, is refused now
        value = str(path)
    config.save(key, value)
    print(f"{args.key}: {value}")
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
        # a server of the person's own (Home Assistant) is the connection's
        # address, not the manifest's
        return helper.run(args.ref, manifest.command, vault=vault, http=http,
                          api_base=entry.get("base_url") or manifest.api_base)


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
    vault = FileVault()
    entry = vault.get(args.ref) or {}
    with httpx.Client() as http:
        existed, revoked = connections.disconnect(args.ref, vault=vault, http=http)
    if not existed:
        print(f"no connection {args.ref!r}")
        return 1
    if entry.get("auth") == "homeassistant":
        base = entry.get("base_url", "your Home Assistant")
        if (entry.get("secret") or {}).get("kind") == "long_lived":
            print(f"disconnected {args.ref} and deleted its token here. A long-lived token "
                  f"cannot be revoked from outside: delete it in your profile on {base} "
                  "(Security → Long-lived access tokens)")
        elif revoked:
            print(f"disconnected {args.ref}: {base} was asked to revoke the sign-in, and "
                  "the key is deleted")
        else:
            print(f"disconnected {args.ref} here, but {base} could not be reached to revoke "
                  "it -- remove it from your profile there (Security → Refresh tokens)")
        return 0
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
    connect.add_argument("--json", action="store_true",
                         help="events as JSON lines, for a harness's page (no browser)")
    connect.add_argument("--url", help="your Home Assistant's address "
                         "(default: setu config homeassistant-url)")
    connect.add_argument("--token-stdin", action="store_true",
                         help="Home Assistant: read a long-lived token from stdin "
                         "instead of signing in on its login page")

    sub.add_parser("list", help="your connections")

    run = sub.add_parser("run", help="start a connector for a connection")
    run.add_argument("ref", help="e.g. gmail:personal")

    mcp_config = sub.add_parser("mcp-config", help="print the MCP config for a harness")
    mcp_config.add_argument("ref")
    mcp_config.add_argument("--for", dest="target", choices=["yantra", "claude"],
                        default="yantra")

    status = sub.add_parser("status", help="connections and connectors, for a harness")
    status.add_argument("--json", action="store_true", help="machine-readable, no secrets")

    disconnect = sub.add_parser("disconnect", help="revoke and forget a connection")
    disconnect.add_argument("ref")

    settings = sub.add_parser("config", help="show or remember a setting (never a key)")
    settings.add_argument("key", nargs="?", help=", ".join(config.KEYS))
    settings.add_argument("value", nargs="?")
    settings.add_argument("--unset", action="store_true", help="forget the setting")
    return parser


COMMANDS = {"connectors": _connectors, "connect": _connect, "list": _list,
            "run": _run, "mcp-config": _mcp_config, "status": _status,
            "disconnect": _disconnect, "config": _config}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return COMMANDS[args.command](args)
    except (connections.ConnectionFailed, google.GoogleAuthError,
            homeassistant.HomeAssistantError, ManifestError, VaultError, ValueError) as exc:
        # `setu run` speaks MCP on stdout, so every complaint goes to stderr.
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\n(cancelled -- nothing saved)", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
