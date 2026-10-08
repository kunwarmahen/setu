"""`setu`: connect a site, see what is connected, run a connector.

    setu connectors                      what is installed, and its levels
    setu connect gmail --client-file F   sign in (browser), Read only by default
    setu list                            your connections -- never a key
    setu run gmail:personal              start the connector (an MCP server); it holds
                                         no key and has no network -- Setu makes its requests
    setu log gmail:personal              the requests Setu made for it, and what it refused
    setu lock set                        lock this folder with a passphrase (asked, hidden)
    setu lock unlock                     print the key that opens it (for whoever holds it)
    setu lock seal                       pack its browser sign-ins away again
    setu lock status | change | remove
    setu mcp-config gmail:personal       the snippet a harness needs
    setu disconnect gmail:personal       revoke at Google, then forget
    setu status --json                   the same, for a harness to read
    setu serve [--port 8775]             all of it in a browser, at the address it prints
    setu config client-file PATH         remember the client file, for every harness
    setu connect homeassistant --as home   your Home Assistant's own login page
    setu connect homeassistant --token-stdin   or a long-lived token, pasted
    setu config homeassistant-url URL    remember where your Home Assistant is
    setu connect amazon --as personal    a site with no API: sign in in a window of its own
    setu connect --site example.com      any other site: Setu writes its rules once you sign in
    setu site guide example [--set TEXT] a site added here: its short guide, shown or replaced
    setu site event amazon:personal robot_check   a harness noting what went wrong (a week kept)
    setu config browser PATH             which browser that window is (default: Chrome on PATH)
    setu catalog                         the signed catalog: labels, installs, withdrawn
    setu catalog use PATH|URL            check an index (and its .sig) and keep it; a URL
                                         is the catalog server, asked again daily
    setu catalog publish INDEX --to URL  the maintainer: send a signed index to the server
    setu catalog counts INDEX --to URL   the maintainer: copy the server's install totals in
    setu config share-installs off       stop telling the catalog which connectors you install
    setu install notion                  a connector the catalog lists, its wheel checked by hash
    setu catalog submit DIR --to URL --author NAME          offer a recipe for listing
    setu catalog submit --connector ID --repo URL --commit SHA --to URL --author NAME
    setu catalog submission ID --to URL  how your submission went
    setu catalog review [ID] --to URL    the maintainer: the queue, or one in full
    setu catalog close ID --verdict accepted|declined --reason TEXT --to URL
    setu catalog review ID --save DIR --to URL     the maintainer: a recipe's files, to try
    setu catalog upload DIR --to URL     the maintainer: a recipe up, by its hash
    setu catalog recipe NAME --into DIR  a listed recipe, checked by hash, for a harness to install
    setu certify keygen KEY --as NAME    a certifier's key (independent of the catalog)
    setu certify sign --subject recipe:NAME --key KEY --statement TEXT --checks deployed,...
    setu certify trust CERTIFIER.pub     count this certifier's word on your cards
    setu certify fetch recipe:NAME       the exact version, by hash, to read and run yourself
    setu certify check DIR [--since OLD] [--run CMD]   a scan, what changed, a run offline
    setu certify publish CERT --to URL   send it to the catalog, for every reader to weigh

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
open), then ``connected`` or ``error`` -- so nothing reads prose. A
site Setu wrote the rules for may also send ``ask`` (a question for the
person) and then read one line, ``yes`` or ``no``, from stdin.

``setu connect --json --paste`` is for a person signing in on ANOTHER
device (a phone, through a chat): every line on stdin is an address
pasted back from the page that would not load, checked like the local
page's visit would be. One that does not belong is answered with a
``paste_refused`` event and the wait goes on. ``--timeout SECONDS``
bounds the wait (default 300).

``setu connect amazon --json --remote`` is a browser-road site signed in
to from ANOTHER device: Setu runs the browser on the connection's
profile and serves a page that streams it (remote.py). Events:
``started``, ``link`` (the address to send the person, and when it
stops working), ``opened`` (a device opened it), then ``connected`` or
``error``. Where it listens and the address in the link are
``SETU_WINDOW_HOST``, ``SETU_WINDOW_PORT`` and ``SETU_WINDOW_URL``.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import json
import os
import shutil
import sys
import threading
import webbrowser
from collections.abc import Callable
from pathlib import Path

import httpx

from setu import browser as site_browser
from setu import (
    catalog,
    certify,
    config,
    connections,
    google,
    health,
    helper,
    homeassistant,
    proxy,
    seal,
)
from setu.manifest import ManifestError, find, installed
from setu.vault import FileVault, VaultError

ENV_CLIENT_FILE = config.ENV_CLIENT_FILE


def _connectors(_args: argparse.Namespace) -> int:
    skipped: list[str] = []
    found = installed(skipped)
    for line in skipped:
        print(f"setu: {line}", file=sys.stderr)
    if not found:
        print("no connectors installed (try: uv pip install setu-gmail)")
        return 0
    for manifest in found.values():
        mark = " (added on this computer)" if manifest.local else ""
        print(f"{manifest.id} — {manifest.name}{mark}: {manifest.summary}")
        for level in manifest.levels:
            mark = " (default)" if level is manifest.default_level else ""
            print(f"    {level.name:<8} {level.label}{mark}")
            for scope in level.scopes:
                print(f"             {scope}")
        if manifest.road == "browser":
            print("    (signed in in a browser window; the harness keeps to the level)")
        elif not manifest.scoped:
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
    if args.site:
        return _connect_site(args)
    manifest = find(_connector_named(args))
    if args.phone:
        return _connect_phone(manifest, args)
    if manifest.auth == "homeassistant":
        return _connect_homeassistant(manifest, args)
    if manifest.auth == "browser":
        return _connect_browser(manifest, args)
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


def _ha_base(manifest, args: argparse.Namespace) -> str | None:
    """Which Home Assistant to sign in to: --url, then the environment and
    the remembered address, then -- signing in again to change a level --
    the address that connection already has."""
    found = config.homeassistant_url(args.url)
    if found:
        return found
    entry = FileVault().get(connections.ref_for(manifest.id, args.account)) or {}
    return entry.get("base_url") or None


def _remember_ha(base: str) -> None:
    """The first address used is remembered, so a page -- which has nowhere
    to type one -- can sign in again later. Never overwrites a choice."""
    if not config.load().get("homeassistant_url"):
        config.save("homeassistant_url", homeassistant.normalise_url(base))


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


def _connect_phone(manifest, args: argparse.Namespace) -> int:
    if manifest.phone is None:
        print(f"error: {manifest.name} has no phone app Setu knows of (its manifest "
              "has no [phone] table)", file=sys.stderr)
        return 2
    level = manifest.level(args.level)
    entry = connections.connect_phone(manifest, args.account, level=level.name,
                                      vault=FileVault())
    app = " / ".join(a for a in (manifest.phone.android, manifest.phone.ios) if a)
    print(f"connected {connections.ref_for(manifest.id, args.account)} on your phone, "
          f"through the {manifest.name} app ({app}): {level.label}")
    print(f"  Sign in to the {manifest.name} app on your phone yourself; Setu holds "
          "nothing for it. An agent that works your phone (Sparsh) keeps to this level, "
          "and never presses buy, pay or delete there.")
    return 0 if entry else 1


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
    _remember_ha(base)
    print(f"connected {ref} to {entry['email']} — {level.label}")
    print(f"next: setu mcp-config {ref}")
    return 0


def _site_browser(args: argparse.Namespace) -> str:
    found = site_browser.find_browser(args.browser)
    if not found:
        raise connections.ConnectionFailed(
            "no browser to sign in with: install Chrome or Chromium, or name one with "
            "`setu config browser PATH`")
    return found


def _connect_browser(manifest, args: argparse.Namespace) -> int:
    level = manifest.level(args.level)
    ref = connections.ref_for(manifest.id, args.account)
    found = _site_browser(args)
    print(f"connecting {ref} at '{level.label}'.")
    print(f"    {level.description}")
    print(f"A window of {found} is opening on {manifest.name}'s sign-in page, on a profile "
          "kept for this connection only.\nSign in there, then CLOSE THE WINDOW to finish.")
    entry = connections.connect_browser(manifest, args.account, level=level.name,
                                        vault=FileVault(), browser=found,
                                        ask=_terminal_ask(args))
    print(f"connected {ref} ({entry['email']}) — {level.label}")
    print(f"the sign-in lives in {entry['profile']}; `setu disconnect {ref}` deletes it")
    return 0


def _connect_browser_json(manifest, args: argparse.Namespace) -> int:
    level = manifest.level(args.level)
    ref = connections.ref_for(manifest.id, args.account)
    found = _site_browser(args)
    _emit("started", ref=ref, level=level.name, level_label=level.label, scopes=[])
    entry = connections.connect_browser(
        manifest, args.account, level=level.name, vault=FileVault(), browser=found,
        on_window=lambda profile: _emit("window", browser=found,
                                        url=None, login_url=manifest.browser.login_url),
        ask=_json_ask(args))
    _emit("connected", ref=ref, email=entry["email"], level=level.name,
          level_label=level.label, asked_level=level.name)
    return 0


def _site(args: argparse.Namespace) -> int:
    return _site_event(args) if args.site_command == "event" else _site_guide(args)


def _site_event(args: argparse.Namespace) -> int:
    """A harness's site tools saying something went wrong (health.py).
    Quiet on success: it runs behind the agent's turn."""
    from setu import health
    if FileVault().get(args.ref) is None:
        print(f"error: no connection {args.ref!r}", file=sys.stderr)
        return 2
    try:
        health.record(args.ref, args.kind)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


def _site_guide(args: argparse.Namespace) -> int:
    from setu import sites
    if args.set is None:
        manifest = find(args.id)
        print(manifest.browser.guide if manifest.browser else "")
        return 0
    try:
        manifest = sites.set_guide(args.id, args.set)
    except sites.SiteError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"{manifest.id}: guide saved ({len(manifest.browser.guide)} characters)")
    return 0


def _install(args: argparse.Namespace) -> int:
    installed_version = catalog.install(args.connector)
    print(f"installed {args.connector} {installed_version}, its wheel checked against the "
          f"signed catalog. Next: setu connect {args.connector}")
    return 0


def _certify(args: argparse.Namespace) -> int:
    """``setu certify``: an independent certifier's side (certify.py)."""
    from setu import certify
    try:
        if args.certify_command == "keygen":
            pub, kid = certify.keygen(Path(args.path).expanduser(), args.name or "")
            print(f"certifier key {kid} for {args.name}: private half at {args.path} "
                  f"(keep it safe), public half at {pub} -- publish that one")
            return 0
        if args.certify_command == "trust":
            if args.remove:
                gone = certify.distrust(args.remove)
                print(f"{args.remove}: {'no longer trusted' if gone else 'was not trusted'}")
                return 0 if gone else 1
            if not args.path:
                for kid, who in certify.trusted().items():
                    print(f"{kid}  {who['name']}")
                return 0
            pub = certify.load_public(Path(args.path).expanduser())
            certify.trust(pub)
            print(f"trusting certifier {pub['name'] or '(no name)'} ({pub['id']})")
            return 0
        if args.certify_command == "sign":
            subject = certify.subject_for(args.subject, catalog.kept())
            name = certify.load_public(Path(args.key + ".pub").expanduser())["name"] \
                if Path(args.key + ".pub").expanduser().exists() else ""
            cert = certify.make(subject, Path(args.key).expanduser(),
                                name=args.name or name, statement=args.statement or "",
                                checks=[c for c in (args.checks or "").split(",") if c],
                                verdict="revoked" if args.revoke else "certified")
            out = Path(args.out or f"{subject['kind']}-{subject['id']}-"
                       f"{subject['version'] or subject['sha256'][:12]}.cert.json")
            out.write_text(json.dumps(cert, indent=2) + "\n")
            what = "withdrawal" if args.revoke else "certification"
            print(f"{what} of {args.subject} ({subject['sha256'][:16]}…) signed as "
                  f"{cert['certifier']['name']} -> {out}")
            return 0
        if args.certify_command == "fetch":
            kind, _, ident = args.subject.partition(":")
            into = Path(args.into or ".").expanduser()
            if kind == "recipe":
                where = catalog.fetch_recipe(ident, into, count=False)
            elif kind == "connector":
                where = catalog.fetch_connector(ident, into)
            else:
                raise certify.CertError("name it as recipe:NAME or connector:ID")
            subject = certify.subject_for(args.subject, catalog.kept())
            print(f"{args.subject} {subject['version']} ({subject['sha256'][:16]}…), checked "
                  f"by hash, in {where}. Next: setu certify check {where}")
            return 0
        if args.certify_command == "check":
            from setu import check
            hosts = tuple(h.strip() for h in (args.hosts or "").split(",") if h.strip())
            report = check.check(Path(args.path), hosts=hosts,
                                 since=Path(args.since) if args.since else None,
                                 run=args.run)
            print(report.text())
            if args.since and args.show_diff:
                print(check.diff(Path(args.since), Path(args.path)))
            if args.json:
                Path(args.json).write_text(json.dumps(report.as_dict(), indent=2) + "\n")
            return 0
        if args.certify_command == "publish":
            cert = json.loads(Path(args.path).read_text())
            certify.verify(cert)
            done = catalog._call("POST", args.to, "/certifications", body=cert)
            print(f"published: {done['verdict']} by {done['certifier']} -- anyone who "
                  "trusts your key now sees it on the card")
            return 0
        if args.certify_command == "verify":
            cert = json.loads(Path(args.path).read_text())
            kid = certify.verify(cert)
            s = cert["subject"]
            print(f"{cert['verdict']}: {s['kind']}:{s['id']} {s['version']} "
                  f"({s['sha256'][:16]}…) by {cert['certifier']['name']} ({kid}), "
                  f"{cert['at']}")
            return 0
    except certify.CertError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 2


def _connector_named(args: argparse.Namespace) -> str:
    if not args.connector:
        raise SystemExit("setu connect: name a connector (setu connectors lists them), "
                         "or pass --site ADDRESS for a site Setu has none for")
    return args.connector


def _terminal_ask(args: argparse.Namespace) -> Callable[[str], bool] | None:
    """The person at the terminal answers -- unless --signed-in already
    did, or nobody is there to (then the answer is no)."""
    if args.signed_in:
        return lambda _question: True
    if not sys.stdin.isatty():
        return None

    def ask(question: str) -> bool:
        return input(f"{question} [y/N] ").strip().lower() in ("y", "yes")
    return ask


def _json_ask(args: argparse.Namespace) -> Callable[[str], bool]:
    """An ``ask`` event, then one line from the harness: yes or no."""
    if args.signed_in:
        return lambda _question: True

    def ask(question: str) -> bool:
        _emit("ask", question=question)
        return sys.stdin.readline().strip().lower() in ("y", "yes")
    return ask


def _connect_site(args: argparse.Namespace) -> int:
    found = _site_browser(args)
    print(f"Setu takes a quick look at {args.site} signed out, then a window of {found} "
          "opens on it, on a profile kept for this connection only.\nSign in there, then "
          "CLOSE THE WINDOW to finish. Setu writes the site's rules once it sees you "
          "signed in.")
    entry = connections.connect_site(
        args.site, args.account, level=args.level, vault=FileVault(), browser=found,
        site_id=args.id, ask=_terminal_ask(args))
    ref = connections.ref_for(entry["connector"], args.account)
    manifest = find(entry["connector"])
    print(f"connected {ref} ({entry['email']}) — {manifest.level(entry['level']).label}")
    if entry.get("note"):
        print(f"note: {entry['note']}")
    if entry.get("manifest_path"):
        print(f"its rules are in {entry['manifest_path']} -- cautious defaults; edit freely")
    print(f"the sign-in lives in {entry['profile']}; `setu disconnect {ref}` deletes it")
    return 0


def _connect_site_json(args: argparse.Namespace) -> int:
    found = _site_browser(args)
    _emit("started", ref=None, site=args.site, level=args.level or "read", scopes=[])
    entry = connections.connect_site(
        args.site, args.account, level=args.level, vault=FileVault(), browser=found,
        site_id=args.id, ask=_json_ask(args),
        on_window=lambda _profile: _emit("window", browser=found, url=None,
                                         login_url=None))
    manifest = find(entry["connector"])
    level = manifest.level(entry["level"])
    _emit("connected", ref=connections.ref_for(entry["connector"], args.account),
          email=entry["email"], level=level.name, level_label=level.label,
          asked_level=args.level or level.name, note=entry.get("note", ""),
          manifest_path=entry.get("manifest_path", ""))
    return 0


def _connect_json(args: argparse.Namespace) -> int:
    """The sign-in, as events. The browser is never opened from here: the
    harness shows the address to the person, in the page they are using --
    except for a site signed in to in a window of its own (``window``)."""
    if args.paste and (args.site or args.token_stdin):
        _emit("error", message="--paste is for a sign-in page (Google, Home Assistant), "
              "not a browser window or a pasted token")
        return 2
    if args.site:
        return _connect_site_json(args)
    manifest = find(_connector_named(args))
    if args.remote:
        return _connect_remote_json(manifest, args)
    if args.paste and manifest.auth == "browser":
        _emit("error", message=f"{manifest.name} is signed in to in a window on this "
              "computer; there is no address to paste back")
        return 2
    if manifest.auth == "homeassistant":
        return _connect_homeassistant_json(manifest, args)
    if manifest.auth == "browser":
        return _connect_browser_json(manifest, args)
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
            on_url=lambda url: _emit("url", url=url, paste=args.paste),
            timeout=args.timeout, pasted=_pasted(args))
    held = manifest.level(entry["level"])
    _emit("connected", ref=ref, email=entry.get("email") or "", level=held.name,
          level_label=held.label, asked_level=entry.get("asked_level", held.name))
    return 0


def _pasted(args: argparse.Namespace) -> google.Pasted | None:
    """With ``--paste``: every stdin line is an address pasted back."""
    if not args.paste:
        return None
    pasted = google.Pasted(on_refused=lambda why: _emit("paste_refused", message=why))

    def read() -> None:
        for line in sys.stdin:
            if line.strip():
                pasted.put(line.strip())

    threading.Thread(target=read, daemon=True).start()
    return pasted


def _connect_remote_json(manifest, args: argparse.Namespace) -> int:
    """A browser-road sign-in, streamed to another device (remote.py)."""
    from setu import remote

    spec = manifest.browser
    if manifest.auth != "browser" or spec is None:
        _emit("error", message=f"{manifest.name} signs in with a link, not a browser window: "
              "--paste is its road from another device")
        return 2
    if manifest.generated or not spec.signed_in:
        _emit("error", message=f"{manifest.name}'s sign-in is checked by its page, which "
              "needs someone at this computer: sign in to it here")
        return 2
    level = manifest.level(args.level)
    ref = connections.ref_for(manifest.id, args.account)
    found = _site_browser(args)
    try:
        window = remote.window_for(
            lambda url, until: _emit("link", url=url, expires_at=until),
            lambda: _emit("opened"), site=manifest.name, patterns=spec.signed_in,
            hosts=manifest.hosts, open_for=(remote.OPEN_FOR if args.timeout ==
                                            google.SIGN_IN_TIMEOUT else args.timeout),
            headed=spec.headed)
    except remote.WindowSettingsError as exc:
        _emit("error", message=str(exc), setup="window")
        return 2
    _emit("started", ref=ref, level=level.name, level_label=level.label, scopes=[])
    vault = FileVault()
    entry = connections.connect_browser(manifest, args.account, level=level.name, vault=vault,
                                        browser=found, window=window)
    # a locked folder with nobody holding its key: the new sign-in is
    # packed away at once, like every other one in it
    if seal.read_lock(vault.home) is not None and seal.held_key(vault.home) is None:
        seal.seal_profiles(vault.home, vault.home / site_browser.PROFILES)
    _emit("connected", ref=ref, email=entry["email"], level=level.name,
          level_label=level.label, asked_level=level.name)
    return 0


def _connect_homeassistant_json(manifest, args: argparse.Namespace) -> int:
    base = _ha_base(manifest, args)
    if not base:
        _emit("error", message=f"{manifest.name} needs your Home Assistant's address: "
              "`setu config homeassistant-url URL`", setup="homeassistant_url")
        return 2
    level = manifest.level(args.level)
    ref = connections.ref_for(manifest.id, args.account)
    token = None if args.paste else _read_token(args)
    _emit("started", ref=ref, level=level.name, level_label=level.label, scopes=[],
          base_url=homeassistant.normalise_url(base))
    with httpx.Client() as http:
        entry = connections.connect_homeassistant(
            manifest, args.account, level=level.name, base_url=base, vault=FileVault(),
            http=http, long_lived=token, open_browser=None,
            on_url=lambda url: _emit("url", url=url, paste=args.paste),
            timeout=args.timeout, pasted=_pasted(args))
    _remember_ha(base)
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
    value = config.check(args.key, args.value)
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
        used = connections.last_used(vault.get(ref) or {}) or "never"
        raw = vault.get(ref) or {}
        where = entry.get("email") or ""
        if raw.get("auth") == "phone":
            where = "phone: " + ((raw.get("phone") or {}).get("android")
                                 or (raw.get("phone") or {}).get("ios") or "its app")
        print(f"{ref:<22} {where:<30} {label:<16} last used {used}")
        if seen := health.line(ref):
            print(f"{'':<22} {seen}")
    print(f"\nkeys live in {vault.path} (readable by you only); no command prints them")
    return 0


def _run(args: argparse.Namespace) -> int:
    vault = FileVault()
    entry = vault.get(args.ref)
    if entry is None:
        print(f"error: no connection {args.ref!r} (setu list)", file=sys.stderr)
        return 2
    manifest = find(entry["connector"])
    if entry.get("auth") == "phone":
        print(f"error: {args.ref} is {manifest.name}'s app on your phone; there is no server "
              "to run. A harness working the phone uses it (setu status --json)",
              file=sys.stderr)
        return 2
    if manifest.road == "browser":
        print(f"error: {args.ref} is signed in to in a browser; there is no server to run. "
              "A harness opens its profile with its own browser tools (setu status --json)",
              file=sys.stderr)
        return 2
    # a server of the person's own (Home Assistant) is the connection's
    # address, not the manifest's
    base = entry.get("base_url") or manifest.api_base
    try:
        # the site's answers pass through here now, not only token refreshes
        with httpx.Client(timeout=60.0) as http:
            if args.callback or manifest.token_mode == "callback":
                return helper.run(args.ref, manifest.command, vault=vault, http=http,
                                  api_base=base)
            return helper.run_proxied(args.ref, manifest, vault=vault, http=http,
                                      api_base=base)
    except connections.ConnectionFailed as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def _passphrases(args: argparse.Namespace, prompts: list[str]) -> list[str]:
    """One line of stdin per prompt with --passphrase-stdin; else asked, hidden."""
    if args.passphrase_stdin:
        lines = [sys.stdin.readline().rstrip("\n") for _ in prompts]
        if not all(lines):
            raise seal.WrongPassphrase("expected one passphrase per line on stdin")
        return lines
    import getpass

    return [getpass.getpass(prompt) for prompt in prompts]


def _lock(args: argparse.Namespace) -> int:
    """``setu lock``: a folder whose keys only a passphrase opens (seal.py)."""
    vault = FileVault()
    home, profiles = vault.home, vault.home / site_browser.PROFILES
    try:
        if args.action == "status":
            data = {"locked": seal.read_lock(home) is not None,
                    "open": seal.held_key(home) is not None,
                    "sealed_profiles": seal.sealed_profiles(profiles)}
            print(json.dumps(data) if args.json else
                  ("locked" if data["locked"] else "not locked")
                  + (", key held" if data["open"] else "")
                  + (f"; sealed browser sign-ins: {', '.join(data['sealed_profiles'])}"
                     if data["sealed_profiles"] else ""))
            return 0
        if args.action == "seal":
            done = seal.seal_profiles(home, profiles)
            print(json.dumps({"sealed": done}) if args.json else
                  f"sealed: {', '.join(done) or 'nothing was open'}")
            return 0
        if args.action == "set":
            (phrase,) = _passphrases(args, ["new passphrase: "])
            with _held(seal.create(home, phrase)):
                for ref in vault.list():
                    vault.put(ref, vault.get(ref) or {})     # written back sealed
            done = seal.seal_profiles(home, profiles)
            print(f"locked {home}: {len(vault.list())} connection(s) sealed"
                  + (f", browser sign-ins packed: {', '.join(done)}" if done else ""))
            return 0
        if args.action == "unlock":
            (phrase,) = _passphrases(args, ["passphrase: "])
            private = seal.unlock_key(home, phrase)
            opened = seal.open_profiles(home, profiles, private)
            key = base64.b64encode(private).decode()
            print(json.dumps({"key": key, "profiles": opened}) if args.json else key)
            return 0
        if args.action == "change":
            old, new = _passphrases(args, ["passphrase now: ", "new passphrase: "])
            seal.change(home, old, new)
            print("passphrase changed")
            return 0
        if args.action == "remove":
            (phrase,) = _passphrases(args, ["passphrase: "])
            private = seal.unlock_key(home, phrase)
            with _held(private):
                entries = {ref: vault.get(ref) or {} for ref in vault.list()}
            seal.open_profiles(home, profiles, private)
            seal.lock_path(home).unlink()
            for ref, entry in entries.items():
                vault.put(ref, entry)                        # written back open
            print(f"{home} is no longer locked")
            return 0
    except (seal.Locked, seal.WrongPassphrase) as exc:
        if args.json:
            print(json.dumps({"error": str(exc)}))
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 2
    return 2


@contextlib.contextmanager
def _held(private: bytes):
    """``SETU_VAULT_KEY`` for the length of one command's own work."""
    before = os.environ.get(seal.ENV_KEY)
    os.environ[seal.ENV_KEY] = base64.b64encode(private).decode()
    try:
        yield
    finally:
        if before is None:
            os.environ.pop(seal.ENV_KEY, None)
        else:
            os.environ[seal.ENV_KEY] = before


def _log(args: argparse.Namespace) -> int:
    path = proxy.log_path(args.ref)
    if not path.exists():
        print(f"no requests made for {args.ref} yet ({path})")
        return 0
    lines = path.read_text(encoding="utf-8").splitlines()
    print("\n".join(lines[-args.lines:]))
    return 0


def _mcp_config(args: argparse.Namespace) -> int:
    entry = FileVault().get(args.ref)
    if entry is None:
        print(f"error: no connection {args.ref!r} (setu list)", file=sys.stderr)
        return 2
    if entry.get("auth") == "browser":
        print(f"error: {args.ref} is a browser profile, not an MCP server", file=sys.stderr)
        return 2
    if entry.get("auth") == "phone":
        print(f"error: {args.ref} is an app on your phone, not an MCP server: a harness "
              "working the phone (Sparsh) uses it", file=sys.stderr)
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


def _serve(args: argparse.Namespace) -> int:
    """``setu serve``: the page (page.py), until Ctrl-C."""
    from setu import page

    vault = FileVault()
    folders = page.people_dir(args.people)
    server = page.PageServer(page.Api(vault), page.page_token(vault.home), host=args.host,
                             port=args.port, public_url=args.public_url, people_dir=folders)
    print(f"Setu's page for {vault.home}:\n  {server.page_url}\n"
          "(the part after # is its key: open it once, the page keeps it. Ctrl-C stops.)",
          flush=True)
    if folders is not None:
        state = "on" if server.people_on() else "OFF (setu config people-page on)"
        none = "" if folders.is_dir() else " (none there yet)"
        print(f"people's own pages, for the folders in {folders}{none}: {state}", flush=True)
    try:
        server.serve_forever()
    finally:
        server.httpd.server_close()
    return 0


def _page_link(args: argparse.Namespace) -> int:
    """``setu page-link``: a one-time link to this folder's page, for the
    person it belongs to (people.py). A door runs it with SETU_HOME at
    the person's folder."""
    from setu import page, people

    home = FileVault().home
    if args.close_all:
        n = people.close_all(home)
        print(f"{home.name}: {n} open page(s) closed, and any unused link forgotten")
        return 0
    base = page.link_base(args.url)
    link, expires = people.make_link(home)
    url = f"{base}#link={link}"
    if args.json:
        print(json.dumps({"url": url, "person": home.name, "expires_at": expires}))
    else:
        print(f"{url}\n(works once, on the first device that opens it, for ten minutes)")
    return 0


def _disconnect(args: argparse.Namespace) -> int:
    vault = FileVault()
    entry = vault.get(args.ref) or {}
    with httpx.Client() as http:
        existed, revoked = connections.disconnect(args.ref, vault=vault, http=http)
    if not existed:
        print(f"no connection {args.ref!r}")
        return 1
    health.forget(args.ref)
    if entry.get("auth") == "phone":
        print(f"disconnected {args.ref}: agents no longer use the app for it. The app "
              "itself stays signed in on your phone; sign out there if you want")
        return 0
    if entry.get("auth") == "browser":
        print(f"disconnected {args.ref}: its browser profile is deleted, so this computer "
              f"is signed out. {entry.get('email') or 'The site'} may still list the "
              "device; sign it out there if you want it gone on their side too")
        return 0
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


def _catalog(args: argparse.Namespace) -> int:
    """``setu catalog``: list the kept index; ``use``, ``trust``,
    ``keygen``, ``sign`` and ``vouch`` keep and make one."""
    action = args.action or "list"
    if action == "keygen":
        pub, kid = catalog.keygen(Path(args.path).expanduser())
        print(f"signing key {kid}: private half at {args.path} (keep it offline), "
              f"public half at {pub}")
        return 0
    if action == "sign":
        index = Path(args.path)
        chain = json.loads(Path(args.chain).read_text()) if args.chain else []
        sig = catalog.sign(index.read_bytes(), Path(args.key).expanduser(), chain)
        out = Path(str(index) + ".sig")
        out.write_text(json.dumps(sig, indent=2) + "\n")
        print(f"signed {index} with key {sig['key']} -> {out}")
        return 0
    if action == "vouch":
        link = catalog.vouch(Path(args.key).expanduser(), catalog.load_public(Path(args.path)))
        print(json.dumps(link, indent=2))
        return 0
    if action == "trust":
        if args.remove:
            gone = catalog.distrust(args.path)
            print(f"key {args.path}: {'no longer trusted' if gone else 'was not trusted'}")
            return 0 if gone else 1
        if not args.path:
            for kid in catalog.trusted():
                print(kid)
            return 0
        pub = catalog.load_public(Path(args.path))
        catalog.trust(pub)
        print(f"trusting catalog key {pub['id']}")
        return 0
    if action == "publish":
        token = os.environ.get("SETU_CATALOG_TOKEN", "")
        if not args.to or not token:
            print("error: setu catalog publish INDEX --to https://catalog.example, with the "
                  "maintainer's token in SETU_CATALOG_TOKEN", file=sys.stderr)
            return 2
        done = catalog.publish(Path(args.path), args.to, token)
        print(f"published to {args.to}: issued {done.get('issued')}, signed by "
              f"{done.get('key')}, {done.get('connectors')} connector(s), "
              f"{done.get('recipes')} recipe(s)")
        return 0
    if action == "submit":
        if not args.to or not args.author:
            print("error: setu catalog submit --to URL --author NAME, and either a recipe "
                  "folder or --connector ID --repo URL --commit SHA", file=sys.stderr)
            return 2
        key = Path(args.sign).expanduser() if args.sign else None
        if args.connector:
            done = catalog.submit_connector(
                args.to, args.connector, args.repo or "", args.commit or "", args.author,
                manifest=Path(args.path) if args.path else None, contact=args.contact or "",
                note=args.note or "", key=key)
        else:
            if not args.path:
                print("error: name the recipe's folder", file=sys.stderr)
                return 2
            done = catalog.submit_recipe(args.to, Path(args.path).expanduser(), args.author,
                                         contact=args.contact or "", note=args.note or "",
                                         key=key)
        print(f"submitted: {done['submission']} ({done['status']}). Check on it with "
              f"setu catalog submission {done['submission']} --to {args.to}")
        return 0
    if action == "submission":
        seen = catalog._call("GET", args.to, f"/submissions/{args.path}")
        print(f"{seen['sid']}: {seen['kind']} {seen['id']} -- {seen['status']}"
              + (f": {seen['reason']}" if seen.get("reason") else ""))
        return 0
    if action in ("review", "close"):
        token = os.environ.get("SETU_CATALOG_TOKEN", "")
        if not args.to or not token:
            print("error: --to URL, with the maintainer's token in SETU_CATALOG_TOKEN",
                  file=sys.stderr)
            return 2
        if action == "close":
            if args.verdict not in ("accepted", "declined") or not args.path:
                print("error: setu catalog close ID --verdict accepted|declined --reason TEXT",
                      file=sys.stderr)
                return 2
            done = catalog._call("POST", args.to, f"/submissions/{args.path}/close",
                                 token=token, body={"verdict": args.verdict,
                                                    "reason": args.reason or ""})
            print(f"{done['submission']}: {done['status']}")
            return 0
        if args.path:
            full = catalog._call("GET", args.to, f"/submissions/{args.path}?full",
                                 token=token)
            if args.save and full.get("kind") == "recipe":
                target = Path(args.save).expanduser() / full["id"]
                for rel, text in (full.get("files") or {}).items():
                    dest = target / rel
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_text(text, encoding="utf-8")
                print(f"{full['id']}: written to {target} -- read it, try it "
                      f"(yantra --skill-install {target}), then upload it")
                return 0
            print(json.dumps(full, indent=2))
            return 0
        queue = catalog._call("GET", args.to, "/submissions", token=token)
        if not queue:
            print("nothing waiting")
        for item in queue:
            signed = f" (key {item['author_key']})" if item.get("author_key") else ""
            print(f"{item['sid']}  {item['kind']:<9} {item['id']:<24} by {item['author']}"
                  f"{signed}  {item['at']}")
        return 0
    if action == "upload":
        token = os.environ.get("SETU_CATALOG_TOKEN", "")
        if not args.to or not token or not args.path:
            print("error: setu catalog upload RECIPE_DIR --to URL, with the maintainer's "
                  "token in SETU_CATALOG_TOKEN", file=sys.stderr)
            return 2
        entry = catalog.upload_recipe(Path(args.path).expanduser(), args.to, token)
        print("uploaded. Add this to the recipe's entry in index.json, then sign and "
              "publish:")
        print(json.dumps(entry, indent=2))
        return 0
    if action == "recipe":
        if not args.path:
            print("error: setu catalog recipe NAME [--into DIR]", file=sys.stderr)
            return 2
        target = catalog.fetch_recipe(args.path, Path(args.into or ".").expanduser())
        print(f"{args.path}: checked against the signed catalog, written to {target}")
        seen = certify.certified(catalog.kept(), "recipe", args.path).get("line")
        print(f"{args.path}: {seen or 'no independent certification yet'}")
        return 0
    if action == "worked":
        # a harness: a catalog recipe was used (path = NAME, --version, --outcome)
        if not args.path or not args.version or args.outcome not in ("ok", "failed"):
            print("error: setu catalog worked NAME --version V --outcome ok|failed",
                  file=sys.stderr)
            return 2
        catalog.report_use(args.path, args.version, args.outcome == "ok")
        return 0
    if action == "counts":
        if not args.to or not args.path:
            print("error: setu catalog counts INDEX --to https://catalog.example",
                  file=sys.stderr)
            return 2
        changed = catalog.fold_counts(Path(args.path), args.to)
        print(f"{args.path}: installs updated for {changed} entr(ies) -- sign it, then "
              "publish")
        return 0
    if action == "use":
        where = args.path if catalog.is_address(args.path) else Path(args.path).expanduser()
        index = catalog.use(where)
        if catalog.is_address(args.path) and config.share_installs():
            print("Setu tells this catalog, anonymously, which of its listed connectors "
                  "you install (the id and version, nothing else). To stop: "
                  "setu config share-installs off")
        print(f"catalog from {index.source}, signed by {index.key}: "
              f"{len(index.connectors)} connector(s), {len(index.recipes)} recipe(s)")
        return 0
    index = catalog.kept()
    if index is None:
        print("no catalog kept (setu catalog trust KEY.pub, then setu catalog use INDEX)")
        return 0
    known = installed()
    print(f"catalog from {index.source}, signed by {index.key}, issued "
          f"{index.data.get('issued') or '?'}")
    for cid, entry in index.connectors.items():
        card = index.card(cid)
        mark = "installed " + card["installed_version"] if cid in known else "not installed"
        who = "by Setu" if entry["label"] == "by-setu" else f"by {entry.get('author') or '?'}, " \
            "reviewed and published by Setu"
        installs = f"{entry['installs']} installs" if entry.get("installs") is not None else ""
        print(f"  {cid:<20} {who}  {installs}  ({mark})")
        if card["yanked"]:
            print(f"      WITHDRAWN {card['installed_version']}: {card['yanked']}")
        if seen := certify.certified(index, "connector", cid).get("line"):
            print(f"      {seen}")
    for cid in sorted(set(known) - set(index.connectors)):
        how = "added on this computer" if known[cid].local else "sideloaded"
        print(f"  {cid:<20} {how} (not in the catalog)")
    for recipe in index.recipes:
        print(f"  recipe {recipe.get('name')}: needs {', '.join(recipe.get('needs') or [])} "
              f"-- {recipe.get('author') or '?'}")
        if seen := certify.certified(index, "recipe", recipe.get("name", "")).get("line"):
            print(f"      {seen}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="setu", description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("connectors", help="installed connectors and their access levels")

    connect = sub.add_parser("connect", help="sign in to a site")
    connect.add_argument("connector", nargs="?", help="e.g. gmail")
    connect.add_argument("--as", dest="account", default="personal",
                         help="your name for this account (default: personal)")
    connect.add_argument("--level", help="access level (default: the least one)")
    connect.add_argument("--client-file", help="the Desktop app OAuth client JSON")
    connect.add_argument("--no-browser", action="store_true",
                         help="print the address instead of opening a browser")
    connect.add_argument("--remote", action="store_true",
                         help="with --json: a browser-road site signed in to from another "
                              "device, through a streamed window (SETU_WINDOW_*)")
    connect.add_argument("--paste", action="store_true",
                         help="with --json: also take the address the sign-in ended on, "
                              "pasted back on stdin (signing in on another device)")
    connect.add_argument("--timeout", type=float, default=google.SIGN_IN_TIMEOUT,
                         help="seconds to wait for the sign-in (default 300)")
    connect.add_argument("--json", action="store_true",
                         help="events as JSON lines, for a harness's page (no browser)")
    connect.add_argument("--url", help="your Home Assistant's address "
                         "(default: setu config homeassistant-url)")
    connect.add_argument("--token-stdin", action="store_true",
                         help="Home Assistant: read a long-lived token from stdin "
                         "instead of signing in on its login page")
    connect.add_argument("--browser", help="a site with no API: the browser to sign in "
                         "with (default: setu config browser, else Chrome on PATH)")
    connect.add_argument("--phone", action="store_true",
                         help="the site's own app on your phone instead of a browser (X, "
                              "Amazon): you sign in to the app there; a harness working "
                              "the phone keeps to the level")
    connect.add_argument("--site", help="a site Setu has no connector for (example.com): "
                         "sign in, and Setu writes cautious rules for it in sites/")
    connect.add_argument("--id", help="with --site: the name to give it (default: from "
                         "the address)")
    connect.add_argument("--signed-in", action="store_true",
                         help="if the page cannot show whether you signed in, take it "
                         "that you did")

    site = sub.add_parser("site", help="a site added on this computer")
    site_sub = site.add_subparsers(dest="site_command", required=True)
    guide = site_sub.add_parser("guide", help="show its guide, or replace it with --set")
    guide.add_argument("id", help="the site's id, e.g. example")
    guide.add_argument("--set", help="the new guide (replaces the old one)")
    event = site_sub.add_parser("event", help="a site's tools: note what went wrong "
                                "(robot_check, signed_out, refused, limit, handoff)")
    event.add_argument("ref", help="the connection, e.g. amazon:personal")
    event.add_argument("kind", help="robot_check, signed_out, refused, limit or handoff")

    inst = sub.add_parser("install", help="install a connector the catalog lists, "
                          "checked by hash")
    inst.add_argument("connector", help="its id, as `setu catalog` lists it")

    cert = sub.add_parser("certify", help="certify a version you checked yourself, under "
                          "your own key; trust certifiers")
    cert_sub = cert.add_subparsers(dest="certify_command", required=True)
    c_key = cert_sub.add_parser("keygen", help="your certifier key")
    c_key.add_argument("path", help="where the private half goes (the .pub beside it)")
    c_key.add_argument("--as", dest="name", required=True,
                       help="the name you certify under (your claim; the key is you)")
    c_trust = cert_sub.add_parser("trust", help="trust a certifier's .pub (no PATH: list)")
    c_trust.add_argument("path", nargs="?")
    c_trust.add_argument("--remove", metavar="KEY_ID")
    c_sign = cert_sub.add_parser("sign", help="sign a certification (or --revoke one)")
    c_sign.add_argument("--subject", required=True, help="recipe:NAME or connector:ID")
    c_sign.add_argument("--key", required=True, help="your certifier key")
    c_sign.add_argument("--statement", help="what you did and what you found")
    c_sign.add_argument("--checks", help="comma-separated: scan, sandboxed-run, deployed, "
                        "read-the-code, rebuilt-from-source")
    c_sign.add_argument("--name", help="the name to sign as (default: from your .pub)")
    c_sign.add_argument("--revoke", action="store_true",
                        help="withdraw your certification of this version")
    c_sign.add_argument("--out", help="where to write it")
    c_fetch = cert_sub.add_parser("fetch", help="the exact listed version, checked by "
                                  "hash, into a folder to read (not installed)")
    c_fetch.add_argument("subject", help="recipe:NAME or connector:ID")
    c_fetch.add_argument("--into", help="where (default: here)")
    c_check = cert_sub.add_parser("check", help="scan a fetched version, compare it with "
                                  "the last one, run a command with no network")
    c_check.add_argument("path", help="the folder certify fetch wrote")
    c_check.add_argument("--hosts", help="comma-separated hosts it may reach")
    c_check.add_argument("--since", help="the previous version's folder, to see what changed")
    c_check.add_argument("--show-diff", action="store_true", help="with --since: the lines")
    c_check.add_argument("--run", help="a command to run in Podman, no network, read-only")
    c_check.add_argument("--json", help="also write the report here")
    c_pub = cert_sub.add_parser("publish", help="send a signed certification to a catalog")
    c_pub.add_argument("path")
    c_pub.add_argument("--to", required=True, help="the catalog server")
    c_ver = cert_sub.add_parser("verify", help="check a certification file")
    c_ver.add_argument("path")

    sub.add_parser("list", help="your connections")

    run = sub.add_parser("run", help="start a connector for a connection")
    run.add_argument("ref", help="e.g. gmail:personal")
    run.add_argument("--callback", action="store_true",
                     help="hand the connector a short-lived token instead of making its "
                          "requests (for trying a connector that cannot go through Setu)")

    lock = sub.add_parser("lock", help="lock this folder with a passphrase")
    lock.add_argument("action", choices=["set", "unlock", "seal", "status", "change",
                                         "remove"])
    lock.add_argument("--passphrase-stdin", action="store_true",
                      help="read the passphrase (for change: old, then new) from stdin")
    lock.add_argument("--json", action="store_true")

    log = sub.add_parser("log", help="the requests Setu made for a connection")
    log.add_argument("ref")
    log.add_argument("-n", dest="lines", type=int, default=40)

    mcp_config = sub.add_parser("mcp-config", help="print the MCP config for a harness")
    mcp_config.add_argument("ref")
    mcp_config.add_argument("--for", dest="target", choices=["yantra", "claude"],
                        default="yantra")

    status = sub.add_parser("status", help="connections and connectors, for a harness")
    status.add_argument("--json", action="store_true", help="machine-readable, no secrets")

    serve = sub.add_parser("serve", help="Setu's page: connections, levels and logs in a "
                           "browser")
    serve.add_argument("--host", default="127.0.0.1",
                       help="where to listen (default: this computer only)")
    serve.add_argument("--port", type=int, default=8775)
    serve.add_argument("--public-url", help="the address a browser uses, when it is not "
                       "where Setu listens (a port mapping, a proxy); or $SETU_PAGE_URL")
    serve.add_argument("--people", help="the folder people's own Setu folders are in (a "
                       "door's state/setu): each may open their own with a link "
                       "(setu page-link); or $SETU_PAGE_PEOPLE")

    plink = sub.add_parser("page-link", help="a one-time link to this folder's page, for "
                           "the person it belongs to")
    plink.add_argument("--url", help="the page's address as their phone reaches it "
                       "(default: $SETU_PAGE_URL, else SETU_WINDOW_HOST on port 8775)")
    plink.add_argument("--json", action="store_true")
    plink.add_argument("--close-all", action="store_true",
                       help="close every page open on this folder, and forget any link")

    disconnect = sub.add_parser("disconnect", help="revoke and forget a connection")
    disconnect.add_argument("ref")

    settings = sub.add_parser("config", help="show or remember a setting (never a key)")
    settings.add_argument("key", nargs="?", help=", ".join(config.KEYS))
    settings.add_argument("value", nargs="?")
    settings.add_argument("--unset", action="store_true", help="forget the setting")

    cat = sub.add_parser("catalog", help="the signed catalog: labels, installs, withdrawn")
    cat.add_argument("action", nargs="?",
                     choices=["list", "use", "trust", "keygen", "sign", "vouch", "publish",
                              "counts", "submit", "submission", "review", "close",
                              "upload", "recipe", "worked"])
    cat.add_argument("path", nargs="?", help="index, key or .pub file, by action")
    cat.add_argument("--key", help="sign/vouch: the private signing key")
    cat.add_argument("--chain", help="sign: a JSON list of vouch links to attach")
    cat.add_argument("--remove", action="store_true", help="trust: stop trusting key PATH")
    cat.add_argument("--to", help="publish, counts, submit, review: the catalog server")
    cat.add_argument("--author", help="submit: who you are, as the listing will say")
    cat.add_argument("--contact", help="submit: how the maintainer can reach you (private)")
    cat.add_argument("--note", help="submit: anything the maintainer should know")
    cat.add_argument("--connector", help="submit: a connector's id (else PATH is a recipe)")
    cat.add_argument("--repo", help="submit --connector: its source, an https address")
    cat.add_argument("--commit", help="submit --connector: the exact commit to review")
    cat.add_argument("--sign", help="submit: sign it with your key (required for a "
                     "connector; `setu catalog keygen` makes one)")
    cat.add_argument("--verdict", help="close: accepted or declined")
    cat.add_argument("--reason", help="close: what the author is told")
    cat.add_argument("--save", help="review ID: write a submitted recipe's files to this folder")
    cat.add_argument("--into", help="recipe: where to write it (default: here)")
    cat.add_argument("--version", help="worked: the recipe version used")
    cat.add_argument("--outcome", help="worked: ok or failed")
    return parser


COMMANDS = {"connectors": _connectors, "connect": _connect, "list": _list,
            "run": _run, "log": _log, "lock": _lock, "mcp-config": _mcp_config, "status": _status,
            "serve": _serve, "page-link": _page_link,
            "disconnect": _disconnect, "config": _config, "catalog": _catalog,
            "site": _site, "install": _install, "certify": _certify}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return COMMANDS[args.command](args)
    except (connections.ConnectionFailed, google.GoogleAuthError,
            site_browser.BrowserSignInFailed,
            homeassistant.HomeAssistantError, catalog.CatalogError, ManifestError,
            VaultError, ValueError, OSError) as exc:
        # `setu run` speaks MCP on stdout, so every complaint goes to stderr.
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\n(cancelled -- nothing saved)", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
