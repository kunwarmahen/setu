"""A site nobody wrote rules for: Setu writes them, cautiously.

Amazon and X are manifests and nothing more -- the rules a harness keeps
to on a site reached through a browser. ``setu connect --site
example.com`` writes such a manifest for a site that has none, into
``sites/`` beside the vault, once the person has signed in.

CAUTIOUS DEFAULTS, NOT GUESSES. Nobody has read this site's pages, so
nothing here is particular to it: no spending pages (none are known), a
broad list of button words that spend or cannot be undone, two seconds
between pages, ten actions a session, a real window on an unseen screen
(the setting more sites accept), and Read only to start. The person may
edit the file; Setu never rewrites one it did not just make.

NAMED FROM THE ADDRESS. ``www.example.com`` is ``example`` on
``example.com``; ``news.ycombinator.com`` is ``ycombinator``;
``bbc.co.uk`` is ``bbc``. ``--id`` picks another name. A site Setu
already has a connector for is pointed at it instead.

MONEY STAYS READ ONLY. A site whose address or page title reads like a
bank, a broker, a wallet or a payment service is connected at Read only,
whatever level was asked for: with no spending pages known, the only
guard on such a site would be words on buttons. Editing the file is the
deliberate way past that.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from setu.manifest import Manifest, ManifestError, load, sites_dir

#: Second-level labels that are part of a country's suffix, not a name.
_SUFFIX_LABELS = {"co", "com", "org", "net", "gov", "ac", "edu", "ne", "or", "go"}
#: Button words that spend or cannot be undone, for a site nobody has read.
SPEND_WORDS = ("buy", "buy now", "pay", "pay now", "checkout", "check out", "place order",
               "place your order", "purchase", "subscribe", "upgrade", "start trial",
               "start free trial", "donate", "send money", "transfer", "withdraw",
               "confirm payment", "delete", "delete account", "deactivate", "close account",
               "cancel order", "cancel subscription", "unsubscribe")
PACE = 2.0
MAX_ACTIONS = 10
_MONEY = re.compile(r"bank|banking|credit ?union|broker|brokerage|trading|invest|wallet|"
                    r"crypto|payment|paypal|venmo|loan|mortgage|insurance|\bpay\b|\bcard\b",
                    re.I)


class SiteError(Exception):
    """An address Setu cannot make a site of, or one it already has."""


def host_of(address: str) -> str:
    """``https://www.Example.com/x`` -> ``www.example.com``."""
    address = address.strip()
    if "://" not in address:
        address = "https://" + address
    host = (urlparse(address).hostname or "").lower().rstrip(".")
    if not host or "." not in host or not re.fullmatch(r"[a-z0-9.-]+", host):
        raise SiteError(f"{address!r} is not a site's address (try: example.com)")
    return host


def _start(address: str, host: str) -> str:
    """The site's front page: https unless the address said otherwise,
    keeping a port when it named one (a site on this computer)."""
    address = address.strip()
    parsed = urlparse(address if "://" in address else "https://" + address)
    port = f":{parsed.port}" if parsed.port else ""
    return f"{parsed.scheme or 'https'}://{host}{port}/"


def name_of(host: str) -> tuple[str, str]:
    """(id, the domain the site's hosts are kept to) for ``host``."""
    labels = host.split(".")
    i = len(labels) - 2
    if i > 0 and labels[i] in _SUFFIX_LABELS and len(labels[-1]) == 2:
        i -= 1                                    # bbc.co.uk, amazon.com.au
    return labels[i], ".".join(labels[i:])


def looks_like_money(host: str, title: str = "") -> bool:
    return bool(_MONEY.search(host.replace(".", " ").replace("-", " ")) or _MONEY.search(title))


def draft(address: str, site_id: str | None = None) -> dict[str, Any]:
    """The manifest for ``address``, before anyone has signed in."""
    host = host_of(address)
    derived, domain = name_of(host)
    site_id = (site_id or derived).lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", site_id):
        raise SiteError(f"{site_id!r} cannot name a site: letters, digits, - and _ only")
    name = site_id.replace("-", " ").replace("_", " ").title()
    start = _start(address, host)
    return {
        "id": site_id,
        "name": name,
        "summary": f"Your account on {domain}, read through your own signed-in browser. "
                   "Added on this computer with cautious rules: buying, paying and "
                   "deleting are handed to you.",
        "road": "browser",
        "auth": "browser",
        "generated": True,
        "hosts": [domain],
        "browser": {"start_url": start, "login_url": start, "signed_in": [],
                    "spend_pages": [], "spend_words": list(SPEND_WORDS),
                    "pace": PACE, "max_actions": MAX_ACTIONS, "headed": True, "guide": ""},
        "levels": {
            "read": {"label": "Read only",
                     "description": "Open pages, follow links, scroll and search. Nothing "
                                    "is clicked or typed except a search."},
            "write": {"label": "Read and act",
                      "description": "Also click and type, each asked about first. Buying, "
                                     "paying and deleting are still handed to you."},
        },
        "verbs": {"open": "read", "follow": "read", "scroll": "read", "search": "read",
                  "click": "write", "fill": "write"},
    }


def _value(value: Any) -> str:
    # JSON's strings, numbers, booleans and arrays of them are TOML's too
    return json.dumps(value, ensure_ascii=False)


def to_toml(data: dict[str, Any]) -> str:
    lines = [f"# {data['name']}: written by `setu connect --site` with cautious defaults.",
             "# Edit freely: add pages that spend to spend_pages, a short guide to the",
             "# site, or the cookie that means signed in to signed_in.", ""]
    for key in ("id", "name", "summary", "road", "auth", "generated", "hosts"):
        lines.append(f"{key} = {_value(data[key])}")
    lines += ["", "[browser]"]
    lines += [f"{key} = {_value(value)}" for key, value in data["browser"].items()]
    for level, spec in data["levels"].items():
        lines += ["", f"[levels.{level}]"]
        lines += [f"{key} = {_value(value)}" for key, value in spec.items()]
    lines += ["", "[verbs]"]
    lines += [f"{key} = {_value(value)}" for key, value in data["verbs"].items()]
    return "\n".join(lines) + "\n"


def path_for(site_id: str) -> Path:
    return sites_dir() / f"{site_id}.toml"


def write(data: dict[str, Any]) -> Manifest:
    """Save the manifest to ``sites/`` and read it back the way every
    other one is read -- a file Setu itself cannot load is never left."""
    directory = sites_dir()
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    target = path_for(data["id"])
    staged = target.with_suffix(".toml.new")
    staged.write_text(to_toml(data), encoding="utf-8")
    try:
        load(staged)
    except ManifestError:
        staged.unlink()
        raise
    staged.replace(target)
    manifest = load(target)
    return manifest
