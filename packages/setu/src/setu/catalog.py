"""The catalog: which connectors and recipes are listed, by whom, and
which versions are withdrawn -- in one signed file.

The catalog is not a server. It is ``index.json`` plus a signature,
``index.json.sig``, wherever they are kept; Setu reads them from a path,
checks the signature, and keeps a copy of the last good pair. What it
says reaches a harness through ``setu status``: each installed
connector's LABEL (by Setu, partner, sideloaded), its author, how many
people installed it, and whether the installed version was WITHDRAWN.

THE SIGNATURE IS THE AUTHORITY. An index whose signature does not check
out against a key the person trusts is refused whole, never read in
part, and the copy already kept stays in use. A key is trusted because
the person said so (``setu catalog trust``) or because a trusted key
vouched for it.

ROTATION SHIPS FROM THE START. A ``.sig`` may carry a CHAIN: each link a
new public key, signed by a key already trusted. So when the signing key
changes -- on schedule, or because it leaked -- the new index arrives
with the old key's word for the new one, and nobody has to re-trust by
hand. A leaked key's own word is worth nothing once it is removed from
the trusted list; that is what ``setu catalog trust --remove`` is for.

LABELS SAY WHO WROTE IT, NOT WHETHER TO TRUST IT. Everything listed was
reviewed. ``by-setu`` is ours; ``partner`` is someone else's, reviewed
and published by Setu; an installed connector the index does not list is
``sideloaded``. With no index at all there is no label, rather than
calling Setu's own Gmail sideloaded. A site a person added by hand
(``sites/``) is ``local`` whether or not an index is kept: no catalog
has a word on it.

FROM A PATH OR A SERVER. ``use`` takes a file or an https address (the
catalog server, setu-catalog-server). Either way the bytes are checked
the same, and the server is trusted for nothing: it never holds the key.
What it could still do is serve an OLD index, one from before a
connector was withdrawn -- so an index issued before the one kept is
refused, here as on the server. A source that is an address is asked
again at most once a day (``current``); unreachable, the last good
index is used and the report says how old it is.

What is not here: installing connectors by hash.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from setu.vault import default_home

FORMAT = "setu.index.v1"
LABELS = ("by-setu", "partner")
SIDELOADED = "sideloaded"
#: A site added by hand on this computer (``sites/``): never in a catalog.
LOCAL = "local"
KEYS_FILE = "trusted-keys.json"
CACHE_DIR = "catalog"


class CatalogError(Exception):
    """An index that cannot be trusted as given."""


# ---- keys ---------------------------------------------------------------------------


def key_id(public: bytes) -> str:
    """A key's short name: the first 16 hex digits of its SHA-256."""
    return hashlib.sha256(public).hexdigest()[:16]


def _raw_public(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def keygen(path: Path) -> tuple[Path, str]:
    """A new signing key: the private half at ``path`` (owner-only), the
    public half beside it as ``<path>.pub``. Returns (pub path, key id)."""
    if path.exists():
        raise CatalogError(f"{path} exists; a signing key is never overwritten")
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                            serialization.NoEncryption())
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as out:
        out.write(base64.b64encode(raw).decode() + "\n")
    public = _raw_public(key.public_key())
    pub = path.with_name(path.name + ".pub")
    pub.write_text(json.dumps({"id": key_id(public),
                               "public": base64.b64encode(public).decode()}) + "\n")
    return pub, key_id(public)


def _load_private(path: Path) -> Ed25519PrivateKey:
    try:
        return Ed25519PrivateKey.from_private_bytes(base64.b64decode(path.read_text().strip()))
    except (OSError, ValueError) as exc:
        raise CatalogError(f"{path} is not a Setu signing key ({exc})") from None


def load_public(path: Path) -> dict[str, str]:
    """A ``.pub`` file -> {"id", "public"}; the id is recomputed, never
    believed."""
    try:
        data = json.loads(path.read_text())
        public = base64.b64decode(data["public"])
        Ed25519PublicKey.from_public_bytes(public)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise CatalogError(f"{path} is not a Setu public key ({exc})") from None
    return {"id": key_id(public), "public": data["public"]}


def trusted(home: Path | None = None) -> dict[str, str]:
    """The keys this person trusts: id -> base64 public key."""
    path = (home or default_home()) / KEYS_FILE
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError:
        return {}
    except ValueError as exc:
        raise CatalogError(f"{path} is not valid JSON ({exc}); fix or delete it") from None
    return {k["id"]: k["public"] for k in data.get("keys", [])}


def _save_trusted(keys: dict[str, str], home: Path | None = None) -> None:
    path = (home or default_home()) / KEYS_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps({"keys": [{"id": k, "public": v} for k, v in keys.items()]},
                              indent=2) + "\n")
    os.replace(tmp, path)


def trust(pub: dict[str, str], home: Path | None = None) -> None:
    keys = trusted(home)
    keys[pub["id"]] = pub["public"]
    _save_trusted(keys, home)


def distrust(kid: str, home: Path | None = None) -> bool:
    keys = trusted(home)
    gone = keys.pop(kid, None) is not None
    _save_trusted(keys, home)
    return gone


# ---- signing and checking -------------------------------------------------------------


def vouch(old_private: Path, new_public: dict[str, str]) -> dict[str, str]:
    """One chain link: the old key's signature over the new public key."""
    old = _load_private(old_private)
    raw = base64.b64decode(new_public["public"])
    return {"public": new_public["public"], "signed_by": key_id(_raw_public(old.public_key())),
            "sig": base64.b64encode(old.sign(raw)).decode()}


def sign(index: bytes, private: Path, chain: list[dict[str, str]] | None = None) -> dict:
    """The ``.sig`` document for these exact bytes."""
    key = _load_private(private)
    return {"key": key_id(_raw_public(key.public_key())),
            "sig": base64.b64encode(key.sign(index)).decode(),
            "chain": list(chain or [])}


def _verify(public_b64: str, sig_b64: str, data: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(public_b64)).verify(
            base64.b64decode(sig_b64), data)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def verify(index: bytes, sig: dict[str, Any], keys: dict[str, str]) -> str:
    """The id of the key that signed ``index``, reached from ``keys``
    through the chain; raises when nothing trusted vouches for it."""
    known = dict(keys)
    if not known:
        raise CatalogError("no trusted catalog key: `setu catalog trust KEY.pub` first")
    for link in sig.get("chain") or []:
        by = link.get("signed_by", "")
        if by not in known:
            continue
        raw = base64.b64decode(link.get("public", ""))
        if _verify(known[by], link.get("sig", ""), raw):
            known[key_id(raw)] = link["public"]
    kid = sig.get("key", "")
    if kid not in known:
        raise CatalogError(f"signed by key {kid or '?'}, which no trusted key vouches for")
    if not _verify(known[kid], sig.get("sig", ""), index):
        raise CatalogError("the signature does not match the index: refused whole")
    return kid


# ---- the index ------------------------------------------------------------------------


@dataclass(slots=True)
class Index:
    data: dict[str, Any]
    key: str
    source: str = ""
    connectors: dict[str, dict[str, Any]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.connectors = {c["id"]: c for c in self.data.get("connectors") or []}

    @property
    def recipes(self) -> list[dict[str, Any]]:
        return list(self.data.get("recipes") or [])

    def card(self, connector_id: str, package: str = "") -> dict[str, Any]:
        """What the catalog says about an installed connector: its label,
        author, installs, and -- for the version installed -- whether it
        was withdrawn and why."""
        entry = self.connectors.get(connector_id)
        if entry is None:
            return {"label": SIDELOADED, "author": "", "installs": None, "yanked": ""}
        installed = _installed_version(entry.get("package") or package)
        reason = (entry.get("yanked") or {}).get(installed, "") if installed else ""
        return {"label": entry.get("label", SIDELOADED), "author": entry.get("author", ""),
                "installs": entry.get("installs"), "latest": entry.get("version", ""),
                "installed_version": installed or "", "yanked": reason}


def parse(raw: bytes, key: str, source: str = "") -> Index:
    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise CatalogError(f"the index is not JSON ({exc})") from None
    if not isinstance(data, dict) or data.get("format") != FORMAT:
        raise CatalogError(f"the index is not {FORMAT} (format {data.get('format')!r})"
                           if isinstance(data, dict) else "the index is not an object")
    for entry in data.get("connectors") or []:
        if not entry.get("id"):
            raise CatalogError("a connector entry has no id")
        if entry.get("label") not in LABELS:
            raise CatalogError(f"{entry['id']}: label {entry.get('label')!r} "
                               f"(listed entries are {' or '.join(LABELS)})")
    return Index(data=data, key=key, source=source)


def _installed_version(package: str) -> str:
    if not package:
        return ""
    try:
        return version(package)
    except PackageNotFoundError:
        return ""


def _cache(home: Path | None = None) -> Path:
    return (home or default_home()) / CACHE_DIR


def is_address(source: str | Path) -> bool:
    return str(source).startswith(("https://", "http://"))


def _fetch(address: str, timeout: float) -> tuple[bytes, dict[str, Any]]:
    import httpx

    base = address.rstrip("/")
    if base.endswith("/index.json"):
        base = base[: -len("/index.json")]
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as http:
            raw = http.get(f"{base}/index.json")
            signed = http.get(f"{base}/index.json.sig")
    except httpx.HTTPError as exc:
        raise CatalogError(f"could not reach {base} ({type(exc).__name__})") from None
    for response in (raw, signed):
        if response.status_code != 200:
            raise CatalogError(f"{response.url} answered HTTP {response.status_code}")
    try:
        sig = signed.json()
    except ValueError as exc:
        raise CatalogError(f"{signed.url} is not JSON ({exc})") from None
    return raw.content, sig


def use(path: Path | str, home: Path | None = None, *, timeout: float = 15.0) -> Index:
    """Check ``path`` and ``path.sig`` -- or an address's index.json and
    index.json.sig -- and keep the pair when they check out. A refused
    index changes nothing that was kept."""
    if is_address(path):
        raw, sig = _fetch(str(path), timeout)
        source = str(path).rstrip("/")
    else:
        raw = Path(path).read_bytes()
        sig_path = Path(str(path) + ".sig")
        try:
            sig = json.loads(sig_path.read_text())
        except FileNotFoundError:
            raise CatalogError(f"no signature beside the index ({sig_path})") from None
        except ValueError as exc:
            raise CatalogError(f"{sig_path} is not JSON ({exc})") from None
        source = str(Path(path).resolve())
    kid = verify(raw, sig, trusted(home))
    index = parse(raw, kid, source)
    try:
        before = kept(home)
    except CatalogError:
        before = None
    issued, was = str(index.data.get("issued") or ""), \
        str(before.data.get("issued") or "") if before is not None else ""
    if was and (not issued or issued < was):
        raise CatalogError(f"this index was issued {issued or '(never said)'}, before the "
                           f"one kept ({was}) -- an old index could bring back what was "
                           "withdrawn, so it is refused")
    cache = _cache(home)
    cache.mkdir(parents=True, exist_ok=True)
    (cache / "index.json").write_bytes(raw)
    (cache / "index.json.sig").write_text(json.dumps(sig))
    (cache / "source.json").write_text(json.dumps({
        "source": index.source, "key": kid,
        "kept": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")}))
    return index


def kept(home: Path | None = None) -> Index | None:
    """The last good index, checked again on every read -- a copy on disk
    is only as good as its signature. None when there is none."""
    cache = _cache(home)
    try:
        raw = (cache / "index.json").read_bytes()
        sig = json.loads((cache / "index.json.sig").read_text())
        source = json.loads((cache / "source.json").read_text()).get("source", "")
    except FileNotFoundError:
        return None
    except ValueError as exc:
        raise CatalogError(f"the kept index is damaged ({exc}); `setu catalog use` again") \
            from None
    return parse(raw, verify(raw, sig, trusted(home)), source)


#: An address is asked again after this long.
REFRESH_SECONDS = 24 * 3600


def kept_at(home: Path | None = None) -> str:
    try:
        return json.loads((_cache(home) / "source.json").read_text()).get("kept", "")
    except (FileNotFoundError, ValueError):
        return ""


def current(home: Path | None = None, *, timeout: float = 5.0,
            now: datetime | None = None) -> tuple[Index | None, str]:
    """The index to use now, and a note when it is not fresh. An address
    kept over a day ago is asked again; failing that, the last good one
    is used and the note says since when."""
    index = kept(home)
    if index is None or not is_address(index.source):
        return index, ""
    at = kept_at(home)
    now = now or datetime.now(UTC)
    try:
        age = (now - datetime.strptime(at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC))
        stale = age.total_seconds() >= REFRESH_SECONDS
    except ValueError:
        stale = True
    if not stale:
        return index, ""
    try:
        return use(index.source, home, timeout=timeout), ""
    except CatalogError as exc:
        return index, f"catalog: using the copy kept {at or '?'} ({exc})"


def publish(index_path: Path, address: str, token: str, *, timeout: float = 30.0) -> dict:
    """Send a signed index (and its .sig) to the catalog server. The server
    checks the signature and refuses an older index; it never sees a key."""
    import httpx

    raw = Path(index_path).read_bytes()
    sig = json.loads(Path(str(index_path) + ".sig").read_text())
    try:
        with httpx.Client(timeout=timeout) as http:
            answer = http.post(f"{address.rstrip('/')}/publish",
                               json={"index": base64.b64encode(raw).decode(), "sig": sig},
                               headers={"Authorization": f"Bearer {token}"})
    except httpx.HTTPError as exc:
        raise CatalogError(f"could not reach {address} ({type(exc).__name__})") from None
    try:
        body = answer.json()
    except ValueError:
        body = {"error": answer.text[:200]}
    if answer.status_code != 200:
        raise CatalogError(f"the server refused it (HTTP {answer.status_code}): "
                           f"{body.get('error', body)}")
    return body
