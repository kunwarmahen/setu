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

INSTALLING IS BY HASH. ``install`` takes a connector's wheel from the
address its index entry names and installs it only if its SHA-256 is the
one the signed index says, and the version is not withdrawn. The wheel's
host (PyPI, a release page) is trusted for nothing, as the server is
not. Its dependencies install the ordinary way: pinning every one by
hash would make each release of httpx a catalog change.
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
                "installed_version": installed or "", "yanked": reason,
                "author_signed": author_line(entry)}


def author_line(entry: dict[str, Any]) -> str:
    """What the index says about the author's key for this entry:
    'signed by its author · same key since 1.0.0', a changed key said
    plainly, or '' when the author did not sign."""
    kid = str(entry.get("author_key") or "")
    if not kid:
        return ""
    since = str(entry.get("author_key_since") or "")
    if entry.get("author_key_changed"):
        return (f"signed by its author with a NEW key ({kid[:8]}) since {since or '?'} -- "
                f"{entry['author_key_changed']}")
    return f"signed by its author · same key since {since}" if since else \
        "signed by its author"


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
    if is_address(source):
        _keep_certifications(source, cache, timeout)
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


CERTS_FILE = "certifications.json"


def _keep_certifications(address: str, cache: Path, timeout: float) -> None:
    """The server's certifications, kept beside the index. Each is checked
    when a card reads it (certify.standing), so nothing here is trusted;
    a server that has none, or cannot say, leaves the last copy."""
    import httpx

    try:
        with httpx.Client(timeout=timeout) as http:
            answer = http.get(f"{address.rstrip('/')}/certifications.json")
        if answer.status_code == 200 and isinstance(answer.json(), list):
            (cache / CERTS_FILE).write_text(json.dumps(answer.json()))
    except (httpx.HTTPError, ValueError):
        pass


def certifications(home: Path | None = None) -> list[dict[str, Any]]:
    try:
        data = json.loads((_cache(home) / CERTS_FILE).read_text())
    except (FileNotFoundError, ValueError):
        return []
    return data if isinstance(data, list) else []


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


def _call(method: str, address: str, path: str, *, token: str = "",
          body: dict | None = None, timeout: float = 30.0) -> Any:
    """One request to a catalog server; its refusal as a CatalogError."""
    import httpx

    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        with httpx.Client(timeout=timeout) as http:
            answer = http.request(method, f"{address.rstrip('/')}{path}", json=body,
                                  headers=headers)
    except httpx.HTTPError as exc:
        raise CatalogError(f"could not reach {address} ({type(exc).__name__})") from None
    try:
        data = answer.json()
    except ValueError:
        data = {"error": answer.text[:200]}
    if answer.status_code >= 300:
        raise CatalogError(f"{address} refused it (HTTP {answer.status_code}): "
                           f"{data.get('error', data) if isinstance(data, dict) else data}")
    return data


def _signed_part(body: dict[str, Any]) -> bytes:
    """What an author's signature covers: everything they sent, but the
    signature and the private contact line."""
    return json.dumps({k: v for k, v in body.items()
                       if k not in ("author_sig", "contact")},
                      sort_keys=True, separators=(",", ":")).encode()


def sign_submission(body: dict[str, Any], key: Path) -> dict[str, Any]:
    """The author's own signature over what they submit: their key travels
    with it, so the listing can say the same author signed every version."""
    private = _load_private(Path(key))
    public = _raw_public(private.public_key())
    body = {**body, "author_key": {"key": key_id(public),
                                   "public": base64.b64encode(public).decode()}}
    body["author_sig"] = base64.b64encode(private.sign(_signed_part(body))).decode()
    return body


def check_submission(body: dict[str, Any]) -> str:
    """The author's key id when the submission is signed and whole; ""
    when unsigned; raises when signed but not by the key it carries."""
    who = body.get("author_key")
    if not who and not body.get("author_sig"):
        return ""
    try:
        public = base64.b64decode(who["public"], validate=True)
        ok = _verify(who["public"], body.get("author_sig", ""), _signed_part(body))
    except (KeyError, TypeError, ValueError):
        ok = False
    if not ok or key_id(public) != who.get("key"):
        raise CatalogError("the author's signature does not match the submission")
    return who["key"]


def submit_connector(address: str, connector: str, repo: str, commit: str, author: str,
                     *, manifest: Path | None = None, contact: str = "",
                     note: str = "", key: Path | None = None) -> dict:
    """Ask for a connector to be listed: its SOURCE at an exact commit,
    never a built package -- the maintainer reviews and builds from that.
    Signed by the author (``key``): a connector without it is refused."""
    body = {"kind": "connector", "id": connector, "repo": repo, "commit": commit,
            "author": author, "contact": contact, "note": note,
            "manifest": Path(manifest).read_text() if manifest else ""}
    return _call("POST", address, "/submissions",
                 body=sign_submission(body, key) if key else body)


def submit_recipe(address: str, folder: Path, author: str, *, contact: str = "",
                  note: str = "", key: Path | None = None) -> dict:
    """Ask for a recipe to be listed: a skill folder's SKILL.md and scripts/.
    Signing it (``key``) is optional for a recipe, and shown when done."""
    body = {"kind": "recipe", "id": Path(folder).name, "author": author,
            "contact": contact, "note": note, "files": recipe_files(Path(folder))}
    return _call("POST", address, "/submissions",
                 body=sign_submission(body, key) if key else body)


def install(connector: str, home: Path | None = None,
            run: Any = None, fetch: Any = None) -> str:
    """Install a listed connector's wheel, checked against the signed index.
    Returns the version installed."""
    import shutil
    import subprocess
    import sys
    import tempfile

    index = kept(home)
    if index is None:
        raise CatalogError("no catalog kept: `setu catalog use URL` first")
    entry = index.connectors.get(connector)
    if entry is None:
        raise CatalogError(f"the catalog does not list {connector!r}")
    wanted = str(entry.get("version") or "")
    wheel = entry.get("wheel") or {}
    url, digest = str(wheel.get("url") or ""), str(wheel.get("sha256") or "").lower()
    if not url or len(digest) != 64:
        raise CatalogError(f"{connector}: the catalog names no wheel to install it from")
    if not _fetchable(url):
        raise CatalogError(f"{connector}: wheels come over https, not {url.split(':')[0]}")
    reason = (entry.get("yanked") or {}).get(wanted)
    if reason:
        raise CatalogError(f"{connector} {wanted} was withdrawn: {reason}")
    name = url.rsplit("/", 1)[-1]
    if not name.endswith(".whl"):
        raise CatalogError(f"{connector}: {name} is not a wheel")
    data = (fetch or _download)(url)
    found = hashlib.sha256(data).hexdigest()
    if found != digest:
        raise CatalogError(f"{connector}: the wheel's hash is {found[:16]}…, not the "
                           f"{digest[:16]}… the signed catalog names -- not installed")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / name
        path.write_bytes(data)
        argv = (["uv", "pip", "install", "--python", sys.executable, str(path)]
                if shutil.which("uv") else [sys.executable, "-m", "pip", "install", str(path)])
        done = (run or subprocess.run)(argv, capture_output=True, text=True)
        if done.returncode != 0:
            raise CatalogError(f"{connector}: the installer failed: "
                               f"{(done.stderr or done.stdout).strip()[-400:]}")
    return wanted


def _fetchable(url: str) -> bool:
    """https, a local file, or this computer (a catalog server under test).
    The hash is the guard either way; plain http elsewhere is refused so a
    network in between cannot even try."""
    return url.startswith(("https://", "file://", "http://127.0.0.1:", "http://localhost:"))


def _download(url: str) -> bytes:
    if url.startswith("file://"):
        return Path(url[len("file://"):]).read_bytes()
    import httpx

    try:
        with httpx.Client(timeout=60, follow_redirects=True) as http:
            answer = http.get(url)
    except httpx.HTTPError as exc:
        raise CatalogError(f"could not download {url} ({type(exc).__name__})") from None
    if answer.status_code != 200:
        raise CatalogError(f"{url} answered HTTP {answer.status_code}")
    return answer.content


RECIPE_FORMAT = "setu.recipe.v1"


def recipe_files(folder: Path) -> dict[str, str]:
    """A recipe folder's SKILL.md and scripts/ -- nothing else travels."""
    folder = Path(folder)
    if not (folder / "SKILL.md").is_file():
        raise CatalogError(f"no SKILL.md in {folder}")
    files = {"SKILL.md": (folder / "SKILL.md").read_text(encoding="utf-8")}
    scripts = folder / "scripts"
    for script in sorted(scripts.glob("*")) if scripts.is_dir() else []:
        if script.is_file():
            files[f"scripts/{script.name}"] = script.read_text(encoding="utf-8")
    return files


def bundle(name: str, files: dict[str, str]) -> bytes:
    """One recipe as the exact bytes its hash is taken over."""
    return json.dumps({"format": RECIPE_FORMAT, "name": name, "files": files},
                      sort_keys=True, separators=(",", ":")).encode()


def upload_recipe(folder: Path, address: str, token: str) -> dict[str, Any]:
    """The maintainer: a recipe folder up to the server, by its hash; the
    entry to put in the index comes back."""
    folder = Path(folder)
    raw = bundle(folder.name, recipe_files(folder))
    import httpx

    try:
        with httpx.Client(timeout=30) as http:
            answer = http.post(f"{address.rstrip('/')}/files", content=raw,
                               headers={"Authorization": f"Bearer {token}",
                                        "Content-Type": "application/json"})
    except httpx.HTTPError as exc:
        raise CatalogError(f"could not reach {address} ({type(exc).__name__})") from None
    if answer.status_code >= 300:
        raise CatalogError(f"{address} refused it (HTTP {answer.status_code}): "
                           f"{answer.text[:200]}")
    digest = answer.json()["sha256"]
    if digest != hashlib.sha256(raw).hexdigest():
        raise CatalogError("the server named the bundle by another hash; not trusted")
    return {"name": folder.name,
            "bundle": {"url": f"{address.rstrip('/')}/files/{digest}.json", "sha256": digest}}


def fetch_recipe(name: str, into: Path, home: Path | None = None,
                 fetch: Any = None, count: bool = True) -> Path:
    """A listed recipe, checked against the signed index, written to
    ``into/NAME`` for the harness to show and install. Counted, as a
    connector's install is, when the catalog is a server."""
    index = kept(home)
    if index is None:
        raise CatalogError("no catalog kept: `setu catalog use URL` first")
    entry = next((r for r in index.recipes if r.get("name") == name), None)
    if entry is None:
        raise CatalogError(f"the catalog does not list a recipe {name!r}")
    spec = entry.get("bundle") or {}
    url, digest = str(spec.get("url") or ""), str(spec.get("sha256") or "").lower()
    if not _fetchable(url) or len(digest) != 64:
        raise CatalogError(f"{name}: the catalog names no bundle to fetch it from")
    raw = (fetch or _download)(url)
    if hashlib.sha256(raw).hexdigest() != digest:
        raise CatalogError(f"{name}: the bundle is not the one the signed catalog names "
                           "-- nothing written")
    data = json.loads(raw)
    if data.get("format") != RECIPE_FORMAT or data.get("name") != name:
        raise CatalogError(f"{name}: not a {RECIPE_FORMAT} bundle for this recipe")
    target = Path(into) / name
    for rel, text in (data.get("files") or {}).items():
        if not (rel == "SKILL.md" or (rel.startswith("scripts/") and rel.count("/") == 1
                                      and ".." not in rel)):
            raise CatalogError(f"{name}: {rel!r} is not SKILL.md or scripts/<name>")
        dest = target / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text, encoding="utf-8")
    if count:
        _ping_one(index, home, name, digest[:12])
    return target


def fetch_connector(connector: str, into: Path, home: Path | None = None,
                    fetch: Any = None) -> Path:
    """A listed connector's wheel, checked by hash and unpacked into
    ``into/ID`` to be read -- not installed, not counted."""
    import io
    import zipfile

    index = kept(home)
    if index is None:
        raise CatalogError("no catalog kept: `setu catalog use URL` first")
    entry = index.connectors.get(connector)
    wheel = (entry or {}).get("wheel") or {}
    url, digest = str(wheel.get("url") or ""), str(wheel.get("sha256") or "").lower()
    if entry is None or not _fetchable(url) or len(digest) != 64:
        raise CatalogError(f"{connector}: the catalog names no wheel for it")
    raw = (fetch or _download)(url)
    if hashlib.sha256(raw).hexdigest() != digest:
        raise CatalogError(f"{connector}: the wheel is not the one the signed catalog names")
    target = Path(into) / connector
    root = target.resolve()
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        for member in archive.infolist():
            dest = (target / member.filename).resolve()
            if root not in dest.parents and dest != root:
                raise CatalogError(f"{connector}: the wheel writes outside itself "
                                   f"({member.filename}) -- refused")
            if not member.is_dir():
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(archive.read(member))
    return target


def _ping_one(index: Index, home: Path | None, item: str, version: str) -> None:
    """One install, told once -- the recipe's twin of ping_installs."""
    from setu import config

    if not is_address(index.source) or not config.share_installs():
        return
    path = _cache(home) / PINGED
    try:
        done = set(json.loads(path.read_text()))
    except (FileNotFoundError, ValueError):
        done = set()
    if f"{item}@{version}" in done:
        return
    import httpx

    try:
        with httpx.Client(timeout=2.0) as http:
            answer = http.post(f"{index.source}/installs", json={"id": item, "version": version})
        if answer.status_code < 500:
            done.add(f"{item}@{version}")
            path.write_text(json.dumps(sorted(done)))
    except httpx.HTTPError:
        pass


PINGED = "pinged.json"


def ping_installs(index: Index, home: Path | None = None, *, timeout: float = 2.0) -> int:
    """Tell the catalog server, once per version, which of ITS listed
    connectors are installed here: the id and the version, nothing else.
    Only connectors the index lists -- a sideloaded or hand-added one's
    name never leaves this computer. Off with ``setu config
    share-installs off``. Never raises: a count is not worth an error.
    Returns how many were sent."""
    from setu import config

    if not is_address(index.source) or not config.share_installs():
        return 0
    path = _cache(home) / PINGED
    try:
        done = set(json.loads(path.read_text()))
    except (FileNotFoundError, ValueError):
        done = set()
    due = []
    for cid, entry in index.connectors.items():
        installed = _installed_version(entry.get("package") or "")
        if installed and f"{cid}@{installed}" not in done:
            due.append((cid, installed))
    if not due:
        return 0
    import httpx

    sent = 0
    try:
        with httpx.Client(timeout=timeout) as http:
            for cid, installed in due:
                answer = http.post(f"{index.source}/installs",
                                   json={"id": cid, "version": installed})
                if answer.status_code < 500:      # counted, or refused for good
                    done.add(f"{cid}@{installed}")
                    sent += 1
    except httpx.HTTPError:
        pass
    path.write_text(json.dumps(sorted(done)))
    return sent


def fold_counts(index_path: Path, address: str, *, timeout: float = 15.0) -> int:
    """The maintainer's step before signing: the server's install totals
    into the index's ``installs``. Returns how many entries changed."""
    import httpx

    try:
        with httpx.Client(timeout=timeout) as http:
            totals = http.get(f"{address.rstrip('/')}/installs.json").json()
    except (httpx.HTTPError, ValueError) as exc:
        raise CatalogError(f"could not read {address}/installs.json ({exc})") from None
    data = json.loads(Path(index_path).read_text())
    changed = 0
    for entry in [*(data.get("connectors") or []), *(data.get("recipes") or [])]:
        key = entry.get("id") or entry.get("name")
        total = (totals.get(key) or {}).get("total")
        if total is not None and entry.get("installs") != total:
            entry["installs"] = total
            changed += 1
    Path(index_path).write_text(json.dumps(data, indent=2) + "\n")
    return changed


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
