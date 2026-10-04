"""Independent certifications: people who ran a version put their name to it.

No scan or review proves that code holds no attack. What can be asked is
that people independent of the catalog -- a company, a known developer,
a user group -- deploy a version on their own servers, check it however
they see fit, and say so under their own key. Several independent names
on one exact version are worth far more than one, and each person
decides whose names they trust.

A CERTIFICATION IS FOR ONE VERSION, BY HASH. ``subject`` names the
recipe or connector, its version and the SHA-256 of the exact bytes the
catalog lists (a recipe's bundle, a connector's wheel). v2 needs its own.

SIGNED BY THE CERTIFIER, NOT THE CATALOG. The document carries the
certifier's public key and is signed with the matching private one; the
key id is recomputed from the key, never believed. The catalog server
stores and serves certifications but cannot add, change or drop one
without the signature failing -- that is the independence.

WITHDRAWN BY THE SAME KEY. A later document from the same certifier for
the same subject with ``verdict: revoked`` ("we found a problem") wins
over their earlier certification.

YOU CHOOSE WHOSE WORD COUNTS. ``trust`` adds a certifier's .pub to the
ones this person trusts; a card counts those apart from all the others.
A certifier's name is their own claim -- the key is the identity.
"""

from __future__ import annotations

import base64
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from setu import catalog
from setu.vault import default_home

FORMAT = "setu.cert.v1"
VERDICTS = ("certified", "revoked")
KINDS = ("recipe", "connector")
#: What a certifier may say they did; free words are kept in the statement.
CHECKS = ("scan", "sandboxed-run", "deployed", "read-the-code", "rebuilt-from-source")
TRUSTED_FILE = "trusted-certifiers.json"


class CertError(Exception):
    """A certification that cannot be believed as given."""


# ---- keys -------------------------------------------------------------------------------


def keygen(path: Path, name: str) -> tuple[Path, str]:
    """A certifier's key: as a catalog key, with the name they go by kept
    in the .pub (their claim; the key is the identity)."""
    if not name.strip():
        raise CertError("say the name you certify under (--as)")
    pub, kid = catalog.keygen(path)
    data = json.loads(pub.read_text())
    data["name"] = name.strip()[:80]
    pub.write_text(json.dumps(data, indent=2) + "\n")
    return pub, kid


def load_public(path: Path) -> dict[str, str]:
    """A certifier's .pub -> {id, public, name}; the id is recomputed."""
    pub = catalog.load_public(path)
    try:
        name = str(json.loads(Path(path).read_text()).get("name") or "")
    except (OSError, ValueError):
        name = ""
    return {**pub, "name": name}


def _trusted_path(home: Path | None) -> Path:
    return (home or default_home()) / TRUSTED_FILE


def trusted(home: Path | None = None) -> dict[str, dict[str, str]]:
    """The certifiers this person trusts: id -> {public, name}."""
    try:
        data = json.loads(_trusted_path(home).read_text())
    except FileNotFoundError:
        return {}
    except ValueError as exc:
        raise CertError(f"{_trusted_path(home)} is not valid JSON ({exc})") from None
    return {c["id"]: {"public": c["public"], "name": c.get("name", "")}
            for c in data.get("certifiers", [])}


def _save_trusted(keys: dict[str, dict[str, str]], home: Path | None) -> None:
    path = _trusted_path(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps({"certifiers": [{"id": k, **v} for k, v in keys.items()]},
                              indent=2) + "\n")
    os.replace(tmp, path)


def trust(pub: dict[str, str], home: Path | None = None) -> None:
    keys = trusted(home)
    keys[pub["id"]] = {"public": pub["public"], "name": pub.get("name", "")}
    _save_trusted(keys, home)


def distrust(kid: str, home: Path | None = None) -> bool:
    keys = trusted(home)
    gone = keys.pop(kid, None) is not None
    _save_trusted(keys, home)
    return gone


# ---- the document -----------------------------------------------------------------------


def canonical(cert: dict[str, Any]) -> bytes:
    """The bytes a signature covers: everything but the signature."""
    return json.dumps({k: v for k, v in cert.items() if k != "sig"},
                      sort_keys=True, separators=(",", ":")).encode()


def make(subject: dict[str, str], private: Path, *, name: str, statement: str,
         checks: list[str], verdict: str = "certified", at: str | None = None) -> dict:
    """A signed certification (or, with ``verdict="revoked"``, its withdrawal)."""
    if verdict not in VERDICTS:
        raise CertError(f"verdict is {' or '.join(VERDICTS)}")
    unknown = [c for c in checks if c not in CHECKS]
    if unknown:
        raise CertError(f"unknown check(s) {unknown}; known: {', '.join(CHECKS)} "
                        "(say anything else in the statement)")
    if not statement.strip():
        raise CertError("say what you did and found (the statement); a name alone "
                        "certifies nothing")
    _subject_ok(subject)
    key = catalog._load_private(private)
    public = catalog._raw_public(key.public_key())
    cert = {"format": FORMAT, "subject": dict(subject),
            "certifier": {"key": catalog.key_id(public),
                          "public": base64.b64encode(public).decode(),
                          "name": name.strip()[:80]},
            "verdict": verdict, "statement": statement.strip()[:4000],
            "checks": list(checks),
            "at": at or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")}
    cert["sig"] = base64.b64encode(key.sign(canonical(cert))).decode()
    return cert


def _subject_ok(subject: dict[str, Any]) -> None:
    if subject.get("kind") not in KINDS or not subject.get("id"):
        raise CertError("a subject is a recipe or a connector, by id")
    digest = str(subject.get("sha256") or "")
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        raise CertError("a subject names the exact bytes it covers (sha256)")


def verify(cert: dict[str, Any]) -> str:
    """The certifier's key id when the document is whole and signed by
    the key it carries; raises otherwise."""
    if cert.get("format") != FORMAT:
        raise CertError(f"not a {FORMAT} certification")
    _subject_ok(cert.get("subject") or {})
    if cert.get("verdict") not in VERDICTS:
        raise CertError("no verdict")
    who = cert.get("certifier") or {}
    try:
        public = base64.b64decode(who.get("public", ""), validate=True)
        Ed25519PublicKey.from_public_bytes(public).verify(
            base64.b64decode(cert.get("sig", ""), validate=True), canonical(cert))
    except (InvalidSignature, ValueError, TypeError):
        raise CertError("the signature does not match the certification") from None
    kid = catalog.key_id(public)
    if who.get("key") != kid:
        raise CertError("the key id does not match the key")
    return kid


def subject_for(spec: str, index: Any) -> dict[str, str]:
    """``recipe:NAME`` or ``connector:ID`` -> the exact version the signed
    index lists, by hash. What is not listed cannot be certified here."""
    kind, _, ident = spec.partition(":")
    if kind not in KINDS or not ident:
        raise CertError("name it as recipe:NAME or connector:ID")
    if index is None:
        raise CertError("no catalog kept: `setu catalog use URL` first")
    if kind == "recipe":
        entry = next((r for r in index.recipes if r.get("name") == ident), None)
        digest = str(((entry or {}).get("bundle") or {}).get("sha256") or "")
        version = digest[:12]
    else:
        entry = index.connectors.get(ident)
        digest = str(((entry or {}).get("wheel") or {}).get("sha256") or "")
        version = str((entry or {}).get("version") or "")
    if entry is None:
        raise CertError(f"the catalog does not list {spec}")
    if len(digest) != 64:
        raise CertError(f"{spec}: the catalog names no exact bytes for it to certify")
    return {"kind": kind, "id": ident, "version": version, "sha256": digest}


# ---- what a card says --------------------------------------------------------------------


def standing(certs: list[dict[str, Any]], subject: dict[str, str],
             trusted_keys: dict[str, dict[str, str]]) -> dict[str, Any]:
    """For one exact subject: who you trust certified it, how many others
    did, and who withdrew. Bad documents and ones for other bytes are
    skipped; each certifier's LATEST word counts."""
    latest: dict[str, dict[str, Any]] = {}
    for cert in certs:
        try:
            kid = verify(cert)
        except CertError:
            continue
        s = cert["subject"]
        if (s.get("kind"), s.get("id"), s.get("sha256")) != \
                (subject.get("kind"), subject.get("id"), subject.get("sha256")):
            continue
        if kid not in latest or cert["at"] > latest[kid]["at"]:
            latest[kid] = cert
    trusted_names, others, revoked = [], 0, []
    for kid, cert in latest.items():
        name = (trusted_keys.get(kid) or {}).get("name") or cert["certifier"].get("name") \
            or kid
        if cert["verdict"] == "revoked":
            revoked.append(name)
        elif kid in trusted_keys:
            trusted_names.append(name)
        else:
            others += 1
    return {"trusted": sorted(trusted_names), "others": others, "revoked": sorted(revoked)}


def line(standing_: dict[str, Any]) -> str:
    """'certified by 2 you trust (Acme Labs, R. Kumar) + 3 others', or ''."""
    text = ""
    names = standing_.get("trusted") or []
    if names:
        text = f"certified by {len(names)} you trust ({', '.join(names)})"
    others = standing_.get("others") or 0
    if others:
        text += (" + " if text else "certified by ") \
            + f"{others} other{'s' if others != 1 else ''}"
    revoked = standing_.get("revoked") or []
    if revoked:
        text += (" · " if text else "") + f"withdrawn by {', '.join(revoked)}"
    return text
