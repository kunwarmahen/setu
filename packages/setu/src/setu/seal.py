"""A folder locked with a passphrase: its keys unreadable at rest.

Setu's folder is readable by the account it runs as, which is fine when
that account is yours. Behind a service it isn't: a person's sign-ins sit
in a folder on the owner's computer, and the owner -- or a backup, or a
stolen disk -- can read them. A LOCKED folder keeps them sealed, with a
key only the person's passphrase opens.

TWO KEYS, SO SEALING NEVER NEEDS THE PASSPHRASE. ``lock.json`` holds an
X25519 key pair: the public half in the clear, the private half sealed
with a key derived from the passphrase (scrypt). Sealing uses only the
public half, so anything may seal at any time -- a fresh sign-in, a token
refresh, a service that restarted and finds a browser profile left
unpacked. Opening needs the private half, which exists outside
``lock.json`` only while someone holds it: ``SETU_VAULT_KEY`` (that
private key, base64), given to Setu by whoever the person unlocked for.

WHAT IS SEALED.

* each connection's ``secret`` (refresh tokens, Home Assistant tokens),
  always, on every write -- ``{"sealed": "..."}`` in the vault file;
* each browser profile (Amazon's, X's cookies), when the folder is
  locked: packed, sealed into ``profiles/<name>.sealed``, the folder
  removed. Unlocking unpacks them; locking packs them again. Chrome's
  caches are left out of the pack: they hold no sign-in and most of the
  bytes.

What stays readable: which accounts exist, their addresses and levels --
what ``setu list`` shows -- so a person can be told *which* account is
locked.

THE HONEST LIMIT. While a folder is unlocked, its private key is in the
memory of whatever holds it, and its profiles are unpacked on disk. The
computer's administrator can take either then. Locked protects the
folder at rest: the owner browsing files, a backup, a disk. It is not a
promise against the machine the person chose to run their agent on.

Format of a sealed blob (base64): ephemeral X25519 public key (32) +
nonce (12) + AES-256-GCM ciphertext; the AES key is HKDF-SHA256 of the
shared secret, and the associated data names what was sealed (a
connection's ref, a profile's name), so a blob cannot be moved to
another entry and opened as it.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import secrets
import shutil
import tarfile
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

#: The private key of an unlocked folder, base64 -- held by whoever the
#: person unlocked for, and never passed on to a connector.
ENV_KEY = "SETU_VAULT_KEY"
LOCK_FILE = "lock.json"
FORMAT = "setu.lock.v1"
#: scrypt's cost: about 0.1 s and 32 MB here -- slow for a guesser.
SCRYPT = {"n": 2 ** 15, "r": 8, "p": 1}
#: Chrome's folders that hold no sign-in, only bytes: not packed.
CACHES = {"Cache", "Code Cache", "GPUCache", "DawnCache", "GrShaderCache",
          "ShaderCache", "CacheStorage", "ScriptCache", "Crashpad", "BrowserMetrics"}
SEALED_SUFFIX = ".sealed"


class Locked(Exception):
    """The folder is locked and this needs it open."""


class WrongPassphrase(Exception):
    pass


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def _kdf(passphrase: str, salt: bytes, params: dict[str, int]) -> bytes:
    return hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, dklen=32,
                          maxmem=128 * 1024 * 1024, **params)


def _raw(private: X25519PrivateKey) -> bytes:
    return private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                 serialization.NoEncryption())


def _pub_raw(public: X25519PublicKey) -> bytes:
    return public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


# ---- sealing and opening ----------------------------------------------------------


def _aes_key(shared: bytes, ephemeral: bytes, recipient: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=ephemeral + recipient,
                info=b"setu.seal.v1").derive(shared)


def seal(public: bytes, data: bytes, what: str) -> str:
    """``data``, sealed to ``public``; only its private key opens it."""
    ephemeral = X25519PrivateKey.generate()
    eph_pub = _pub_raw(ephemeral.public_key())
    key = _aes_key(ephemeral.exchange(X25519PublicKey.from_public_bytes(public)), eph_pub,
                   public)
    nonce = secrets.token_bytes(12)
    return _b64(eph_pub + nonce + AESGCM(key).encrypt(nonce, data, what.encode()))


def open_sealed(private: bytes, blob: str, what: str) -> bytes:
    raw = _unb64(blob)
    eph_pub, nonce, body = raw[:32], raw[32:44], raw[44:]
    me = X25519PrivateKey.from_private_bytes(private)
    key = _aes_key(me.exchange(X25519PublicKey.from_public_bytes(eph_pub)), eph_pub,
                   _pub_raw(me.public_key()))
    try:
        return AESGCM(key).decrypt(nonce, body, what.encode())
    except InvalidTag:
        raise Locked(f"{what}: sealed with another key, or changed since") from None


# ---- the lock file -------------------------------------------------------------------


def lock_path(home: Path) -> Path:
    return home / LOCK_FILE


def read_lock(home: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(lock_path(home).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    if data.get("format") != FORMAT:
        raise Locked(f"{lock_path(home)} is not a {FORMAT} file")
    return data


def public_key(home: Path) -> bytes | None:
    lock = read_lock(home)
    return _unb64(lock["public"]) if lock else None


def _write_lock(home: Path, data: dict[str, Any]) -> None:
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = lock_path(home).with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        json.dump(data, out, indent=2)
    os.replace(tmp, lock_path(home))


def _wrap(private: bytes, passphrase: str, public: bytes) -> dict[str, Any]:
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    wrapped = AESGCM(_kdf(passphrase, salt, SCRYPT)).encrypt(nonce, private, public)
    return {"format": FORMAT, "public": _b64(public), "kdf": "scrypt", **SCRYPT,
            "salt": _b64(salt), "private": _b64(nonce + wrapped)}


def create(home: Path, passphrase: str) -> bytes:
    """Lock a folder that was not: a new key pair. Returns the private key."""
    if read_lock(home) is not None:
        raise Locked("this folder is locked already; change its passphrase instead")
    _check_passphrase(passphrase)
    private = X25519PrivateKey.generate()
    _write_lock(home, _wrap(_raw(private), passphrase, _pub_raw(private.public_key())))
    return _raw(private)


def unlock_key(home: Path, passphrase: str) -> bytes:
    """The private key, from the passphrase -- or ``WrongPassphrase``."""
    lock = read_lock(home)
    if lock is None:
        raise Locked("this folder is not locked")
    raw = _unb64(lock["private"])
    params = {k: int(lock[k]) for k in ("n", "r", "p")}
    try:
        return AESGCM(_kdf(passphrase, _unb64(lock["salt"]), params)).decrypt(
            raw[:12], raw[12:], _unb64(lock["public"]))
    except InvalidTag:
        raise WrongPassphrase("that is not this folder's passphrase") from None


def change(home: Path, old: str, new: str) -> None:
    private = unlock_key(home, old)
    _check_passphrase(new)
    _write_lock(home, _wrap(private, new, public_key(home) or b""))


def _check_passphrase(passphrase: str) -> None:
    if len(passphrase) < 8:
        raise WrongPassphrase("a passphrase needs at least 8 characters -- a few "
                              "words are easier to remember than symbols")


def held_key(home: Path) -> bytes | None:
    """``SETU_VAULT_KEY``, if it is this folder's private key."""
    raw = os.environ.get(ENV_KEY, "").strip()
    public = public_key(home)
    if not raw or public is None:
        return None
    try:
        private = _unb64(raw)
        if _pub_raw(X25519PrivateKey.from_private_bytes(private).public_key()) != public:
            return None
    except ValueError:
        return None
    return private


# ---- browser profiles ------------------------------------------------------------------


def _pack(folder: Path) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        def keep(info: tarfile.TarInfo) -> tarfile.TarInfo | None:
            return None if set(Path(info.name).parts) & CACHES else info
        tar.add(folder, arcname=".", filter=keep)
    return buffer.getvalue()


def seal_profiles(home: Path, profiles: Path) -> list[str]:
    """Pack every unpacked profile under ``profiles`` (public key only).
    Returns their names."""
    public = public_key(home)
    if public is None or not profiles.is_dir():
        return []
    done = []
    for folder in sorted(p for p in profiles.iterdir() if p.is_dir()):
        target = folder.with_name(folder.name + SEALED_SUFFIX)
        tmp = target.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as out:
            out.write(seal(public, _pack(folder), f"profile:{folder.name}"))
        os.replace(tmp, target)
        shutil.rmtree(folder)
        done.append(folder.name)
    return done


def open_profiles(home: Path, profiles: Path, private: bytes) -> list[str]:
    """Unpack every sealed profile; the sealed copy goes once it is out."""
    if not profiles.is_dir():
        return []
    done = []
    for sealed in sorted(profiles.glob("*" + SEALED_SUFFIX)):
        name = sealed.name[:-len(SEALED_SUFFIX)]
        data = open_sealed(private, sealed.read_text(encoding="ascii"), f"profile:{name}")
        target = profiles / name
        target.mkdir(mode=0o700, exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
            tar.extractall(target, filter="data")
        sealed.unlink()
        done.append(name)
    return done


def sealed_profiles(profiles: Path) -> list[str]:
    if not profiles.is_dir():
        return []
    return sorted(p.name[:-len(SEALED_SUFFIX)] for p in profiles.glob("*" + SEALED_SUFFIX))
