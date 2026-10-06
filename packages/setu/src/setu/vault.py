"""Where connections and their keys rest: one file, readable by you alone.

A connection is two things kept together: what the person chose (which
site, which account, how much access) and the key that proves it (a
refresh token, plus the client that earned it). They live in ONE entry
because they die together -- disconnecting deletes both, and a key with
no record of what it was granted for is a key nobody can reason about.

WHY A FILE AND NOT THE OS KEYRING. A keyring is not always there
(headless Linux, containers, a Pi), and a feature that works on some
machines and silently not on others is worse than a plain file with
honest permissions. The file is mode 0600 inside a 0700 directory, and
it lives under ``~/.local/state`` -- never the working directory,
because a refresh token in a project folder is one ``git add -A`` away
from being public. Other backends fit the same four verbs.

WRITES ARE ATOMIC. Write a sibling, fsync, rename over. A crash mid-write
leaves the old file or the new one, never half of either: losing every
connection because the laptop died during a token refresh would be a
strange price for a refresh.

AND SERIALISED. Every change is read-modify-write under an exclusive
lock on ``vault.lock``: two connectors refreshing at once (``gmail:work``
and ``gmail:personal`` in two sessions) would otherwise each write back
the file as they read it, and the slower one would erase the faster
one's fresh token.

A LOCKED FOLDER SEALS EVERY SECRET (seal.py). With a ``lock.json`` in
the folder, each entry's ``secret`` is written sealed to the folder's
public key, and read back open only when ``SETU_VAULT_KEY`` holds its
private key. Without it, ``get`` returns the entry with ``secret`` None
and ``locked`` True -- what was chosen stays readable, the key does not
-- and writing such an entry back keeps the sealed secret it had.

NOTHING HERE LEAVES THE PROCESS. The vault is read by Setu itself --
the sign-in, the refresh, the credential helper -- and by nothing a
model can call. A connector never opens this file; it asks the helper
for an access token and receives exactly that (see helper.py).
"""

from __future__ import annotations

import fcntl
import json
import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Protocol

from setu import seal

#: Override the home directory -- tests, a second profile, a container.
ENV_HOME = "SETU_HOME"


def default_home() -> Path:
    override = os.environ.get(ENV_HOME)
    if override:
        return Path(override).expanduser()
    state = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(state) / "setu"


class Vault(Protocol):
    def put(self, ref: str, entry: dict[str, Any]) -> None: ...
    def get(self, ref: str) -> dict[str, Any] | None: ...
    def delete(self, ref: str) -> bool: ...
    def list(self) -> list[str]: ...


class FileVault:
    """The default vault: ``<home>/vault.json``, 0600."""

    def __init__(self, home: Path | None = None) -> None:
        self.home = home or default_home()
        self.path = self.home / "vault.json"

    # ---- the four verbs --------------------------------------------------

    def put(self, ref: str, entry: dict[str, Any]) -> None:
        entry = {k: v for k, v in entry.items() if k != "locked"}
        public = seal.public_key(self.home)
        with self._locked():
            data = self._read()
            secret = entry.get("secret")
            if public is not None and isinstance(secret, dict) and "sealed" not in secret:
                entry["secret"] = {"sealed": seal.seal(
                    public, json.dumps(secret).encode(), f"secret:{ref}")}
            elif secret is None and isinstance(data.get(ref), dict) \
                    and data[ref].get("secret") is not None:
                entry["secret"] = data[ref]["secret"]   # read while locked: keep it
            data[ref] = entry
            self._write(data)

    def get(self, ref: str) -> dict[str, Any] | None:
        entry = self._read().get(ref)
        if not isinstance(entry, dict):
            return None
        entry = dict(entry)
        secret = entry.get("secret")
        if isinstance(secret, dict) and "sealed" in secret:
            private = seal.held_key(self.home)
            if private is None:
                entry["secret"], entry["locked"] = None, True
            else:
                entry["secret"] = json.loads(seal.open_sealed(
                    private, secret["sealed"], f"secret:{ref}"))
        return entry

    def delete(self, ref: str) -> bool:
        with self._locked():
            data = self._read()
            if ref not in data:
                return False
            del data[ref]
            self._write(data)
            return True

    def list(self) -> list[str]:
        return sorted(self._read())

    # ---- the file ---------------------------------------------------------

    @contextmanager
    def _locked(self) -> Iterator[None]:
        self.home.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(self.home / "vault.lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)   # closing releases the lock

    def _read(self) -> dict[str, Any]:
        try:
            raw = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return {}
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            # Loud, never "start empty": an empty vault written back over a
            # corrupt one would destroy every connection the person had.
            raise VaultError(f"{self.path} is not valid JSON ({exc}); "
                             "fix or move it -- nothing was changed") from None
        if not isinstance(data, dict):
            raise VaultError(f"{self.path} does not hold an object")
        return data

    def _write(self, data: dict[str, Any]) -> None:
        self.home.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.home, 0o700)
        fd, tmp = tempfile.mkstemp(dir=self.home, prefix=".vault-", suffix=".tmp")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=2, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise


class VaultError(Exception):
    """The vault file exists but cannot be trusted as it stands."""
