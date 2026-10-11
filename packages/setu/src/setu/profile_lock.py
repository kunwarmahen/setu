"""One browser per profile, shared with Yantra -- and Chrome's leftovers.

A sign-in window and a Yantra run on the same profile would be two
Chromes on one directory. Chrome refuses the second itself, but only
when both see the same computer name; a Setu in a container and a
Yantra on the host do not. So Setu takes the lock file Yantra takes
(``yantra.lock`` in the profile, ``flock``: the kernel lets go when the
process ends) for as long as its browser is open.

Holding it, Setu also knows no Yantra and no other Setu window is on the
profile, so Chrome's own ``SingletonLock`` naming ANOTHER computer --
left by a Chrome that was killed rather than closed, on the host or in
an older container -- is a leftover, not a live browser: it is removed,
and a line says so. Without that, Chrome in a container refuses such a
profile for good ("in use by another computer"). A lock naming this
computer is left to Chrome, which checks the pid itself; a socket that
answers is a live Chrome and is never touched.
"""

from __future__ import annotations

import fcntl
import os
import socket
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from setu.browser import BrowserSignInFailed

#: The same file Yantra's profile_lock takes.
LOCK_NAME = "yantra.lock"
CHROME_LOCKS = ("SingletonLock", "SingletonCookie", "SingletonSocket")
#: A person is waiting on a sign-in window: not long.
WAIT = 10.0
_POLL = 0.5


class ProfileBusy(BrowserSignInFailed):
    """Another program has a browser open on the profile."""


@contextmanager
def held(profile: Path, why: str = "Setu sign-in window",
         wait: float = WAIT) -> Iterator[None]:
    """The profile's lock for the duration, Chrome's leftovers cleared;
    ProfileBusy naming the holder if it stays taken for ``wait`` seconds."""
    profile.mkdir(parents=True, exist_ok=True)
    fd = os.open(profile / LOCK_NAME, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        deadline = time.monotonic() + wait
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise ProfileBusy(_busy(fd, profile)) from None
                time.sleep(_POLL)
        os.ftruncate(fd, 0)
        os.pwrite(fd, f"{os.getpid()}\n{datetime.now():%H:%M}\n{why}\n".encode(), 0)
        left = clear_left_chrome_lock(profile)
        if left:
            print(f"setu: removed a browser lock left in {profile} by {left}, "
                  "which is no longer running", file=sys.stderr)
        try:
            yield
        finally:
            os.ftruncate(fd, 0)
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def clear_left_chrome_lock(profile: Path) -> str | None:
    """Remove Chrome's lock when it names another computer and nothing
    answers its socket; say whose it was, or None. Hold ``held`` first."""
    try:
        target = os.readlink(profile / "SingletonLock")
    except OSError:
        return None
    host, _, pid = target.rpartition("-")
    if not host or host == socket.gethostname() or _answers(profile):
        return None
    for name in CHROME_LOCKS:
        try:
            (profile / name).unlink()
        except FileNotFoundError:
            pass
    return f"{host} pid {pid}"


def _answers(profile: Path) -> bool:
    try:
        path = os.readlink(profile / "SingletonSocket")
    except OSError:
        return False
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(1.0)
        try:
            sock.connect(path)
        except OSError:
            return False
    return True


def _busy(fd: int, profile: Path) -> str:
    lines = os.pread(fd, 200, 0).decode(errors="replace").splitlines()
    if len(lines) < 3:
        whose = "another program"
    else:
        pid, since, why = lines[:3]
        program = why if why.startswith("Setu") else f"Yantra, for {why}"
        whose = f"{program} (pid {pid}, since {since})"
    return (f"the browser profile {profile} is in use by {whose}. Only one browser can "
            "use a profile at a time: try again when that is finished")
