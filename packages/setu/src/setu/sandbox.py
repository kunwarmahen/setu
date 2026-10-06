"""Where a connector runs: no network, and nothing of yours to read.

Setu makes a connector's requests for it (proxy.py), so the connector
needs no network at all -- and is given none. It runs inside
bubblewrap with its own empty network, where the only way out is the
one socket Setu listens on:

* ``--unshare-net``: no route anywhere; even the host's 127.0.0.1 is
  another machine's from in here. Abstract unix sockets go with it.
* your home folder is an empty one, except the Python the connector
  runs on, put back read-only. The vault, your SSH keys, your mail
  client's files: not there.
* Setu's own folder is emptied too, wherever it lives.
* ``/run`` and ``/tmp`` are empty: no podman, D-Bus or X11 socket to
  talk to instead.
* the rest of the system is read-only, as programs need it to start.

WITHOUT BUBBLEWRAP the connector still holds no key -- every request
still goes through Setu and its rules -- but it has the computer's
network and can read your files, and ``setu status`` says so in those
words rather than claiming a wall that is not there.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from collections.abc import Sequence
from functools import cache
from pathlib import Path

#: ``off`` runs connectors without bubblewrap (where user namespaces are
#: refused); the card then says the connector is not confined.
ENV_SANDBOX = "SETU_SANDBOX"


@cache
def available() -> bool:
    """Whether bubblewrap is here and may make a network-less sandbox."""
    if os.environ.get(ENV_SANDBOX, "").lower() in ("off", "0", "no"):
        return False
    bwrap = shutil.which("bwrap")
    if bwrap is None:
        return False
    try:
        done = subprocess.run([bwrap, "--ro-bind", "/", "/", "--unshare-net", "true"],
                              capture_output=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return done.returncode == 0


def _python_paths() -> list[Path]:
    """What the connector's Python needs to start: this environment, the
    interpreter it was made from, and every import path (an editable
    install's source folder among them)."""
    found = [Path(sys.prefix), Path(sys.base_prefix).resolve(),
             Path(sys.executable).resolve().parent.parent]
    found += [Path(p) for p in sys.path if p]
    return found


def wrap(argv: Sequence[str], *, keep: Sequence[Path], hide: Sequence[Path] = (),
         home: Path | None = None) -> list[str]:
    """``argv`` as bubblewrap will run it. ``keep`` are folders bound in
    read-write at the same path (the socket's); ``hide`` are folders
    emptied whatever else is bound (Setu's home)."""
    home = (home or Path.home()).resolve()
    args = ["bwrap", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc",
            "--tmpfs", "/tmp", "--tmpfs", "/run", "--tmpfs", str(home)]
    program = Path(argv[0])
    back = _python_paths() + ([program.resolve().parent] if program.is_absolute() else [])
    seen: set[Path] = set()
    for path in back:
        path = path.resolve() if path.exists() else path
        if path in seen or not path.exists() or not path.is_relative_to(home):
            continue      # outside the home folder it is visible already
        seen.add(path)
        args += ["--ro-bind", str(path), str(path)]
    for path in hide:
        args += ["--tmpfs", str(Path(path).expanduser().resolve())]
    for path in keep:
        args += ["--bind", str(path), str(path)]
    args += ["--unshare-net", "--unshare-pid", "--unshare-ipc", "--die-with-parent",
             "--chdir", "/", "--"]
    return args + list(argv)
