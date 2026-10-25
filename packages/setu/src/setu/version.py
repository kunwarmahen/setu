"""Which version this is: the day of its last commit, and that day's count.

Every project in this family is versioned the same way, by its history
rather than by a number someone remembers to bump. ``YEAR.MONTH.DAY.N``
is the day of the last commit (in the time zone it was made in) and N
the commits made that day up to it: ``2026.10.25.3`` is the third commit
of 25 October. Two versions say at once which is newer, and when it was
made; the commit beside it says exactly which.

A checkout works it out from git, and ``+dirty`` marks uncommitted
changes. An image has no git: ``sarathi image`` writes a ``VERSION``
file at the checkout's top (``YEAR.MONTH.DAY.N COMMIT``), read instead.
With neither -- an install from somewhere else -- it is the package's own
``__PACKAGE_VERSION__`` and no commit.
"""

from __future__ import annotations

import argparse
import functools
import subprocess
import sys
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as installed
from pathlib import Path

#: The checkout's top: where .git is, and where an image's VERSION is.
ROOT = Path(__file__).resolve().parents[4]
FILE = "VERSION"
#: Commits looked back through to count a day's; more in one day is rare.
LOOK = 500


def from_git(root: Path) -> tuple[str, str] | None:
    """(version, commit) from a checkout's history, or None."""
    if not (root / ".git").exists():
        return None
    try:
        said = subprocess.run(["git", "-C", str(root), "log", f"-{LOOK}", "--format=%h %cd",
                               "--date=format:%Y.%m.%d"], capture_output=True, text=True,
                              timeout=5, check=False)
        rows = [line.split() for line in said.stdout.splitlines() if line.strip()]
        if said.returncode != 0 or not rows or len(rows[0]) != 2:
            return None
        day = rows[0][1]
        count = next((i for i, row in enumerate(rows) if row[1:] != [day]), len(rows))
        dirty = subprocess.run(["git", "-C", str(root), "status", "--porcelain",
                                "--untracked-files=no"], capture_output=True, text=True,
                               timeout=5, check=False).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return None
    return f"{day}.{count}" + ("+dirty" if dirty else ""), rows[0][0]


def from_file(root: Path) -> tuple[str, str] | None:
    try:
        words = (root / FILE).read_text().split()
    except OSError:
        return None
    return (words[0], words[1] if len(words) > 1 else "") if words else None


def from_package() -> str:
    try:
        return installed("setu")
    except PackageNotFoundError:
        return "unknown"


@functools.lru_cache(maxsize=1)
def found() -> tuple[str, str]:
    """(version, commit): git, else the image's VERSION, else the package's."""
    return from_git(ROOT) or from_file(ROOT) or (from_package(), "")


def version() -> str:
    return found()[0]


def commit() -> str:
    return found()[1]


def line() -> str:
    """``2026.10.25.3 (a65654e)``: what ``--version`` prints after the name."""
    number, at = found()
    return f"{number} ({at})" if at else number


class Show(argparse.Action):
    """``--version``, worked out only when asked: git is not run on every start."""

    def __init__(self, option_strings, dest=argparse.SUPPRESS, default=argparse.SUPPRESS,
                 help="the version: the day of the last commit, that day's count, "
                      "and the commit"):
        super().__init__(option_strings, dest=dest, default=default, nargs=0, help=help)

    def __call__(self, parser, namespace, values, option_string=None):
        sys.stdout.write(f"{parser.prog} {line()}\n")      # where argparse's own prints
        parser.exit()
