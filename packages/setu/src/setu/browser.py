"""Signing in to a site that has no API: your own browser, a profile of its own.

Some sites offer a person no way in but the website -- Amazon's orders,
X's timeline. For those the connection is not a token but a BROWSER
PROFILE: a directory where a real browser keeps that site's cookies.
The person signs in there by hand, once, in a window of their own
browser; the harness's browser tools later open the same directory and
simply are signed in.

ONE PROFILE PER CONNECTION. ``profiles/amazon-personal/`` holds Amazon's
cookies and nothing else, so a page on one site can never ride another
site's sign-in -- the reason not to reuse the browser a person browses
with.

A PLAIN WINDOW, NOT AN AUTOMATED ONE. The sign-in window is the person's
own Chrome (or Chromium, Brave, Edge) started as an ordinary program on
that directory: nothing drives it, so a site checking for robots sees
none. Setu waits for the window to close.

THE SAME BROWSER, THE SAME KEY, ON BOTH HALVES. Chromium refuses a
profile written by a newer version of itself, and encrypts cookies with
a key chosen by a launch flag -- a browser holding the other key DELETES
what it cannot read. So the connection records which browser signed in,
the harness opens the profile with that browser, and both pass
``--password-store=basic`` (the key Playwright always uses).

SIGNED IN MEANS A SIGN-IN COOKIE. A window closed before signing in
leaves cookies too, so counting them proves nothing. The manifest names
the cookies that exist only after a sign-in (``at-*`` on Amazon,
``auth_token`` on X), and Setu looks for those names -- names only: the
values are encrypted and never read.

A profile is a credential store in plain sight, so it lives beside the
vault (0700), never in a project folder.

A SITE NOBODY HAS NAMED THE COOKIES OF is proved by its PAGE instead.
After the window closes, the site's start page is loaded once more on
the profile -- headless, still driven by nobody: ``--dump-dom`` prints
the page and quits -- and read for the signs a person sees: a password
box means signed out, a sign-out link means signed in. Cookie names that
appeared since a signed-out visit are kept as evidence, never as proof:
a site sets plenty of new cookies for a visitor who never signs in.
"""

from __future__ import annotations

import fnmatch
import os
import re
import shutil
import signal
import sqlite3
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

from setu import config
from setu.manifest import Manifest
from setu.vault import default_home

PROFILES = "profiles"
#: Must match the harness's browser: see the module docstring.
COOKIE_KEY_ARG = "--password-store=basic"
#: Browsers looked for on PATH when none is configured, best first.
CANDIDATES = ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
              "brave-browser", "brave", "microsoft-edge", "microsoft-edge-stable")
#: How long a window asked to quit gets to write its cookies.
CLOSE_SECONDS = 15.0
#: How long a headless look at a page may take (Chrome's own, then ours).
DUMP_MS = 10_000
DUMP_SECONDS = 60

_CODE = re.compile(r"<(script|style|noscript|template)\b.*?</\1\s*>", re.I | re.S)
_PASSWORD = re.compile(r"<input\b[^>]*\btype\s*=\s*[\"']?password", re.I)
_SIGN_OUT = re.compile(
    r"\b(href|action)\s*=\s*[\"'][^\"']*(log_?out|log-out|sign_?out|sign-out|logoff)"
    r"[^\"']*[\"']|>\s*(sign|log)\s*(out|off)\s*<", re.I)
_SIGN_IN = re.compile(r">\s*(sign|log)\s*in\s*<", re.I)
_TITLE = re.compile(r"<title[^>]*>(.*?)</title\s*>", re.I | re.S)


class BrowserSignInFailed(Exception):
    """The window closed, and nothing in it says the person signed in."""


def profile_dir(ref: str) -> Path:
    """Where ``amazon:personal``'s profile lives (made 0700 on use)."""
    return default_home() / PROFILES / ref.replace(":", "-")


def find_browser(explicit: str | None = None) -> str | None:
    """The browser to sign in with: flag, ``SETU_BROWSER``, ``setu config
    browser``, else the first Chromium-family browser on PATH."""
    named = config.browser(explicit)
    if named:
        found = shutil.which(os.path.expanduser(named))
        return found or None
    for name in CANDIDATES:
        found = shutil.which(name)
        if found:
            return found
    return None


def _has_state(profile: Path) -> bool:
    return (profile / "Local State").exists() or (profile / "Default").is_dir()


def signed_in(profile: Path, patterns: tuple[str, ...], hosts: tuple[str, ...]) -> list[str]:
    """The hosts holding a sign-in cookie in ``profile`` -- by NAME only,
    from Chromium's cookie store opened read-only. Empty when none, or
    when the store cannot be read."""
    db = profile / "Default" / "Cookies"
    if not db.exists():
        return []
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    except sqlite3.Error:
        return []
    try:
        rows = conn.execute("select host_key, name from cookies").fetchall()
    except sqlite3.Error:
        return []
    finally:
        conn.close()
    found = []
    for host_key, name in rows:
        host = str(host_key).lstrip(".")
        if not any(host == h or host.endswith("." + h) for h in hosts):
            continue
        if any(fnmatch.fnmatchcase(str(name), pattern) for pattern in patterns):
            if host not in found:
                found.append(host)
    return found


def cookie_names(profile: Path, hosts: tuple[str, ...]) -> set[str]:
    """Every cookie NAME on ``hosts`` in ``profile`` (values never read)."""
    db = profile / "Default" / "Cookies"
    if not db.exists():
        return set()
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        try:
            rows = conn.execute("select host_key, name from cookies").fetchall()
        finally:
            conn.close()
    except sqlite3.Error:
        return set()
    return {str(name) for host_key, name in rows
            if any(str(host_key).lstrip(".") == h or str(host_key).lstrip(".").endswith("." + h)
                   for h in hosts)}


def dump_dom(browser: str, profile: Path, url: str,
             run: Callable[..., Any] = subprocess.run) -> str:
    """The page at ``url`` as ``profile`` sees it, from a headless run of
    ``browser`` that prints it and quits. Empty when the site refuses a
    headless browser or the page never came."""
    argv = [browser, "--headless=new", f"--user-data-dir={profile}", "--no-first-run",
            "--no-default-browser-check", COOKIE_KEY_ARG, f"--timeout={DUMP_MS}",
            "--dump-dom", url]
    try:
        done = run(argv, capture_output=True, text=True, timeout=DUMP_SECONDS)
    except (subprocess.TimeoutExpired, OSError):
        return ""
    return done.stdout or ""


def page_state(html: str) -> str:
    """``in``, ``out`` or ``unknown``, from what a person would see on the
    page: never ``in`` while a password box is showing."""
    html = _CODE.sub("", html)
    password = bool(_PASSWORD.search(html))
    sign_out = bool(_SIGN_OUT.search(html))
    if sign_out and not password:
        return "in"
    if password or _SIGN_IN.search(html):
        return "out"
    return "unknown"


def page_title(html: str) -> str:
    found = _TITLE.search(html)
    return re.sub(r"\s+", " ", found.group(1)).strip() if found else ""


def _close(proc: subprocess.Popen) -> None:
    """Ask the browser to quit the way Ctrl-C would -- it writes its
    cookies on the way out -- and kill it only if it will not."""
    try:
        os.killpg(proc.pid, signal.SIGINT)
        proc.wait(timeout=CLOSE_SECONDS)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def window(browser: str, profile: Path, url: str,
           popen: Callable[..., Any] = subprocess.Popen) -> None:
    """Open ``url`` in a plain window of ``browser`` on ``profile`` and
    wait until the person closes it."""
    profile.mkdir(parents=True, exist_ok=True)
    os.chmod(profile.parent, 0o700)
    os.chmod(profile, 0o700)
    argv = [browser, f"--user-data-dir={profile}", "--no-first-run",
            "--no-default-browser-check", COOKIE_KEY_ARG, url]
    # its own session: the terminal's Ctrl-C reaches Setu, which asks the
    # browser to close properly instead of cutting it off mid-write
    proc = popen(argv, start_new_session=True)
    try:
        proc.wait()
    except KeyboardInterrupt:
        _close(proc)
        raise
    if not _has_state(profile):
        raise BrowserSignInFailed(
            f"{browser} closed without writing anything to {profile}. Usually it was "
            "already running in a way that took the window over, or it is a snap that "
            "cannot write there -- close it, or name another with `setu config browser`")


#: Files a Chromium profile rewrites as pages are visited on it.
ACTIVITY_FILES = ("Default/History", "Default/Cookies", "Default/Network/Cookies",
                  "Default/Preferences")
#: Writes this soon after the sign-in are the sign-in window's own.
SIGN_IN_SECONDS = 120


def last_active(profile: Path, created: str = "") -> str | None:
    """When something last used ``profile`` -- the browser rewrites its
    history and cookies as pages are visited -- or None when nothing has
    since the sign-in. Nothing is opened; only the files' times are read.

    A harness's site tools never tell Setu they ran, and need not: the
    browser they drive keeps this record already."""
    from datetime import UTC, datetime

    times = []
    for name in ACTIVITY_FILES:
        try:
            times.append((profile / name).stat().st_mtime)
        except OSError:
            continue
    if not times:
        return None
    latest = max(times)
    if created:
        try:
            signed = datetime.strptime(created, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
            if latest <= signed.timestamp() + SIGN_IN_SECONDS:
                return None
        except ValueError:
            pass
    return datetime.fromtimestamp(latest, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def home(manifest: Manifest, hosts: list[str]) -> str:
    """The address the agent starts from: the manifest's, or -- for a site
    with a store per country -- the store the person signed in to."""
    spec = manifest.browser
    assert spec is not None
    if spec.home_from_cookie and hosts:
        host = hosts[0]
        return f"https://{host if host.startswith('www.') else 'www.' + host}/"
    return spec.start_url


def remove_profile(path: str | Path) -> bool:
    """Delete a connection's profile -- only one under Setu's own
    ``profiles/`` directory, whatever the vault entry says."""
    target = Path(path).resolve()
    root = (default_home() / PROFILES).resolve()
    if root not in target.parents or not target.exists():
        return False
    shutil.rmtree(target)
    return True
