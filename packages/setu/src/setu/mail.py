"""A mail account kept by its password: IMAP, for any mail service.

Gmail signs in with Google, and nothing here is needed for it. Every
other mail service -- Fastmail, iCloud, Outlook, a mail server of your
own -- speaks IMAP, and IMAP signs in with a user and a password. For
Gmail, iCloud and Outlook that is an APP PASSWORD the account's security
settings make, never the person's own: it can be revoked on its own, and
it reaches mail and nothing else.

THE PASSWORD IS KEPT LIKE EVERY OTHER KEY. It lives in the vault entry
of its connection (``mail:work``), in the person's own folder, under the
person's passphrase when the folder is locked; it is checked against the
server before anything is saved, and ``setu list``, the page and
``setu status`` never show it.

IT LEAVES ONLY TO A PROGRAM, ONLY OVER A PIPE. IMAP is not HTTP, so Setu
cannot make the requests for a mail connector the way it does for Gmail
(proxy.py): whatever holds the IMAP connection must hold the password.
So this is the callback road's exception, said plainly. Two ways out,
both a pipe to one program:

* ``setu run mail:work`` starts the mail connector (``setu-mail``) with a
  private pipe, and answers ``{"op": "login"}`` on it for that one
  connection (helper.py);
* ``setu login mail:work --json`` prints the login for the program that
  started it -- Prahari, keeping a mailbox open -- and refuses when its
  output is a screen.

Nothing else gets it: ``token`` refuses a password connection, and a
connection of any other kind is refused by ``login``.
"""

from __future__ import annotations

import imaplib
import re
import ssl
from collections.abc import Callable
from typing import Any

#: How long signing in may take.
TIMEOUT = 30
HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
LOCAL = ("127.0.0.1", "localhost", "::1")


class MailError(Exception):
    """A mail account that cannot be added or opened, said in words."""


def check_settings(*, server: str, user: str, port: int, folder: str, tls: bool) -> None:
    if not server or not HOST_RE.match(server):
        raise MailError("the mail server is a name like imap.fastmail.com, not "
                        f"{server!r}")
    if not user or any(c.isspace() for c in user):
        raise MailError("the user is the address you sign in with")
    if not 1 <= int(port) <= 65535:
        raise MailError("the port is a number (993 for IMAP over TLS)")
    if not folder.strip():
        raise MailError("the folder is a mail folder's name (INBOX)")
    if not tls and server not in LOCAL:
        raise MailError("mail is opened over TLS: a password sent in plain text to "
                        "another computer is a password given away")


def open_imap(server: str, port: int, user: str, password: str, *, tls: bool = True,
              timeout: float = TIMEOUT) -> imaplib.IMAP4:
    """Signed in, nothing opened yet."""
    if tls:
        conn: imaplib.IMAP4 = imaplib.IMAP4_SSL(server, port, timeout=timeout,
                                                ssl_context=ssl.create_default_context())
    else:
        conn = imaplib.IMAP4(server, port, timeout=timeout)
    try:
        conn.login(user, password)
    except BaseException:
        close(conn)
        raise
    return conn


def try_login(login: dict[str, Any], opener: Callable[..., Any] | None = None) -> str:
    """Sign in and open the folder read-only, then let go; what the
    server said, in words. MailError when it refused."""
    opener = opener or open_imap
    try:
        conn = opener(login["server"], int(login["port"]), login["user"],
                      login["password"], tls=bool(login.get("tls", True)))
    except imaplib.IMAP4.error as exc:
        raise MailError(said(exc)) from None
    except (OSError, ssl.SSLError) as exc:
        raise MailError(f"could not reach {login['server']}:{login['port']}: "
                        f"{' '.join(str(exc).split()) or type(exc).__name__}") from None
    try:
        kind, answer = conn.select(quoted(login.get("folder") or "INBOX"), readonly=True)
        if kind != "OK":
            raise MailError(f"no folder {login.get('folder')!r} there: "
                            + " ".join(_text(a) for a in answer or []))
        count = _text((answer or [b"0"])[0])
    finally:
        close(conn)
    return f"opened {login.get('folder') or 'INBOX'} on {login['server']} as " \
           f"{login['user']} ({count} messages)"


def said(exc: BaseException) -> str:
    text = " ".join(str(exc).split())
    if "AUTHENTICATIONFAILED" in text.upper() or "LOGIN" in text.upper() \
            or "invalid credentials" in text.lower():
        return ("the mail server refused the user and password (for Gmail, iCloud and "
                "Outlook, use an app password from your account's security settings)")
    return text or type(exc).__name__


def quoted(folder: str) -> str:
    return '"' + folder.replace("\\", "\\\\").replace('"', '\\"') + '"'


def close(conn: Any) -> None:
    for step in (getattr(conn, "close", None), getattr(conn, "logout", None)):
        if step is None:
            continue
        try:
            step()
        except Exception:
            pass


def _text(value: Any) -> str:
    return value.decode(errors="replace") if isinstance(value, bytes) else str(value)
