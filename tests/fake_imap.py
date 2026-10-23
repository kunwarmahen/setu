"""A mail server, small and plain, on a local socket: enough IMAP for
Python's imaplib -- LOGIN, EXAMINE, LIST, UID SEARCH, UID FETCH of
headers and whole messages -- and a record of every command, so a test
can say what was NEVER sent (a STORE that marks mail read, a SELECT that
opens the folder for writing)."""

from __future__ import annotations

import re
import socketserver
import threading


def message(sender: str, subject: str, body: str, *,
            date: str = "Thu, 22 Oct 2026 09:00:00 +0000", html: bool = False) -> bytes:
    kind = "text/html" if html else "text/plain"
    return (f"From: {sender}\r\nTo: me@example.com\r\nSubject: {subject}\r\nDate: {date}\r\n"
            f"Message-ID: <{abs(hash(subject))}@mail.example>\r\n"
            f"Content-Type: {kind}; charset=utf-8\r\n\r\n{body}\r\n").encode()


class FakeImap:
    def __init__(self, password: str = "app-password") -> None:
        self.password = password
        #: uid -> (raw message, seen)
        self.mail: dict[int, tuple[bytes, bool]] = {}
        self.commands: list[str] = []
        self.lock = threading.Lock()
        fake = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                fake.serve(self)

        self.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def deliver(self, raw: bytes, seen: bool = False) -> int:
        with self.lock:
            uid = max(self.mail, default=0) + 1
            self.mail[uid] = (raw, seen)
        return uid

    def serve(self, conn) -> None:
        out = conn.wfile

        def say(line: str) -> None:
            out.write(line.encode() + b"\r\n")
            out.flush()

        say("* OK [CAPABILITY IMAP4rev1 IDLE] fake ready")
        while True:
            raw = conn.rfile.readline()
            if not raw:
                return
            line = raw.decode().rstrip("\r\n")
            tag, _, rest = line.partition(" ")
            verb = rest.split(" ", 1)[0].upper()
            self.commands.append(rest.upper())
            if verb == "CAPABILITY":
                say("* CAPABILITY IMAP4rev1 IDLE")
                say(f"{tag} OK done")
            elif verb == "LOGIN":
                say(f"{tag} OK signed in" if self.password in rest
                    else f"{tag} NO [AUTHENTICATIONFAILED] Invalid credentials")
            elif verb in ("EXAMINE", "SELECT"):
                if '"INBOX"' not in rest.upper() and "INBOX" not in rest.upper():
                    say(f"{tag} NO no such folder")
                    continue
                say(f"* {len(self.mail)} EXISTS")
                say("* OK [UIDVALIDITY 7] ok")
                say(f"* OK [UIDNEXT {max(self.mail, default=0) + 1}] ok")
                say(f"{tag} OK [READ-ONLY] opened")
            elif verb == "LIST":
                say('* LIST (\\HasNoChildren) "/" "INBOX"')
                say('* LIST (\\HasNoChildren) "/" "Receipts"')
                say(f"{tag} OK listed")
            elif verb == "UID" and " SEARCH " in f" {rest.upper()} ":
                found = [u for u, (m, seen) in sorted(self.mail.items())
                         if self._matches(rest, m, seen)]
                say("* SEARCH " + " ".join(map(str, found)))
                say(f"{tag} OK searched")
            elif verb == "UID" and " FETCH " in rest.upper():
                wanted = re.search(r"FETCH ([\d,:*]+) ", rest, re.I).group(1)
                uids = [int(u) for u in wanted.split(",") if u.isdigit()]
                whole = "BODY.PEEK[]" in rest.upper()
                for seq, uid in enumerate(uids, 1):
                    if uid not in self.mail:
                        continue
                    raw_mail, seen = self.mail[uid]
                    data = raw_mail if whole else raw_mail.split(b"\r\n\r\n")[0] + b"\r\n\r\n"
                    flags = "\\Seen" if seen else ""
                    part = ("BODY[]" if whole else
                            "BODY[HEADER.FIELDS (FROM TO SUBJECT DATE MESSAGE-ID)]")
                    out.write(f"* {seq} FETCH (UID {uid} FLAGS ({flags}) {part} {{{len(data)}}}\r\n"
                              .encode())
                    out.write(data + b")\r\n")
                out.flush()
                say(f"{tag} OK fetched")
            elif verb in ("NOOP", "CLOSE"):
                say(f"{tag} OK done")
            elif verb == "LOGOUT":
                say("* BYE")
                say(f"{tag} OK bye")
                return
            else:
                say(f"{tag} BAD unknown")

    @staticmethod
    def _matches(rest: str, raw: bytes, seen: bool) -> bool:
        text = raw.decode(errors="replace").lower()
        head = text.split("\r\n\r\n")[0]
        for key, value in re.findall(r'(FROM|SUBJECT|TEXT) "([^"]*)"', rest, re.I):
            where = {"from": head.split("from:", 1)[-1].split("\r\n")[0],
                     "subject": head.split("subject:", 1)[-1].split("\r\n")[0],
                     "text": text}[key.lower()]
            if value.lower() not in where:
                return False
        return not ("UNSEEN" in rest.upper() and seen)
