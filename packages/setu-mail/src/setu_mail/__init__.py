"""Mail by IMAP for Setu: any mail service, read only.

Gmail has its own connector, signed in with Google. This one is for
everything else that speaks IMAP -- Fastmail, iCloud, Outlook, a server
of your own -- and for a Gmail account kept by an app password, which is
what a program holding a mailbox open (Prahari) needs.
"""

from pathlib import Path

#: The entry point ``setu.connectors:mail`` resolves to this path.
MANIFEST = str(Path(__file__).with_name("manifest.toml"))
