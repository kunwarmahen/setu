"""Sites a person reaches only through the website, as Setu connectors.

Amazon has no API that sees a shopper's own orders; X's API costs money
to read. For both, the connection is a browser profile the person signs
in to by hand (``setu connect amazon``), and each manifest here says how
a harness keeps to the site on it: which hosts, which pages and buttons
are the person's alone (buying, paying, deleting), how slowly to go.

No code: the harness drives the profile with its own browser tools.
"""

from pathlib import Path

#: The entry points ``setu.connectors:amazon`` and ``setu.connectors:x``.
AMAZON = str(Path(__file__).with_name("amazon.toml"))
X = str(Path(__file__).with_name("x.toml"))
