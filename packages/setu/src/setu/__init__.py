"""Setu -- sign in to a site once; the agents you allow can use it.

Setu (सेतु) is a bridge between a person's accounts and the agents that
work for them. Three promises shape every module here:

* **The key never reaches the model, nor the connector.** Tokens rest
  in the vault; a connector runs with no network and asks Setu to make
  each request, which Setu checks against the level, signs and sends to
  the connector's own site (proxy.py, sandbox.py, client.py).
* **Access is chosen in words and enforced by the site.** A person picks
  "Read only"; Google is asked for ``gmail.readonly`` and nothing else,
  so the limit holds whatever any code does (manifest.py, google.py).
  Where a site has no scopes (Home Assistant), the connector holds the
  level, and the levels say so (homeassistant.py).
* **Everything stays on the person's computer.** No Setu server sees a
  token, a message or an order.
"""

from setu.client import NoToken, granted_level, granted_scopes, http

__all__ = ["NoToken", "granted_level", "granted_scopes", "http"]
__version__ = "0.1.0"
