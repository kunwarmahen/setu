"""Setu -- sign in to a site once; the agents you allow can use it.

Setu (सेतु) is a bridge between a person's accounts and the agents that
work for them. Three promises shape every module here:

* **The key never reaches the model.** Tokens rest in the vault; a
  connector asks for one over a private pipe and receives an access
  token for its own connection only (helper.py, client.py).
* **Access is chosen in words and enforced by the site.** A person picks
  "Read only"; Google is asked for ``gmail.readonly`` and nothing else,
  so the limit holds whatever any code does (manifest.py, google.py).
* **Everything stays on the person's computer.** No Setu server sees a
  token, a message or an order.
"""

from setu.client import NoToken, granted_scopes, http

__all__ = ["NoToken", "granted_scopes", "http"]
__version__ = "0.1.0"
