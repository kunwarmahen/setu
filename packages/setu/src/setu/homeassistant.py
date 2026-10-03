"""Signing in to a Home Assistant: the person's own server, two ways.

Home Assistant is not a cloud with one address. Each person runs their
own (``http://homeassistant.local:8123``), so every connection carries
its server's URL, and nothing is registered with anyone in advance.

THE LOGIN PAGE, BY DEFAULT. Home Assistant speaks IndieAuth: the client
id is simply the address of the program asking, and a redirect to the
same host and port is accepted without registration. So Setu listens on
``http://127.0.0.1:<port>/``, names that as both client id and redirect,
and opens the server's own login page. The person signs in there, with
their own password and second factor, and never types either into Setu.
Back come a 30-minute access token and a refresh token, which shows in
the person's Home Assistant profile under its client id and can be
removed there -- or revoked from here on disconnect.

THE REFRESH NEEDS THE SAME CLIENT ID. A refresh token is bound to the
client id that earned it, and the port was random, so the client id is
stored beside the refresh token (it is not a secret; the refresh token
is).

A PASTED TOKEN, FOR A MACHINE WITH NO BROWSER. A long-lived access
token, made in the profile page, works too. It lasts ten years, cannot
be refreshed or revoked from outside, and is checked once against the
server before it is kept. Disconnecting deletes it here and says to
delete it in the profile as well.

NEITHER IS SMALLER THAN THE USER. A Home Assistant token holds every
right of the user who made it. The levels Setu offers are kept by the
connector (it offers only that level's tools), not by the server -- so
the honest advice, repeated where people choose, is a Home Assistant
user of its own for the assistant, without admin rights.
"""

from __future__ import annotations

import secrets
import threading
import webbrowser
from collections.abc import Callable
from typing import Any
from urllib.parse import urlencode, urlparse

import httpx

from setu.google import SIGN_IN_TIMEOUT, RedirectListener


class HomeAssistantError(Exception):
    """Anything between "which server?" and a usable token."""


def normalise_url(url: str) -> str:
    """``homeassistant.local:8123/`` -> ``http://homeassistant.local:8123``.
    Refuses what cannot be a server address rather than guessing."""
    url = (url or "").strip().rstrip("/")
    if not url:
        raise HomeAssistantError("no Home Assistant address given")
    if "://" not in url:
        url = "http://" + url
    parts = urlparse(url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise HomeAssistantError(f"{url!r} is not a Home Assistant address "
                                 "(like http://homeassistant.local:8123)")
    if parts.path or parts.query:
        raise HomeAssistantError(f"{url!r}: give the server's address only, "
                                 "without a path")
    return f"{parts.scheme}://{parts.netloc}"


def authorization_url(base: str, *, client_id: str, redirect_uri: str, state: str) -> str:
    params = {"response_type": "code", "client_id": client_id,
              "redirect_uri": redirect_uri, "state": state}
    return f"{base}/auth/authorize?{urlencode(params)}"


def _post(http: httpx.Client, url: str, form: dict[str, str], what: str) -> dict[str, Any]:
    try:
        response = http.post(url, data=form, timeout=30.0)
    except httpx.HTTPError as exc:
        raise HomeAssistantError(f"{what}: {url} unreachable ({exc})") from None
    try:
        payload = response.json()
    except ValueError:
        payload = {}
    if response.status_code != 200:
        reason = (payload.get("error_description") or payload.get("error")
                  or response.text[:200])
        raise HomeAssistantError(f"{what} refused: HTTP {response.status_code} {reason}")
    if not payload.get("access_token"):
        raise HomeAssistantError(f"{what}: no access_token in the answer")
    return payload


def sign_in(base: str, *, http: httpx.Client,
            open_browser: Callable[[str], Any] | None = webbrowser.open,
            on_url: Callable[[str], Any] | None = None,
            timeout: float = SIGN_IN_TIMEOUT) -> dict[str, Any]:
    """Login page -> code -> tokens. Returns the token answer plus the
    ``client_id`` the refresh will need."""
    listener = RedirectListener()
    try:
        client_id = listener.redirect_uri
        state = secrets.token_urlsafe(24)
        url = authorization_url(base, client_id=client_id,
                                redirect_uri=listener.redirect_uri, state=state)
        if on_url is not None:
            on_url(url)
        if open_browser is not None:
            threading.Thread(target=open_browser, args=(url,), daemon=True).start()
        try:
            code = listener.wait(state, timeout=timeout)
        except Exception as exc:          # the listener speaks Google's error type
            raise HomeAssistantError(str(exc)) from None
        payload = _post(http, f"{base}/auth/token", {
            "grant_type": "authorization_code", "code": code, "client_id": client_id,
        }, "sign-in")
        return {**payload, "client_id": client_id}
    finally:
        listener.close()


def refresh(base: str, client_id: str, refresh_token: str, *,
            http: httpx.Client) -> dict[str, Any]:
    return _post(http, f"{base}/auth/token", {
        "grant_type": "refresh_token", "refresh_token": refresh_token,
        "client_id": client_id,
    }, "refresh")


def revoke(base: str, refresh_token: str, *, http: httpx.Client) -> bool:
    """Ask the server to forget a refresh token. It answers 200 whatever
    the token was, so True means only that the server was reached."""
    try:
        response = http.post(f"{base}/auth/revoke", data={"token": refresh_token},
                             timeout=30.0)
    except httpx.HTTPError:
        return False
    return response.status_code == 200


def whoami(base: str, access_token: str, *, http: httpx.Client) -> dict[str, Any]:
    """The server's own config -- its name and version -- which also
    proves the token works. Raises when it does not."""
    try:
        response = http.get(f"{base}/api/config", timeout=30.0,
                            headers={"Authorization": f"Bearer {access_token}"})
    except httpx.HTTPError as exc:
        raise HomeAssistantError(f"{base} unreachable ({exc})") from None
    if response.status_code == 401:
        raise HomeAssistantError(f"{base} refused the token (401): it may be mistyped, "
                                 "or deleted in your Home Assistant profile")
    if response.status_code != 200:
        raise HomeAssistantError(f"{base}/api/config answered HTTP {response.status_code}")
    try:
        data = response.json()
    except ValueError:
        raise HomeAssistantError(f"{base} is not a Home Assistant (no JSON config)") from None
    return data if isinstance(data, dict) else {}


def label(base: str, config: dict[str, Any]) -> str:
    """What a person recognises a server by: ``Home (homeassistant.local:8123)``."""
    host = urlparse(base).netloc
    name = str(config.get("location_name") or "").strip()
    return f"{name} ({host})" if name else host
