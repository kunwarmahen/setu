"""Signing in to a server of your own that asks for it: MCP's own OAuth.

A server you bring (own.py) took a pasted token or none. Many remote
MCP servers have no token to paste. Their first answer is

    401, WWW-Authenticate: Bearer resource_metadata="https://…"

which is not a refusal but directions. MCP's authorization (2025-06-18)
points at four standards, and the walk between them is short:

1. the challenge names the server's *protected-resource metadata*
   (RFC 9728), which names the authorization server that guards it;
2. that server's own metadata (RFC 8414) says where to register, where
   to send the person, and where to collect tokens;
3. Setu registers itself there (RFC 7591, dynamic registration): a
   public client, no secret, no developer portal;
4. the person signs in on the server's own page, the way Google's and
   Home Assistant's sign-ins go: a browser here, or the link opened on
   another device with the address it ends on pasted back
   (``google.RedirectListener`` and ``google.Pasted``). PKCE (RFC 7636)
   ties the code to this sign-in, and ``resource`` (RFC 8707) names the
   one server the token is for;
5. the code becomes an access token and a refresh token.

THE REFRESH TOKEN STAYS IN SETU. It goes into the connection's vault
entry, beside the client id it is bound to and the token endpoint that
refreshes it. connections.py refreshes it when the access token is due,
and Setu's proxy adds the access token to each request. The harness, the
bridge, a container and a person's chat never see either one. A refresh
the server refuses marks the connection, as an expired Google sign-in
does, and ``setu check`` (Dvara's daily check) tries it.

NOT EVERY SERVER CAN BE SIGNED IN TO THIS WAY. One whose authorization
server offers no registration needs a client id from its own dashboard.
That is said in those words; nothing is guessed. A 401 that names no
metadata is a server that wants a pasted token (``--ask-token``).
"""

from __future__ import annotations

import re
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode, urljoin, urlparse

import httpx

from setu.google import SIGN_IN_TIMEOUT, Pasted, RedirectListener, make_pkce

#: The name Setu registers under; the server shows it on its consent page.
CLIENT_NAME = "Setu"
#: Refreshed this long before the server would call it expired.
EXPIRY_SKEW = 60.0
#: When the server says nothing about how long a token lasts.
DEFAULT_LIFETIME = 3600.0


class McpAuthError(Exception):
    """Anything between the 401 and a usable token."""

    def __init__(self, message: str, *, refused: bool = False) -> None:
        super().__init__(message)
        #: The server answered and said no (a revoked or expired grant),
        #: not "could not be reached", which may pass.
        self.refused = refused


def resource_metadata_url(challenge: str) -> str | None:
    """``resource_metadata="…"`` out of a WWW-Authenticate header, or None.
    Matched by name: the header opens with its scheme, the value is a URL
    that may hold ``=``, and other parameters may stand either side."""
    match = re.search(r'resource_metadata\s*=\s*(?:"([^"]*)"|([^\s,]+))', challenge or "",
                      re.IGNORECASE)
    if match is None:
        return None
    return match.group(1) if match.group(1) is not None else match.group(2)


def asked_scope(challenge: str) -> str | None:
    """``scope="…"`` from the challenge: what the server says a sign-in
    should ask for (Linear's and Notion's both name one). None: the
    scopes the server's details offer, as MCP's sign-in says, and with
    none offered either, nothing in particular, the server's default."""
    match = re.search(r'\bscope\s*=\s*"([^"]*)"', challenge or "", re.IGNORECASE)
    return match.group(1).strip() or None if match else None


def challenge(url: str, http: httpx.Client) -> str | None:
    """The server's WWW-Authenticate when it answers a first ``initialize``
    with 401 and says where its sign-in is; None when it doesn't ask, or
    asks for a token it doesn't say how to get."""
    hello = {"jsonrpc": "2.0", "id": 0, "method": "initialize",
             "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                        "clientInfo": {"name": "setu", "version": "1"}}}
    try:
        response = http.post(url, json=hello, timeout=15.0,
                             headers={"Accept": "application/json, text/event-stream"})
    except httpx.HTTPError:
        return None                     # own.py's own try says why
    if response.status_code != 401:
        return None
    said = response.headers.get("www-authenticate", "")
    return said if resource_metadata_url(said) else None


def _get_json(http: httpx.Client, url: str, what: str) -> dict[str, Any]:
    try:
        response = http.get(url, timeout=15.0)
    except httpx.HTTPError as exc:
        raise McpAuthError(f"cannot reach the {what} at {url}: {exc}") from None
    if response.status_code != 200:
        raise McpAuthError(f"the {what} at {url} answered HTTP {response.status_code}")
    try:
        data = response.json()
    except ValueError:
        raise McpAuthError(f"the {what} at {url} is not JSON") from None
    if not isinstance(data, dict):
        raise McpAuthError(f"the {what} at {url} is not an object")
    return data


def _metadata_urls(issuer: str) -> list[str]:
    """Where an issuer's metadata may be, in RFC 8414's order first: the
    ``.well-known`` part goes BEFORE the path, which servers in the wild
    don't all follow, so the other places are tried too."""
    parts = urlparse(issuer)
    root, path = f"{parts.scheme}://{parts.netloc}", parts.path.rstrip("/")
    found = [f"{root}/.well-known/oauth-authorization-server{path}",
             f"{root}/.well-known/openid-configuration{path}"]
    if path:
        found.append(urljoin(issuer + "/", ".well-known/oauth-authorization-server"))
    found.append(f"{root}/.well-known/oauth-authorization-server")
    return list(dict.fromkeys(found))


@dataclass(frozen=True)
class AuthServer:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    registration_endpoint: str | None
    revocation_endpoint: str | None
    resource: str
    #: What a sign-in asks for when the 401 names nothing: the server's own
    #: ``scopes_supported`` (Robinhood's sign-in wants its one scope named).
    scope: str | None = None


def discover(url: str, said: str, http: httpx.Client) -> AuthServer:
    """From the 401's WWW-Authenticate to the endpoints that sign in to it."""
    where = resource_metadata_url(said)
    if where is None:
        raise McpAuthError("the server asks for a sign-in but doesn't say where its "
                           "details are (no resource_metadata): give its token instead")
    meta = _get_json(http, where, "server's sign-in details")
    servers = meta.get("authorization_servers") or []
    if not servers:
        raise McpAuthError(f"{where} names no authorization server")
    issuer = str(servers[0])
    last: McpAuthError | None = None
    for candidate in _metadata_urls(issuer):
        try:
            auth = _get_json(http, candidate, "authorization server's details")
            break
        except McpAuthError as exc:
            last = exc
    else:
        raise McpAuthError(f"no details found for the authorization server {issuer} ({last})")
    for needed in ("authorization_endpoint", "token_endpoint"):
        if not auth.get(needed):
            raise McpAuthError(f"the authorization server {issuer} gives no {needed}")
    methods = auth.get("code_challenge_methods_supported")
    if methods and "S256" not in methods:
        raise McpAuthError(f"the authorization server {issuer} doesn't take PKCE's S256, "
                           "which a client with no secret needs")
    return AuthServer(issuer=str(auth.get("issuer") or issuer),
                      authorization_endpoint=str(auth["authorization_endpoint"]),
                      token_endpoint=str(auth["token_endpoint"]),
                      registration_endpoint=auth.get("registration_endpoint") or None,
                      revocation_endpoint=auth.get("revocation_endpoint") or None,
                      resource=str(meta.get("resource") or url),
                      scope=_offered_scope(meta) or _offered_scope(auth))


def _offered_scope(details: dict[str, Any]) -> str | None:
    offered = details.get("scopes_supported")
    if not isinstance(offered, list):
        return None
    return " ".join(str(s) for s in offered if str(s).strip()) or None


def register(server: AuthServer, redirect_uri: str, http: httpx.Client) -> str:
    """Dynamic registration: a public client for this one redirect."""
    if not server.registration_endpoint:
        raise McpAuthError(f"the authorization server {server.issuer} doesn't let a "
                           "program register itself, so its sign-in needs a client id from "
                           "its own dashboard; Setu can't make one up")
    body = {"client_name": CLIENT_NAME, "redirect_uris": [redirect_uri],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"], "token_endpoint_auth_method": "none"}
    try:
        response = http.post(server.registration_endpoint, json=body, timeout=20.0)
    except httpx.HTTPError as exc:
        raise McpAuthError(f"registering at {server.registration_endpoint} failed: "
                           f"{exc}") from None
    if response.status_code not in (200, 201):
        raise McpAuthError(f"registering was refused: HTTP {response.status_code} "
                           f"{response.text[:200]}")
    try:
        client_id = response.json().get("client_id")
    except (ValueError, AttributeError):
        client_id = None
    if not client_id:
        raise McpAuthError("registering gave no client id")
    return str(client_id)


def _token(endpoint: str, form: dict[str, str], http: httpx.Client, what: str) -> dict[str, Any]:
    try:
        response = http.post(endpoint, data=form, timeout=20.0,
                             headers={"Accept": "application/json"})
    except httpx.HTTPError as exc:
        raise McpAuthError(f"{what}: {endpoint} unreachable ({exc})") from None
    try:
        payload = response.json()
    except ValueError:
        payload = {}
    if response.status_code != 200:
        reason = (payload.get("error_description") or payload.get("error")
                  or response.text[:200]) if isinstance(payload, dict) else response.text[:200]
        raise McpAuthError(f"{what} refused: HTTP {response.status_code} {reason}",
                           refused=400 <= response.status_code < 500)
    if not isinstance(payload, dict) or not payload.get("access_token"):
        raise McpAuthError(f"{what}: no access_token in the answer")
    return payload


def _secret(server: AuthServer, client_id: str, payload: dict[str, Any],
            old_refresh: str = "") -> dict[str, Any]:  # fmt: skip
    """What the vault keeps: everything the next refresh needs."""
    lasts = float(payload.get("expires_in") or DEFAULT_LIFETIME)
    return {"kind": "oauth", "token": str(payload["access_token"]),
            "header": "Authorization",
            "refresh_token": str(payload.get("refresh_token") or old_refresh),
            "expires_at": time.time() + lasts, "client_id": client_id,
            "issuer": server.issuer, "token_endpoint": server.token_endpoint,
            "authorization_endpoint": server.authorization_endpoint,
            "registration_endpoint": server.registration_endpoint,
            "revocation_endpoint": server.revocation_endpoint,
            "resource": server.resource}


def sign_in(url: str, said: str, *, http: httpx.Client,
            open_browser: Callable[[str], Any] | None = None,
            on_url: Callable[[str], Any] | None = None,
            timeout: float = SIGN_IN_TIMEOUT,
            pasted: Pasted | None = None) -> dict[str, Any]:  # fmt: skip
    """The whole walk (module docstring); the secret the vault keeps."""
    server = discover(url, said, http)
    listener = RedirectListener(pasted=pasted)
    try:
        client_id = register(server, listener.redirect_uri, http)
        verifier, code_challenge = make_pkce()
        state = secrets.token_urlsafe(24)
        address = server.authorization_endpoint + ("&" if "?" in
                                                   server.authorization_endpoint else "?")
        params = {"response_type": "code", "client_id": client_id,
                  "redirect_uri": listener.redirect_uri, "state": state,
                  "code_challenge": code_challenge, "code_challenge_method": "S256",
                  "resource": server.resource}
        scope = asked_scope(said) or server.scope
        if scope:
            params["scope"] = scope
        address += urlencode(params)
        if on_url is not None:
            on_url(address)
        if open_browser is not None:
            threading.Thread(target=open_browser, args=(address,), daemon=True).start()
        try:
            code = listener.wait(state, timeout=timeout)
        except Exception as exc:          # the listener speaks Google's error type
            raise McpAuthError(str(exc)) from None
        payload = _token(server.token_endpoint, {
            "grant_type": "authorization_code", "code": code, "client_id": client_id,
            "redirect_uri": listener.redirect_uri, "code_verifier": verifier,
            "resource": server.resource}, http, "the sign-in")
        return _secret(server, client_id, payload)
    finally:
        listener.close()


def due(secret: dict[str, Any]) -> bool:
    return time.time() >= float(secret.get("expires_at") or 0) - EXPIRY_SKEW


def refresh(secret: dict[str, Any], http: httpx.Client) -> dict[str, Any]:
    """A new access token from the refresh token; the secret, updated. A
    server that rotates refresh tokens sends a new one, which is kept."""
    if not secret.get("refresh_token"):
        raise McpAuthError("the server gave no refresh token, so its sign-in can't be "
                           "renewed: sign in again", refused=True)
    payload = _token(secret["token_endpoint"], {
        "grant_type": "refresh_token", "refresh_token": secret["refresh_token"],
        "client_id": secret["client_id"], "resource": secret.get("resource") or ""},
        http, "the refresh")
    server = AuthServer(issuer=secret.get("issuer") or "",
                        authorization_endpoint=secret.get("authorization_endpoint") or "",
                        token_endpoint=secret["token_endpoint"],
                        registration_endpoint=secret.get("registration_endpoint"),
                        revocation_endpoint=secret.get("revocation_endpoint"),
                        resource=secret.get("resource") or "")
    return _secret(server, secret["client_id"], payload, secret["refresh_token"])


def revoke(secret: dict[str, Any], http: httpx.Client) -> bool:
    """RFC 7009, where the server offers it: True when it was reached."""
    endpoint = secret.get("revocation_endpoint")
    token = secret.get("refresh_token") or secret.get("token")
    if not endpoint or not token:
        return False
    try:
        response = http.post(endpoint, data={"token": token, "client_id":
                                             secret.get("client_id") or ""}, timeout=20.0)
    except httpx.HTTPError:
        return False
    return response.status_code == 200
