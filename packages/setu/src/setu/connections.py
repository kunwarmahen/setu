"""A connection: one person's account on one site, at one level of access.

Named ``<connector>:<account>`` -- ``gmail:personal``, ``gmail:work`` --
because one site can hold several accounts, and the account name is the
person's word for it, not an address. The address is recorded too (the
provider is asked who the token belongs to), so "which Gmail?" always
has an answer a person recognises.

WHAT WAS GRANTED WINS OVER WHAT WAS ASKED. The consent screen lets a
person untick boxes. The level a connection records is the richest one
whose scopes all came back -- never the one requested -- and a sign-in
that did not even grant the least level is refused and revoked on the
spot, rather than stored as a connection that can do nothing.

ONE GRANT PER APP PER ACCOUNT, AND REVOKING ANY TOKEN ENDS ALL OF IT.
That is Google's rule, and it decides every revoke below. Signing in
again with the same client and the same Google account -- to change a
level -- does not make a second grant; it updates the one there is, and
revoking the "old" refresh token would sign out the new one with it. So
a token is revoked only when no connection still stands on its grant.

RECONNECTING REPLACES. The new sign-in is stored first. If the name now
points at a DIFFERENT account (or client), the grant it replaced is
revoked after, so a failure in between leaves a working connection,
never none. A sign-in that is refused (too little granted, no refresh
token) is given back the same way -- unless a stored connection shares
its grant, which revoking would break.

DISCONNECTING REVOKES FIRST. Deleting the local copy alone would leave a
live grant on Google's side -- the account's "third-party access" page
would still list it. The revoke is attempted, reported, and the entry
deleted either way: a person who asked to disconnect is disconnected
here even when Google cannot be reached, and is told to check there.
The one exception is the rule above: the same account connected under a
second name keeps the grant alive, and the person is told why.

HOME ASSISTANT IS ITS OWN SERVER. Its connections carry the server's
address (``base_url``) and an ``auth`` of ``homeassistant``; the token is
either a login-page sign-in (refreshed and revoked like Google's, but
against that server) or a pasted long-lived token, which is neither.
Every sign-in there has its own refresh token, so the shared-grant rule
above does not arise: a replaced one is simply revoked. Levels are the
one chosen -- the server has no scopes to grant fewer
(homeassistant.py).
"""

from __future__ import annotations

import time
import webbrowser
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx

from setu import google, homeassistant
from setu.manifest import Manifest
from setu.vault import Vault

#: Refresh this long before Google would call a token expired.
EXPIRY_SKEW = 60


class ConnectionFailed(Exception):
    """A connection that cannot do what was asked of it."""


def ref_for(connector: str, account: str) -> str:
    if not account or ":" in account or account.strip() != account:
        raise ConnectionFailed(f"account name {account!r} must be a plain word "
                               "(personal, work, shop...)")
    return f"{connector}:{account}"


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True, slots=True)
class Token:
    access_token: str
    expires_at: float
    scopes: tuple[str, ...]
    account: str
    email: str
    level: str = ""


def public(entry: dict[str, Any]) -> dict[str, Any]:
    """The entry with its secrets removed -- what `setu list` may show."""
    return {key: value for key, value in entry.items() if key != "secret"}


def connect(manifest: Manifest, account: str, *, level: str | None,
            client: google.Client, vault: Vault, http: httpx.Client,
            open_browser: Callable[[str], Any] | None = webbrowser.open,
            on_url: Callable[[str], Any] | None = None,
            timeout: float = google.SIGN_IN_TIMEOUT) -> dict[str, Any]:
    if manifest.auth != "google":
        raise ConnectionFailed(f"{manifest.id} signs in with {manifest.auth!r}, "
                               "which this Setu does not know yet")
    ref = ref_for(manifest.id, account)
    asked = manifest.level(level)
    payload = google.sign_in(client, asked.scopes, http=http, open_browser=open_browser,
                             on_url=on_url, timeout=timeout)
    got = google.granted(payload)
    held = manifest.level_for_scopes(got)
    if held is None:
        _discard(payload, client, vault, http)
        raise ConnectionFailed(
            f"Google granted {sorted(got) or 'nothing'}, which is less than "
            f"{manifest.name}'s least level ({manifest.default_level.label}) needs. "
            "Nothing was saved; sign in again and leave its box ticked.")
    if not payload.get("refresh_token"):
        _discard(payload, client, vault, http)
        raise ConnectionFailed("Google sent no refresh token, so the connection "
                               "would die within the hour. Nothing was saved.")
    email = _who(manifest, payload["access_token"], http)
    previous = vault.get(ref)
    entry = {
        "connector": manifest.id,
        "account": account,
        "email": email,
        "level": held.name,
        "asked_level": asked.name,
        "scopes": sorted(got),
        "created": _now(),
        "last_used": None,
        "secret": {
            "client_id": client.client_id,
            "client_secret": client.client_secret,
            "token_url": client.token_url,
            "refresh_token": payload["refresh_token"],
            "access_token": payload["access_token"],
            "expires_at": time.time() + float(payload.get("expires_in", 3600)),
        },
    }
    vault.put(ref, entry)
    if previous and not _same_grant(previous, client.client_id, email):
        # A different Google account (or client) under the same name: the
        # old grant is its own -- revoked unless yet another connection
        # still stands on it.
        old = previous["secret"]
        if not _grant_in_use(vault, old["client_id"], previous.get("email", ""), skip=ref):
            google.revoke(old["refresh_token"], http=http)
    return entry


def connect_homeassistant(manifest: Manifest, account: str, *, level: str | None,
                          base_url: str, vault: Vault, http: httpx.Client,
                          long_lived: str | None = None,
                          open_browser: Callable[[str], Any] | None = webbrowser.open,
                          on_url: Callable[[str], Any] | None = None,
                          timeout: float = google.SIGN_IN_TIMEOUT) -> dict[str, Any]:
    """Sign in to a Home Assistant at ``base_url``: its login page, or a
    pasted ``long_lived`` token, checked against the server first."""
    if manifest.auth != "homeassistant":
        raise ConnectionFailed(f"{manifest.id} does not sign in to Home Assistant")
    ref = ref_for(manifest.id, account)
    asked = manifest.level(level)
    base = homeassistant.normalise_url(base_url)
    if long_lived:
        config = homeassistant.whoami(base, long_lived.strip(), http=http)
        secret: dict[str, Any] = {"kind": "long_lived", "access_token": long_lived.strip()}
    else:
        payload = homeassistant.sign_in(base, http=http, open_browser=open_browser,
                                        on_url=on_url, timeout=timeout)
        if not payload.get("refresh_token"):
            raise ConnectionFailed(f"{base} sent no refresh token, so the connection "
                                   "would die within the hour. Nothing was saved.")
        try:
            config = homeassistant.whoami(base, payload["access_token"], http=http)
        except homeassistant.HomeAssistantError:
            homeassistant.revoke(base, payload["refresh_token"], http=http)
            raise
        secret = {"kind": "oauth", "client_id": payload["client_id"],
                  "refresh_token": payload["refresh_token"],
                  "access_token": payload["access_token"],
                  "expires_at": time.time() + float(payload.get("expires_in", 1800))}
    previous = vault.get(ref)
    entry = {
        "connector": manifest.id,
        "account": account,
        "auth": "homeassistant",
        "base_url": base,
        "email": homeassistant.label(base, config),
        "level": asked.name,
        "asked_level": asked.name,
        "scopes": [],
        "created": _now(),
        "last_used": None,
        "secret": secret,
    }
    vault.put(ref, entry)
    if previous and previous.get("auth") == "homeassistant":
        old = previous.get("secret") or {}
        if old.get("kind") == "oauth" and old.get("refresh_token") != secret.get("refresh_token"):
            homeassistant.revoke(previous["base_url"], old["refresh_token"], http=http)
    return entry


def _same_grant(entry: dict[str, Any], client_id: str, email: str) -> bool:
    """Whether ``entry`` rides on the grant (client, Google account) given.

    Google keeps ONE grant per app per account, and revoking any token of
    it revokes all of it -- the newest refresh token included. So a token
    is never revoked while another connection shares its grant: that
    would sign out the connection the person just made.
    """
    return (entry.get("secret", {}).get("client_id") == client_id
            and bool(email) and entry.get("email") == email)


def _grant_in_use(vault: Vault, client_id: str, email: str = "",
                  skip: str | None = None) -> bool:
    """Any OTHER connection on this client -- for this account when the
    account is known, for any account when it is not (the cautious
    answer: a grant we cannot place is a grant we do not revoke)."""
    for ref in vault.list():
        if ref == skip:
            continue
        entry = vault.get(ref) or {}
        if entry.get("secret", {}).get("client_id") != client_id:
            continue
        if not email or not entry.get("email") or entry.get("email") == email:
            return True
    return False


def _discard(payload: dict[str, Any], client: google.Client, vault: Vault,
             http: httpx.Client) -> None:
    """Give back a sign-in we will not keep -- unless its grant is one a
    stored connection still stands on, which revoking would sign out."""
    if not _grant_in_use(vault, client.client_id):
        google.revoke(payload.get("refresh_token") or payload["access_token"], http=http)


def _who(manifest: Manifest, access_token: str, http: httpx.Client) -> str:
    if manifest.whoami is None:
        return ""
    try:
        response = http.get(manifest.whoami.url, timeout=30.0,
                            headers={"Authorization": f"Bearer {access_token}"})
        response.raise_for_status()
        return str(response.json().get(manifest.whoami.field, ""))
    except (httpx.HTTPError, ValueError):
        return ""   # the connection works; only its label is missing


def token(ref: str, *, vault: Vault, http: httpx.Client, force: bool = False) -> Token:
    """A live access token for ``ref``, refreshed when it is due."""
    entry = vault.get(ref)
    if entry is None:
        raise ConnectionFailed(f"no connection {ref!r}; run `setu connect "
                               f"{ref.split(':')[0]} --as {ref.partition(':')[2] or 'personal'}`")
    secret = entry["secret"]
    if entry.get("auth") == "homeassistant":
        return _ha_token(ref, entry, vault=vault, http=http, force=force)
    if force or time.time() >= float(secret.get("expires_at", 0)) - EXPIRY_SKEW:
        client = google.Client(client_id=secret["client_id"],
                               client_secret=secret["client_secret"],
                               token_url=secret.get("token_url", google.TOKEN_URL))
        try:
            payload = google.refresh(client, secret["refresh_token"], http=http)
        except google.GoogleAuthError as exc:
            raise ConnectionFailed(
                f"{ref} could not refresh ({exc}). Google may have expired it -- "
                "apps in Testing mode lose their sign-in after 7 days -- run "
                f"`setu connect {entry['connector']} --as {entry['account']}` again") from None
        secret["access_token"] = payload["access_token"]
        secret["expires_at"] = time.time() + float(payload.get("expires_in", 3600))
        if payload.get("refresh_token"):
            secret["refresh_token"] = payload["refresh_token"]   # rotation
    entry["secret"] = secret
    entry["last_used"] = _now()
    vault.put(ref, entry)
    return Token(access_token=secret["access_token"], expires_at=float(secret["expires_at"]),
                 scopes=tuple(entry.get("scopes", ())), account=entry["account"],
                 email=entry.get("email", ""), level=entry.get("level", ""))


#: What a long-lived token's expiry is reported as: far enough away that
#: nobody asks for a new one, and still a number JSON can carry.
NEVER = 4102444800.0     # 2100-01-01


def _ha_token(ref: str, entry: dict[str, Any], *, vault: Vault, http: httpx.Client,
              force: bool) -> Token:
    secret, base = entry["secret"], entry["base_url"]
    if secret.get("kind") == "long_lived":
        if force:
            raise ConnectionFailed(
                f"{ref}: {base} refused its long-lived token, which cannot be refreshed. "
                f"It may have been deleted in your profile; run `setu connect "
                f"{entry['connector']} --as {entry['account']}` again")
        expires = NEVER
    else:
        if force or time.time() >= float(secret.get("expires_at", 0)) - EXPIRY_SKEW:
            try:
                payload = homeassistant.refresh(base, secret["client_id"],
                                                secret["refresh_token"], http=http)
            except homeassistant.HomeAssistantError as exc:
                raise ConnectionFailed(
                    f"{ref} could not refresh ({exc}). Its sign-in may have been removed "
                    f"in your Home Assistant profile; run `setu connect "
                    f"{entry['connector']} --as {entry['account']}` again") from None
            secret["access_token"] = payload["access_token"]
            secret["expires_at"] = time.time() + float(payload.get("expires_in", 1800))
        expires = float(secret["expires_at"])
    entry["secret"] = secret
    entry["last_used"] = _now()
    vault.put(ref, entry)
    return Token(access_token=secret["access_token"], expires_at=expires, scopes=(),
                 account=entry["account"], email=entry.get("email", ""),
                 level=entry.get("level", ""))


def disconnect(ref: str, *, vault: Vault, http: httpx.Client) -> tuple[bool, bool | None]:
    """(was connected, revoked at Google). The second is None when the
    grant was deliberately KEPT because another connection -- the same
    Google account under a second name -- still stands on it."""
    entry = vault.get(ref)
    if entry is None:
        return False, False
    secret = entry["secret"]
    if entry.get("auth") == "homeassistant":
        # a pasted token cannot be revoked from outside: False, and the
        # caller says to delete it in the profile
        revoked = (secret.get("kind") == "oauth"
                   and homeassistant.revoke(entry["base_url"], secret["refresh_token"],
                                            http=http))
        vault.delete(ref)
        return True, revoked
    if _grant_in_use(vault, secret["client_id"], entry.get("email", ""), skip=ref):
        vault.delete(ref)
        return True, None
    revoked = google.revoke(secret["refresh_token"], http=http)
    vault.delete(ref)
    return True, revoked
