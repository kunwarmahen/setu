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

A BROWSER ROAD HOLDS NO TOKEN. Its connection is a profile directory the
person signed in to by hand (browser.py); the entry records where it is,
which browser wrote it, and the store it signed in to. There is nothing
to refresh, and ``token`` refuses it. Disconnecting deletes the profile
-- the sign-in is gone from this computer; the site may still list the
device until the person signs it out there.

A PHONE ROAD HOLDS NOTHING AT ALL. The sign-in is the site's own app,
on the person's phone (``connect_phone``). The entry records which app
and the level, so a harness working the phone knows what it may do
there; there is no token, no profile, and nothing to revoke from here.
Disconnecting deletes the entry; the app stays signed in on the phone.

A SITE SETU WROTE THE RULES FOR is proved by its page (``connect_site``):
nobody named its sign-in cookies, so after the window the start page is
looked at once more, and a page that still shows a sign-in saves
nothing. A page that says neither is the person's to answer -- they
have just closed the window -- and with nobody to ask, nothing is saved.
The manifest is written only after that, so a failed sign-in leaves no
site behind, and no profile either.
"""

from __future__ import annotations

import re
import shutil
import tempfile
import time
import webbrowser
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from setu import browser as site_browser
from setu import google, homeassistant, sites
from setu.manifest import Manifest, installed, parse
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


def last_used(entry: dict[str, Any]) -> str | None:
    """When the connection was last used: a token's refresh stamps it, and
    a browser profile says so itself (browser.last_active)."""
    if entry.get("auth") == "browser" and entry.get("profile"):
        return site_browser.last_active(Path(entry["profile"]), entry.get("created", ""))
    return entry.get("last_used")


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
            timeout: float = google.SIGN_IN_TIMEOUT,
            pasted: google.Pasted | None = None) -> dict[str, Any]:
    if manifest.auth != "google":
        raise ConnectionFailed(f"{manifest.id} signs in with {manifest.auth!r}, "
                               "which this Setu does not know yet")
    ref = ref_for(manifest.id, account)
    asked = manifest.level(level)
    payload = google.sign_in(client, asked.scopes, http=http, open_browser=open_browser,
                             on_url=on_url, timeout=timeout, pasted=pasted)
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
                          timeout: float = google.SIGN_IN_TIMEOUT,
                          pasted: google.Pasted | None = None) -> dict[str, Any]:
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
                                        on_url=on_url, timeout=timeout, pasted=pasted)
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


def connect_browser(manifest: Manifest, account: str, *, level: str | None, vault: Vault,
                    browser: str, on_window: Callable[[Path], Any] | None = None,
                    window: Callable[..., Any] = site_browser.window,
                    ask: Callable[[str], bool] | None = None,
                    dump: Callable[..., str] = site_browser.dump_dom,
                    fresh: bool = False) -> dict[str, Any]:
    """Sign in to a browser-road site: a window of ``browser`` on the
    connection's own profile, kept only when a sign-in cookie is there --
    or, for a site Setu wrote the rules for, when its page says so.

    ``fresh``: sign in on an empty profile beside the old one, and put it
    in the old one's place only once the sign-in is good. A site marks a
    browser it distrusts by a cookie in the profile, and the mark outlives
    the sign-in: X refused every streamed sign-in on a profile that had
    failed before, and let the same window, the same person, through on
    an empty one. A sign-in that fails leaves the old profile as it was."""
    spec = manifest.browser
    if manifest.auth != "browser" or spec is None:
        raise ConnectionFailed(f"{manifest.id} is not signed in to in a browser")
    asked = manifest.level(level)
    profile = site_browser.profile_dir(ref_for(manifest.id, account))
    work = profile.with_name(profile.name + FRESH) if fresh and profile.exists() else profile
    if work != profile:
        shutil.rmtree(work, ignore_errors=True)        # an earlier try's, never finished
    try:
        if on_window is not None:
            on_window(work)
        try:
            window(browser, work, spec.login_url)
        except site_browser.BrowserSignInFailed as exc:
            raise ConnectionFailed(str(exc)) from None
        if manifest.generated:
            _prove_by_page(manifest, browser, work, ask, dump)
            hosts = list(manifest.hosts[:1])
        else:
            hosts = site_browser.signed_in(work, spec.signed_in, manifest.hosts)
        if not hosts:
            raise ConnectionFailed(
                f"the window closed, but {manifest.name} has not signed you in there "
                f"(none of {', '.join(spec.signed_in)} is set). Nothing was saved; run it "
                "again and close the window only after signing in")
    except BaseException:
        if work != profile:
            shutil.rmtree(work, ignore_errors=True)
        raise
    if work != profile:
        _replace(profile, work)
    return _save_browser(manifest, account, asked.name, profile, browser, hosts, vault)


#: Beside a connection's profile while a fresh sign-in is made in it.
FRESH = ".fresh"


def _replace(profile: Path, new: Path) -> None:
    """``new`` in ``profile``'s place, the old one gone. Renames, so the
    connection is never left with half of either."""
    old = profile.with_name(profile.name + ".old")
    shutil.rmtree(old, ignore_errors=True)
    profile.rename(old)
    new.rename(profile)
    shutil.rmtree(old, ignore_errors=True)


def connect_phone(manifest: Manifest, account: str, *, level: str | None,
                  vault: Vault) -> dict[str, Any]:
    """The site's own app on the person's phone, at a level. Nothing is
    signed in to here: the person signs in to the app themselves."""
    spec = manifest.phone
    if spec is None:
        raise ConnectionFailed(f"{manifest.name} has no phone app Setu knows of")
    asked = manifest.level(level)
    entry = {
        "connector": manifest.id,
        "account": account,
        "auth": "phone",
        "email": "",
        "level": asked.name,
        "asked_level": asked.name,
        "scopes": [],
        "created": _now(),
        "last_used": None,
        "phone": {"android": spec.android, "ios": spec.ios},
        "secret": {},
    }
    vault.put(ref_for(manifest.id, account), entry)
    return entry


def _save_browser(manifest: Manifest, account: str, level: str, profile: Path, browser: str,
                  hosts: list[str], vault: Vault) -> dict[str, Any]:
    entry = {
        "connector": manifest.id,
        "account": account,
        "auth": "browser",
        "email": hosts[0],
        "level": level,
        "asked_level": level,
        "scopes": [],
        "created": _now(),
        "last_used": None,
        "profile": str(profile),
        "browser": browser,
        "home": site_browser.home(manifest, hosts),
        "secret": {},
    }
    vault.put(ref_for(manifest.id, account), entry)
    return entry


def _prove_by_page(manifest: Manifest, browser: str, profile: Path,
                   ask: Callable[[str], bool] | None, dump: Callable[..., str]) -> str:
    """The start page as the profile now sees it, once it shows a
    sign-in did happen -- or the person, asked, says it did."""
    assert manifest.browser is not None
    html = dump(browser, profile, manifest.browser.start_url)
    state = site_browser.page_state(html)
    if state == "out":
        raise ConnectionFailed(
            f"the window closed, but {manifest.name}'s page still shows a sign-in. Nothing "
            "was saved; run it again and close the window only after signing in")
    if state == "unknown":
        question = (f"Setu could not tell from {manifest.name}'s page whether you are signed "
                    "in (some sites hide it, or show nothing to a browser without a window). "
                    "Did you sign in?")
        if ask is None or not ask(question):
            raise ConnectionFailed(
                f"could not tell whether you signed in to {manifest.name}, so nothing was "
                "saved. If you did, run it again and answer yes (or pass --signed-in)")
    return html


#: Cookie names that read like a sign-in -- kept as evidence in the file.
_SESSIONISH = re.compile(r"sess|auth|token|login|^sid$|_sid$|^at-|jwt|user|uid", re.I)


def connect_site(address: str, account: str, *, level: str | None, vault: Vault,
                 browser: str, site_id: str | None = None,
                 ask: Callable[[str], bool] | None = None,
                 on_window: Callable[[Path], Any] | None = None,
                 window: Callable[..., Any] = site_browser.window,
                 dump: Callable[..., str] = site_browser.dump_dom) -> dict[str, Any]:
    """Sign in to a site no manifest describes, and write one for it.

    The entry carries ``note`` when the level was lowered, and
    ``connector`` names the site's new id."""
    try:
        data = sites.draft(address, site_id)
    except sites.SiteError as exc:
        raise ConnectionFailed(str(exc)) from None
    host = sites.host_of(address)
    for known in installed().values():
        covers = any(host == h or host.endswith("." + h) for h in known.hosts)
        if known.id == data["id"] or (covers and not known.generated):
            if known.local and known.generated:
                # signing in again to a site made here: its own rules
                return connect_browser(known, account, level=level, vault=vault,
                                       browser=browser, on_window=on_window, window=window,
                                       ask=ask, dump=dump)
            how = ("a file you wrote in sites/" if known.local
                   else "an installed connector")
            raise ConnectionFailed(
                f"Setu already has {known.name} ({known.id}, {how}): run `setu connect "
                f"{known.id}`, or pass --id to name this one differently")
    draft = parse(data, source=f"{host} (draft)")
    asked = draft.level(level)
    hosts = tuple(data["hosts"])
    start = data["browser"]["start_url"]
    base = _baseline(browser, start, hosts, dump)
    profile = site_browser.profile_dir(ref_for(draft.id, account))
    if on_window is not None:
        on_window(profile)
    try:
        try:
            window(browser, profile, start)
        except site_browser.BrowserSignInFailed as exc:
            raise ConnectionFailed(str(exc)) from None
        html = _prove_by_page(draft, browser, profile, ask, dump)
    except BaseException:
        site_browser.remove_profile(profile)
        raise
    new = site_browser.cookie_names(profile, hosts) - base
    data["browser"]["signed_in"] = sorted(n for n in new if _SESSIONISH.search(n))
    note = ""
    held = asked.name
    if held != "read" and sites.looks_like_money(host, site_browser.page_title(html)):
        held = "read"
        note = (f"{draft.name} looks like a bank or a payment service, so it is connected "
                f"Read only. To allow more, edit {sites.path_for(draft.id)} -- with no "
                "spending pages known, only button words would stand guard")
    manifest = sites.write(data)
    entry = _save_browser(manifest, account, held, profile, browser, [hosts[0]], vault)
    return {**entry, "note": note, "manifest_path": str(sites.path_for(manifest.id))}


def _baseline(browser: str, url: str, hosts: tuple[str, ...],
              dump: Callable[..., str]) -> set[str]:
    """The cookie names a signed-out visitor gets: two visits on a
    throwaway profile, since some are set only on the second."""
    scratch = Path(tempfile.mkdtemp(prefix="setu-baseline-"))
    try:
        for _ in range(2):
            dump(browser, scratch, url)
        return site_browser.cookie_names(scratch, hosts)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


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
    if entry.get("auth") == "browser":
        raise ConnectionFailed(f"{ref} is a browser profile, not a token: the harness's "
                               "browser tools open it")
    if entry.get("auth") == "phone":
        raise ConnectionFailed(f"{ref} is an app on the phone, not a token: the harness's "
                               "phone tools open it")
    if entry.get("locked"):
        raise ConnectionFailed(f"{ref} is locked: its folder opens with its person's "
                               "passphrase (setu lock unlock)")
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
    if entry.get("auth") == "phone":
        vault.delete(ref)              # the app's sign-in is on the phone
        return True, False
    if entry.get("auth") == "browser":
        # nothing to revoke from here: the profile IS the sign-in
        removed = site_browser.remove_profile(entry.get("profile") or "")
        vault.delete(ref)
        return True, removed
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
