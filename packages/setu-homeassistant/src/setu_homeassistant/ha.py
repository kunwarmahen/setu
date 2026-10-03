"""Home Assistant's REST API, as text a model can use.

Every call is one request on ``setu.http()``, so the token and the
server's address come from Setu and never from here.

WHAT GUARDS THE HOME IS NOT A LIGHT SWITCH. Unlocking a door, disarming
an alarm, opening a garage, running a script (which can do any of
those) or restarting Home Assistant are not the same act as dimming a
lamp, though the API spells them alike: ``POST /api/services/<domain>/
<service>``. So ``call_service`` refuses them and names the other tool,
``call_secure_service``, which a harness asks about every time.
"Secure" is decided here by domain, and for covers by the device class
Home Assistant reports (garage, gate, door), never by the model's word.

ANSWERS ARE SHORT. A house has hundreds of entities with dozens of
attributes each; the whole ``/api/states`` would fill a local model's
context on its own. Listings are one line per entity and capped, and a
history is its changes, not its samples.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote

import httpx

#: Domains whose services guard the home or can do anything at all.
SECURE_DOMAINS = frozenset({
    "lock", "alarm_control_panel", "siren", "valve", "button",
    "script", "automation", "notify", "update",
    "homeassistant", "hassio", "shell_command", "rest_command", "python_script",
})
#: Cover device classes that are a way into the house.
SECURE_COVERS = frozenset({"garage", "gate", "door"})
#: At most this many entities per listing, and points per history.
MAX_ENTITIES = 200
MAX_POINTS = 60
#: An attribute value longer than this is cut, so one camera's token list
#: or a media player's queue does not drown the rest.
MAX_ATTR = 200


class HomeAssistantError(Exception):
    """A request Home Assistant refused, or one refused here first."""


class HomeAssistant:
    def __init__(self, http: httpx.Client) -> None:
        self.http = http

    def _get(self, path: str, **params: Any) -> Any:
        return self._answer(self.http.get(path, params=params or None), path)

    def _answer(self, response: httpx.Response, path: str) -> Any:
        if response.status_code == 404:
            raise HomeAssistantError(f"Home Assistant has nothing at {path} "
                                     "(check the entity id or service name)")
        if response.status_code == 400:
            raise HomeAssistantError(f"Home Assistant refused it: {response.text[:300]}")
        if response.status_code >= 300:
            raise HomeAssistantError(f"Home Assistant answered HTTP {response.status_code} "
                                     f"for {path}")
        try:
            return response.json()
        except ValueError:
            return response.text

    # ---- reading -------------------------------------------------------------

    def list_entities(self, domain: str = "", search: str = "",
                      limit: int = MAX_ENTITIES) -> str:
        states = self._get("/api/states")
        domain, needle = domain.strip().lower().rstrip("."), search.strip().lower()
        rows = []
        for st in sorted(states, key=lambda s: s.get("entity_id", "")):
            eid = st.get("entity_id", "")
            name = str((st.get("attributes") or {}).get("friendly_name") or "")
            if domain and eid.split(".")[0] != domain:
                continue
            if needle and needle not in eid.lower() and needle not in name.lower():
                continue
            rows.append(_line(st))
        limit = max(1, min(int(limit or MAX_ENTITIES), MAX_ENTITIES))
        if not rows:
            what = " ".join(x for x in (domain and f"domain {domain!r}",
                                        needle and f"matching {needle!r}") if x)
            return f"no entities {what}".strip()
        more = (f"\n… and {len(rows) - limit} more; narrow with domain or search"
                if len(rows) > limit else "")
        return f"{len(rows)} entities:\n" + "\n".join(rows[:limit]) + more

    def get_state(self, entity_id: str) -> str:
        st = self._get(f"/api/states/{quote(entity_id.strip())}")
        attrs = st.get("attributes") or {}
        lines = [_line(st), f"last changed: {st.get('last_changed', '?')}"]
        for key in sorted(attrs):
            if key in ("friendly_name", "entity_picture"):
                continue
            value = str(attrs[key])
            lines.append(f"  {key}: {value[:MAX_ATTR]}{'…' if len(value) > MAX_ATTR else ''}")
        return "\n".join(lines)

    def get_history(self, entity_id: str, hours: float = 24) -> str:
        hours = max(0.1, min(float(hours or 24), 24 * 30))
        start = (datetime.now(UTC) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
        data = self._get(f"/api/history/period/{start}", filter_entity_id=entity_id.strip(),
                         minimal_response="", no_attributes="")
        points = data[0] if data else []
        if not points:
            return f"no history for {entity_id} in the last {hours:g} hours"
        changes, last = [], None
        for p in points:
            if p.get("state") != last:
                changes.append(f"{p.get('last_changed', '?')}  {p.get('state')}")
                last = p.get("state")
        cut = changes[-MAX_POINTS:]
        head = (f"{entity_id}, last {hours:g} hours: {len(changes)} changes"
                + (f" (latest {len(cut)} shown)" if len(cut) < len(changes) else ""))
        return head + "\n" + "\n".join(cut)

    def list_services(self, domain: str) -> str:
        domain = domain.strip().lower()
        for entry in self._get("/api/services"):
            if entry.get("domain") != domain:
                continue
            lines = [f"services in {domain}:"]
            for name, spec in sorted((entry.get("services") or {}).items()):
                fields = ", ".join(sorted(spec.get("fields") or {}))
                desc = str(spec.get("description") or spec.get("name") or "")[:120]
                secure = "  [secure: call_secure_service]" if self.secure(domain) else ""
                lines.append(f"  {domain}.{name} — {desc}"
                             + (f" (fields: {fields})" if fields else "") + secure)
            return "\n".join(lines)
        return f"no services in domain {domain!r}"

    # ---- changing ------------------------------------------------------------

    def secure(self, domain: str, entity_ids: list[str] | None = None) -> bool:
        """Whether this act guards the home -- by domain, and for covers by
        what Home Assistant says the cover is."""
        if domain in SECURE_DOMAINS:
            return True
        if domain == "cover":
            for eid in entity_ids or ["all"]:
                if eid == "all" or not eid.startswith("cover."):
                    return True        # a cover we cannot look at is a door until shown not
                try:
                    st = self._get(f"/api/states/{quote(eid)}")
                except HomeAssistantError:
                    return True
                if (st.get("attributes") or {}).get("device_class") in SECURE_COVERS:
                    return True
        return False

    def call_service(self, domain: str, service: str, entity_id: str = "",
                     data: dict[str, Any] | None = None, *, secure_ok: bool = False) -> str:
        domain, service = domain.strip().lower(), service.strip().lower()
        if "." in service and not domain:
            domain, _, service = service.partition(".")
        if not domain or not service:
            raise HomeAssistantError("name both the domain and the service "
                                     "(light and turn_on)")
        ids = [e.strip() for e in entity_id.split(",") if e.strip()]
        if not secure_ok and self.secure(domain, ids):
            raise HomeAssistantError(
                f"{domain}.{service} guards the home or can do anything (locks, alarms, "
                "doors, scripts, admin): use call_secure_service, which the person approves "
                "each time -- if it is offered at all")
        body = dict(data or {})
        if ids:
            body["entity_id"] = ids[0] if len(ids) == 1 else ids
        path = f"/api/services/{quote(domain)}/{quote(service)}"
        changed = self._answer(self.http.post(path, json=body), path)
        if isinstance(changed, dict):           # newer servers may wrap the list
            changed = changed.get("changed_states", [])
        if not changed:
            return f"called {domain}.{service}; no state changed (yet)"
        return f"called {domain}.{service}; now:\n" + "\n".join(_line(s) for s in changed[:20])


def _line(st: dict[str, Any]) -> str:
    attrs = st.get("attributes") or {}
    name = attrs.get("friendly_name")
    unit = attrs.get("unit_of_measurement")
    state = f"{st.get('state')}{' ' + unit if unit else ''}"
    return f"{st.get('entity_id')}{' — ' + str(name) if name else ''}: {state}"
