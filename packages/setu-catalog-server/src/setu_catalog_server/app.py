"""The routes, and ``setu-catalog-server`` to run them.

    GET  /index.json, /index.json.sig   the signed index, byte for byte
    POST /publish                       maintainer: a newly signed index
    POST /installs                      a Setu saying "installed": id + version
    GET  /installs.json                 the totals (unsigned: a hint)
    GET  /health                        what is served, for a monitor

COUNTING WITHOUT KNOWING WHO. An install is an id and a version -- no
account, no client id, and the address it came from is never kept: a
hash of it, salted with a key made for the day and deleted the next,
counts one install per address per connector per day and caps how many
one address may send. Then only totals remain. The maintainer copies the
totals into the next signed index (``setu catalog counts``), so the
number a card shows is still a signed one.

Publishing takes the maintainer's token (``SETU_CATALOG_TOKEN``) and is
refused unless the signature checks out against the server's trusted
keys and the index is not older than the one being served -- an old
index could bring back a version that was withdrawn.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import tempfile
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from setu import catalog
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

INDEX = "index.json"
SIG = "index.json.sig"
#: An index larger than this is not an index.
MAX_INDEX = 4 * 1024 * 1024
INSTALLS = "installs.json"
#: The day's salt and the day's seen hashes; both gone the next day.
TODAY = "installs-today.json"
#: Pings one address may send in a day before the rest are ignored.
PINGS_PER_DAY = 50
_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_VERSION = re.compile(r"^[0-9A-Za-z.+_-]{1,32}$")


def write_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, staged = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}-")
    with os.fdopen(handle, "wb") as out:
        out.write(data)
    os.replace(staged, path)


class Catalog:
    """What one data directory holds."""

    def __init__(self, data: Path, token: str) -> None:
        self.data = Path(data)
        self.token = token

    def served(self) -> tuple[bytes, bytes] | None:
        try:
            return (self.data / INDEX).read_bytes(), (self.data / SIG).read_bytes()
        except FileNotFoundError:
            return None

    def issued(self) -> str:
        served = self.served()
        if served is None:
            return ""
        try:
            return str(json.loads(served[0]).get("issued") or "")
        except ValueError:
            return ""

    def publish(self, index: bytes, sig: dict[str, Any]) -> dict[str, Any]:
        """Keep a newly signed index -- or say why not, changing nothing."""
        if len(index) > MAX_INDEX:
            raise catalog.CatalogError(f"an index over {MAX_INDEX} bytes")
        kid = catalog.verify(index, sig, catalog.trusted(self.data))
        parsed = catalog.parse(index, kid)
        issued = str(parsed.data.get("issued") or "")
        current = self.issued()
        if current and (not issued or issued < current):
            raise catalog.CatalogError(
                f"issued {issued or '(none)'} is older than the index served "
                f"({current}); an old index could bring back what was withdrawn")
        write_atomic(self.data / SIG, json.dumps(sig).encode())
        write_atomic(self.data / INDEX, index)
        return {"ok": True, "issued": issued, "key": kid,
                "connectors": len(parsed.connectors), "recipes": len(parsed.recipes)}

    # ---- installs ---------------------------------------------------------

    _lock = threading.Lock()

    def totals(self) -> dict[str, Any]:
        try:
            return json.loads((self.data / INSTALLS).read_text())
        except (FileNotFoundError, ValueError):
            return {}

    def _today(self, day: str) -> dict[str, Any]:
        try:
            today = json.loads((self.data / TODAY).read_text())
        except (FileNotFoundError, ValueError):
            today = {}
        if today.get("day") != day:      # a new day: yesterday's salt is gone for good
            today = {"day": day, "salt": secrets.token_hex(16), "seen": [], "pings": {}}
        return today

    def install(self, connector: str, version: str, address: str,
                day: str | None = None) -> bool:
        """Count one install; False when it was this address's again today."""
        day = day or datetime.now(UTC).strftime("%Y-%m-%d")
        with self._lock:
            today = self._today(day)
            who = hashlib.sha256(f"{today['salt']}|{address}".encode()).hexdigest()[:24]
            pings = today["pings"].get(who, 0)
            if pings >= PINGS_PER_DAY:
                return False
            today["pings"][who] = pings + 1
            seen = hashlib.sha256(f"{who}|{connector}".encode()).hexdigest()[:24]
            counted = seen not in today["seen"]
            if counted:
                today["seen"].append(seen)
                totals = self.totals()
                entry = totals.setdefault(connector, {"total": 0, "versions": {}})
                entry["total"] += 1
                entry["versions"][version] = entry["versions"].get(version, 0) + 1
                write_atomic(self.data / INSTALLS, json.dumps(totals).encode())
            write_atomic(self.data / TODAY, json.dumps(today).encode())
            return counted

    def allowed(self, request: Request) -> bool:
        given = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
        return bool(self.token) and hmac.compare_digest(given.encode(), self.token.encode())


def make_app(data: Path, token: str, *, behind_proxy: bool = False) -> Starlette:
    cat = Catalog(data, token)

    def _file(which: int, media: str):
        async def serve(request: Request) -> Response:
            served = cat.served()
            if served is None:
                return JSONResponse({"error": "no index published yet"}, status_code=404)
            return Response(served[which], media_type=media,
                            headers={"Cache-Control": "public, max-age=300"})
        return serve

    async def publish(request: Request) -> Response:
        if not cat.allowed(request):
            return JSONResponse({"error": "not the maintainer"}, status_code=401)
        try:
            body = await request.json()
            index = base64.b64decode(body["index"], validate=True)
            sig = body["sig"]
            if not isinstance(sig, dict):
                raise TypeError("sig is not an object")
        except (ValueError, KeyError, TypeError) as exc:
            return JSONResponse({"error": f"expected {{index: base64, sig: {{...}}}} "
                                          f"({exc})"}, status_code=400)
        try:
            return JSONResponse(cat.publish(index, sig))
        except catalog.CatalogError as exc:
            return JSONResponse({"error": str(exc)}, status_code=409)

    def address(request: Request) -> str:
        if behind_proxy:
            forwarded = request.headers.get("x-forwarded-for", "")
            if forwarded:
                return forwarded.split(",")[0].strip()
        return request.client.host if request.client else ""

    async def installs(request: Request) -> Response:
        try:
            body = await request.json()
            connector, version = str(body["id"]), str(body["version"])
        except (ValueError, KeyError, TypeError):
            return JSONResponse({"error": "expected {id, version}"}, status_code=400)
        if not _ID.match(connector) or not _VERSION.match(version):
            return JSONResponse({"error": "not an id and a version"}, status_code=400)
        return JSONResponse({"counted": cat.install(connector, version, address(request))})

    async def totals(request: Request) -> Response:
        return JSONResponse(cat.totals(), headers={"Cache-Control": "public, max-age=300"})

    async def health(request: Request) -> Response:
        return JSONResponse({"ok": True, "issued": cat.issued(),
                             "keys": sorted(catalog.trusted(cat.data))})

    return Starlette(routes=[
        Route("/index.json", _file(0, "application/json")),
        Route("/index.json.sig", _file(1, "application/json")),
        Route("/publish", publish, methods=["POST"]),
        Route("/installs", installs, methods=["POST"]),
        Route("/installs.json", totals),
        Route("/health", health),
    ])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="setu-catalog-server",
        description="Serve Setu's signed catalog. It never holds the signing key.")
    parser.add_argument("--data", default=os.environ.get("SETU_CATALOG_DATA", "./catalog-data"),
                        help="where everything is kept (default: $SETU_CATALOG_DATA)")
    parser.add_argument("--trust", metavar="KEY.pub",
                        help="trust a maintainer's public key for uploads, then exit")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8780)
    parser.add_argument("--behind-proxy", action="store_true",
                        help="the address is the first X-Forwarded-For (only behind a "
                        "proxy you run -- otherwise anyone can claim any address)")
    args = parser.parse_args(argv)
    data = Path(args.data)
    if args.trust:
        pub = catalog.load_public(Path(args.trust))
        catalog.trust(pub, home=data)
        print(f"uploads signed by {pub['id']} are accepted")
        return 0
    token = os.environ.get("SETU_CATALOG_TOKEN", "")
    if not token:
        print("setu-catalog-server: set SETU_CATALOG_TOKEN (the maintainer's publish "
              "token); without it nothing can be published", file=sys.stderr)
    if not catalog.trusted(data):
        print(f"setu-catalog-server: no trusted key in {data}; run with --trust KEY.pub "
              "first, or every upload is refused", file=sys.stderr)
    import uvicorn
    uvicorn.run(make_app(data, token, behind_proxy=args.behind_proxy),
                host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
