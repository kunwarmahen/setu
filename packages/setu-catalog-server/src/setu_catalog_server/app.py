"""The routes, and ``setu-catalog-server`` to run them.

    GET  /index.json, /index.json.sig   the signed index, byte for byte
    POST /publish                       maintainer: a newly signed index
    GET  /health                        what is served, for a monitor

Publishing takes the maintainer's token (``SETU_CATALOG_TOKEN``) and is
refused unless the signature checks out against the server's trusted
keys and the index is not older than the one being served -- an old
index could bring back a version that was withdrawn.
"""

from __future__ import annotations

import argparse
import base64
import hmac
import json
import os
import sys
import tempfile
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

    def allowed(self, request: Request) -> bool:
        given = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
        return bool(self.token) and hmac.compare_digest(given.encode(), self.token.encode())


def make_app(data: Path, token: str) -> Starlette:
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

    async def health(request: Request) -> Response:
        return JSONResponse({"ok": True, "issued": cat.issued(),
                             "keys": sorted(catalog.trusted(cat.data))})

    return Starlette(routes=[
        Route("/index.json", _file(0, "application/json")),
        Route("/index.json.sig", _file(1, "application/json")),
        Route("/publish", publish, methods=["POST"]),
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
    uvicorn.run(make_app(data, token), host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
