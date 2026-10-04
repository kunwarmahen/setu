"""The routes, and ``setu-catalog-server`` to run them.

    GET  /index.json, /index.json.sig   the signed index, byte for byte
    POST /publish                       maintainer: a newly signed index
    POST /installs                      a Setu saying "installed": id + version
    GET  /installs.json                 the totals (unsigned: a hint)
    POST /submissions                   an author: a connector or a recipe, queued
    GET  /submissions/{id}              its author: open, accepted or declined, and why
    GET  /submissions                   maintainer: the queue (?all for closed too)
    GET  /submissions/{id}?full         maintainer: everything that was sent
    POST /submissions/{id}/close        maintainer: accepted or declined, with a reason
    GET  /health                        what is served, for a monitor

A SUBMISSION IS AN INBOX, NEVER A PUBLISH. It is stored -- size-capped,
a few per address a day -- and nothing more. A connector is its source
(an https repo and an exact 40-character commit), never a built package;
a recipe is its files (SKILL.md and scripts). Accepting one changes
nothing that is served: the maintainer puts it in the index on their own
machine, signs, and publishes as always.

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
SUBMISSIONS = "submissions"
#: A submission larger than this, or more than this many a day from one
#: address, is refused.
MAX_SUBMISSION = 512 * 1024
SUBMISSIONS_PER_DAY = 5
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_REPO = re.compile(r"^https://[A-Za-z0-9.-]+/[A-Za-z0-9._/-]+$")
_FILE = re.compile(r"^(SKILL\.md|scripts/[A-Za-z0-9._-]+)$")
_SID = re.compile(r"^[0-9a-f]{12}$")
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

    # ---- submissions ------------------------------------------------------

    def _who_today(self, address: str, day: str) -> str:
        today = self._today(day)
        write_atomic(self.data / TODAY, json.dumps(today).encode())
        return hashlib.sha256(f"{today['salt']}|{address}".encode()).hexdigest()[:24]

    def submit(self, body: dict[str, Any], address: str, day: str | None = None) -> dict:
        """Queue one submission, or raise ValueError saying what is wrong."""
        kind, sid_name = body.get("kind"), str(body.get("id") or "")
        if kind not in ("connector", "recipe"):
            raise ValueError("kind is connector or recipe")
        if not _ID.match(sid_name):
            raise ValueError("id: lower-case letters, digits, - and _")
        author = str(body.get("author") or "").strip()[:80]
        if not author:
            raise ValueError("say who you are (author)")
        entry: dict[str, Any] = {"kind": kind, "id": sid_name, "author": author,
                                 "contact": str(body.get("contact") or "")[:200],
                                 "note": str(body.get("note") or "")[:2000]}
        if kind == "connector":
            repo, commit = str(body.get("repo") or ""), str(body.get("commit") or "")
            if not _REPO.match(repo):
                raise ValueError("repo: an https address of the source")
            if not _COMMIT.match(commit):
                raise ValueError("commit: the exact 40-character commit to review")
            entry.update(repo=repo, commit=commit,
                         manifest=str(body.get("manifest") or "")[:64 * 1024])
        else:
            files = body.get("files")
            if not isinstance(files, dict) or "SKILL.md" not in files:
                raise ValueError("files: a recipe's SKILL.md, and its scripts/")
            for name, text in files.items():
                if not _FILE.match(str(name)) or not isinstance(text, str):
                    raise ValueError(f"files: {name!r} is not SKILL.md or scripts/<name>")
            entry["files"] = files
        if len(json.dumps(entry)) > MAX_SUBMISSION:
            raise ValueError(f"over {MAX_SUBMISSION // 1024} KB")
        day = day or datetime.now(UTC).strftime("%Y-%m-%d")
        with self._lock:
            who = self._who_today(address, day)
            queue = self.data / SUBMISSIONS
            today = [p for p in queue.glob("*.json")
                     if json.loads(p.read_text()).get("who") == f"{day}|{who}"]
            if len(today) >= SUBMISSIONS_PER_DAY:
                raise PermissionError(f"{SUBMISSIONS_PER_DAY} submissions a day from one "
                                      "address; try tomorrow")
            sid = secrets.token_hex(6)
            entry.update(sid=sid, status="open", reason="", who=f"{day}|{who}",
                         at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"))
            write_atomic(queue / f"{sid}.json", json.dumps(entry).encode())
        return {"submission": sid, "status": "open"}

    def submission(self, sid: str) -> dict[str, Any] | None:
        if not _SID.match(sid):
            return None
        try:
            return json.loads((self.data / SUBMISSIONS / f"{sid}.json").read_text())
        except (FileNotFoundError, ValueError):
            return None

    def queue(self, everything: bool = False) -> list[dict[str, Any]]:
        found = []
        for p in sorted((self.data / SUBMISSIONS).glob("*.json")):
            entry = json.loads(p.read_text())
            if everything or entry.get("status") == "open":
                found.append({k: entry.get(k) for k in
                              ("sid", "kind", "id", "author", "at", "status", "reason")})
        return found

    def close(self, sid: str, verdict: str, reason: str) -> dict[str, Any]:
        entry = self.submission(sid)
        if entry is None:
            raise KeyError(sid)
        if verdict not in ("accepted", "declined"):
            raise ValueError("verdict is accepted or declined")
        entry.update(status=verdict, reason=reason.strip()[:2000])
        write_atomic(self.data / SUBMISSIONS / f"{sid}.json", json.dumps(entry).encode())
        return {"submission": sid, "status": verdict, "reason": entry["reason"]}

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

    async def submit(request: Request) -> Response:
        raw = await request.body()
        if len(raw) > MAX_SUBMISSION + 4096:
            return JSONResponse({"error": "too large"}, status_code=413)
        try:
            body = json.loads(raw)
            if not isinstance(body, dict):
                raise ValueError("not an object")
            return JSONResponse(cat.submit(body, address(request)), status_code=201)
        except PermissionError as exc:
            return JSONResponse({"error": str(exc)}, status_code=429)
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)

    async def submissions(request: Request) -> Response:
        if not cat.allowed(request):
            return JSONResponse({"error": "not the maintainer"}, status_code=401)
        return JSONResponse(cat.queue("all" in request.query_params))

    async def one(request: Request) -> Response:
        entry = cat.submission(request.path_params["sid"])
        if entry is None:
            return JSONResponse({"error": "no such submission"}, status_code=404)
        if "full" in request.query_params:
            if not cat.allowed(request):
                return JSONResponse({"error": "not the maintainer"}, status_code=401)
            return JSONResponse({k: v for k, v in entry.items() if k != "who"})
        # what its author may see: never the contact or what was sent
        return JSONResponse({k: entry.get(k) for k in
                             ("sid", "kind", "id", "at", "status", "reason")})

    async def close(request: Request) -> Response:
        if not cat.allowed(request):
            return JSONResponse({"error": "not the maintainer"}, status_code=401)
        try:
            body = await request.json()
            return JSONResponse(cat.close(request.path_params["sid"],
                                          str(body.get("verdict")), str(body.get("reason") or "")))
        except KeyError:
            return JSONResponse({"error": "no such submission"}, status_code=404)
        except (ValueError, AttributeError) as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)

    async def health(request: Request) -> Response:
        return JSONResponse({"ok": True, "issued": cat.issued(),
                             "keys": sorted(catalog.trusted(cat.data))})

    return Starlette(routes=[
        Route("/index.json", _file(0, "application/json")),
        Route("/index.json.sig", _file(1, "application/json")),
        Route("/publish", publish, methods=["POST"]),
        Route("/installs", installs, methods=["POST"]),
        Route("/installs.json", totals),
        Route("/submissions", submit, methods=["POST"]),
        Route("/submissions", submissions, methods=["GET"]),
        Route("/submissions/{sid}", one),
        Route("/submissions/{sid}/close", close, methods=["POST"]),
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
