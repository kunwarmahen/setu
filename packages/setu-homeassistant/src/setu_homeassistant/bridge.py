"""setu-homeassistant-mcp: Home Assistant's own MCP server, on stdio.

Home Assistant serves MCP itself, at ``/api/mcp`` over Streamable HTTP,
stateless: one JSON-RPC request in a POST, one answer back. A harness
that starts connectors as programs on stdio cannot reach that alone, and
should not hold the token if it could. So this bridge reads JSON-RPC
lines on stdin, POSTs each with the token Setu hands it
(``setu.http()``), and writes the answer back as a line. The harness
talks MCP to Home Assistant; the token stays between Setu and here.

THE LEVEL IS KEPT HERE. At "See only", ``tools/list`` answers carry only
the tools the manifest classes read, and a ``tools/call`` for any other
is refused before it leaves the machine. At "See and control" every tool
passes; the manifest's ``"*" = "write"`` makes a harness ask about each
one it does not name.

NOTHING ELSE IS INTERPRETED. Requests and answers pass through as
Home Assistant wrote them, so a newer Home Assistant with new tools or
fields works without a new bridge.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import IO, Any

import httpx
import setu
from setu.manifest import load

from setu_homeassistant import MCP_MANIFEST

PATH = "/api/mcp"
HEADERS = {"Accept": "application/json, text/event-stream",
           "Content-Type": "application/json"}


def read_tools() -> frozenset[str]:
    """The tools the manifest classes read -- all that "See only" shows."""
    manifest = load(Path(MCP_MANIFEST))
    return frozenset(t for t, k in manifest.verbs.items() if k == "read" and t != "*")


def _error(mid: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def _messages(response: httpx.Response) -> list[dict[str, Any]]:
    """The JSON-RPC message(s) in one answer: a JSON body, or the data
    lines of an event stream."""
    kind = response.headers.get("content-type", "")
    if "text/event-stream" in kind:
        out = []
        for line in response.text.splitlines():
            if line.startswith("data:") and line[5:].strip():
                out.append(json.loads(line[5:].strip()))
        return out
    if not response.content.strip():
        return []
    data = response.json()
    return data if isinstance(data, list) else [data]


class Bridge:
    def __init__(self, http: httpx.Client, level: str) -> None:
        self.http = http
        self.read_only = level not in ("control", "full")
        self.readable = read_tools()
        self.session: str | None = None

    def handle(self, message: dict[str, Any]) -> list[dict[str, Any]]:
        """One message from the harness -> the answers to write back."""
        mid, method = message.get("id"), message.get("method")
        if self.read_only and method == "tools/call":
            name = (message.get("params") or {}).get("name", "")
            if name not in self.readable:
                return [_error(mid, -32601, f"{name!r} changes things, and this "
                               "connection is See only")]
        headers = dict(HEADERS)
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        try:
            response = self.http.post(PATH, json=message, headers=headers)
        except httpx.HTTPError as exc:
            return [] if mid is None else [_error(mid, -32000, f"Home Assistant "
                                                  f"unreachable: {exc}")]
        self.session = response.headers.get("mcp-session-id") or self.session
        if response.status_code == 404:
            return [] if mid is None else [_error(
                mid, -32000, "Home Assistant has no MCP server at /api/mcp: add the "
                "'Model Context Protocol Server' integration (2025.2 or later)")]
        if response.status_code >= 400:
            return [] if mid is None else [_error(
                mid, -32000, f"Home Assistant answered HTTP {response.status_code}: "
                f"{response.text[:200]}")]
        if mid is None:
            return []                       # a notification: nothing comes back
        return [self._filter(m) for m in _messages(response)]

    def _filter(self, answer: dict[str, Any]) -> dict[str, Any]:
        result = answer.get("result")
        if self.read_only and isinstance(result, dict) and isinstance(result.get("tools"), list):
            result = {**result, "tools": [t for t in result["tools"]
                                          if t.get("name") in self.readable]}
            return {**answer, "result": result}
        return answer

    def run(self, stdin: IO[str], stdout: IO[str]) -> None:
        for line in stdin:
            if not line.strip():
                continue
            try:
                message = json.loads(line)
            except ValueError:
                answers = [_error(None, -32700, "not JSON")]
            else:
                answers = self.handle(message)
            for answer in answers:
                stdout.write(json.dumps(answer) + "\n")
                stdout.flush()


def main() -> int:
    try:
        level = setu.granted_level()
        http = setu.http(timeout=60.0)
    except setu.NoToken as exc:
        print(f"setu-homeassistant-mcp: {exc}", file=sys.stderr)
        return 2
    Bridge(http, level).run(sys.stdin, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
