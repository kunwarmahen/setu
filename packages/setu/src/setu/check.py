"""The certifier's kit: look at a version before putting your name to it.

``setu certify check DIR`` reads every text file of a recipe or a
connector and reports what a careful reader would want to look at
first. It is a help, not a verdict: a clean report proves nothing, and
a finding may be fine (a connector is SUPPOSED to make requests). What
the certifier deploys, reads and runs is what they certify.

WHAT IT LOOKS FOR, line by line: secrets and tokens; addresses outside
the hosts the subject declares; running other code (eval, exec,
subprocess, os.system, a shell pipe from curl); hiding it (long base64
or hex blobs, marshal, compile, rot13); writing outside its own folder
(~, /etc, .ssh, shell rc files). With ``--since OLD`` it says which
files changed from the version before -- what changed is what to read.

THE RUN HAS NO NETWORK. ``--run CMD`` runs one command the certifier
chooses inside Podman with ``--network none``, a read-only root, the
subject's folder mounted read-only and a small /tmp, under a time limit.
A recipe that only works by phoning somewhere fails here, visibly.
"""

from __future__ import annotations

import difflib
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

#: (rule, why, pattern). Kept conservative and readable: each finding is
#: a line for a person to read, so a pattern that fires on everything
#: would bury the ones that matter.
RULES: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("secret", "looks like a key or token written into the code",
     re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][^'\"]{12,}['\"]"
                r"|\b(sk|ghp|xox[bap]|AKIA)[-_A-Za-z0-9]{16,}")),
    ("runs-code", "runs other code -- read what it runs and where that comes from",
     re.compile(r"\b(eval|exec)\s*\(|\bsubprocess\.|\bos\.(system|popen|exec\w*)\s*\("
                r"|shell\s*=\s*True|\|\s*(sh|bash)\b|curl[^|\n]*\|\s*\w")),
    ("hides-code", "hides what it does -- decode it and read the result",
     re.compile(r"[A-Za-z0-9+/]{120,}={0,2}|\b(marshal|compile|__import__)\s*\("
                r"|codecs\.decode\([^)]*rot|\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){20,}", re.I)),
    ("writes-outside", "touches files outside its own folder",
     re.compile(r"(~/|/etc/|/root/|\.ssh/|\.bashrc|\.zshrc|\.profile|/usr/local/"
                r"|crontab|\.config/autostart|expanduser\()")),
)
_URL = re.compile(r"\bhttps?://([A-Za-z0-9.-]+)", re.I)
TEXT_SUFFIXES = {".py", ".sh", ".md", ".toml", ".json", ".txt", ".js", ".ts", ".cfg",
                 ".ini", ".yaml", ".yml", ""}
RUN_SECONDS = 120


@dataclass(slots=True)
class Finding:
    file: str
    line: int
    rule: str
    why: str
    text: str


@dataclass(slots=True)
class Report:
    target: str
    files: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    changed: dict[str, list[str]] = field(default_factory=dict)
    run: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    def text(self) -> str:
        lines = [f"{self.target}: {len(self.files)} file(s)"]
        if self.changed:
            for what in ("added", "removed", "changed"):
                if self.changed.get(what):
                    lines.append(f"  {what} since the last version: "
                                 + ", ".join(self.changed[what]))
        if not self.findings:
            lines.append("  nothing the scan looks for -- which proves nothing; read it")
        for f in self.findings:
            lines.append(f"  {f.file}:{f.line}  [{f.rule}] {f.why}\n      {f.text}")
        if self.run is not None:
            lines.append(f"  ran `{self.run['command']}` with no network: exit "
                         f"{self.run['exit']}")
            if self.run.get("output"):
                lines += ["      " + ln for ln in self.run["output"].splitlines()[-15:]]
        return "\n".join(lines)


def _texts(folder: Path) -> dict[str, str]:
    found = {}
    for path in sorted(p for p in folder.rglob("*") if p.is_file()):
        rel = path.relative_to(folder).as_posix()
        if "__pycache__" in path.parts or path.suffix not in TEXT_SUFFIXES:
            continue
        try:
            found[rel] = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            found[rel] = ""          # binary in a recipe is itself worth a look
    return found


def scan(folder: Path, hosts: tuple[str, ...] = ()) -> list[Finding]:
    findings: list[Finding] = []
    for rel, text in _texts(folder).items():
        if not text and (folder / rel).stat().st_size:
            findings.append(Finding(rel, 0, "binary", "not text: what is it doing here?",
                                    ""))
            continue
        for number, line in enumerate(text.splitlines(), 1):
            for rule, why, pattern in RULES:
                if pattern.search(line):
                    findings.append(Finding(rel, number, rule, why, line.strip()[:200]))
            for host in _URL.findall(line):
                host = host.lower()
                if not any(host == h or host.endswith("." + h) for h in hosts):
                    findings.append(Finding(
                        rel, number, "undeclared-host",
                        f"reaches {host}, which it does not declare"
                        + (f" (declared: {', '.join(hosts)})" if hosts else ""),
                        line.strip()[:200]))
    return findings


def changed(old: Path, new: Path) -> dict[str, list[str]]:
    before, after = _texts(old), _texts(new)
    return {"added": sorted(set(after) - set(before)),
            "removed": sorted(set(before) - set(after)),
            "changed": sorted(rel for rel in set(before) & set(after)
                              if before[rel] != after[rel])}


def diff(old: Path, new: Path) -> str:
    """The changed lines, as a reader wants them."""
    before, after = _texts(old), _texts(new)
    out = []
    for rel in sorted(set(before) | set(after)):
        if before.get(rel) != after.get(rel):
            out += difflib.unified_diff((before.get(rel) or "").splitlines(),
                                        (after.get(rel) or "").splitlines(),
                                        f"old/{rel}", f"new/{rel}", lineterm="")
    return "\n".join(out)


def run_isolated(folder: Path, command: str, *, image: str = "docker.io/library/python:3.12-slim",
                 seconds: int = RUN_SECONDS, runner: Any = None) -> dict[str, Any]:
    """``command`` in Podman: no network, read-only root, the folder
    read-only at /work, a small /tmp, a time limit."""
    podman = shutil.which("podman")
    if podman is None and runner is None:
        return {"command": command, "exit": None,
                "output": "podman is not installed here; nothing was run"}
    argv = [podman or "podman", "run", "--rm", "--network", "none", "--read-only",
            "--tmpfs", "/tmp:rw,size=64m", "--cap-drop", "ALL", "--security-opt",
            "no-new-privileges", "-v", f"{Path(folder).resolve()}:/work:ro,Z", "-w", "/work",
            image, "sh", "-c", command]
    try:
        done = (runner or subprocess.run)(argv, capture_output=True, text=True,
                                          timeout=seconds)
    except subprocess.TimeoutExpired:
        return {"command": command, "exit": None, "network": "none",
                "output": f"stopped after {seconds}s"}
    return {"command": command, "exit": done.returncode, "network": "none",
            "output": ((done.stdout or "") + (done.stderr or ""))[-4000:]}


def check(folder: Path, *, hosts: tuple[str, ...] = (), since: Path | None = None,
          run: str | None = None, runner: Any = None) -> Report:
    folder = Path(folder)
    report = Report(target=folder.name, files=list(_texts(folder)))
    report.findings = scan(folder, hosts)
    if since is not None:
        report.changed = changed(Path(since), folder)
    if run:
        report.run = run_isolated(folder, run, runner=runner)
    return report
