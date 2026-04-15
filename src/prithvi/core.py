"""Dockerfile static-analysis scanner.

The scanner is intentionally rule-based and stateless. Each check is a
small function that takes the parsed instruction list and yields findings.
Adding a new rule means adding one function and one line to ``RULES``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Tuple


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    line: int
    message: str
    hint: str

    def pretty(self) -> str:
        return (
            f"[{self.severity.value.upper():>8}] "
            f"{self.rule_id}  (line {self.line}): {self.message}\n"
            f"         → {self.hint}"
        )


@dataclass
class Instruction:
    line: int
    cmd: str  # uppercase verb: FROM, RUN, USER, ...
    args: str


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


_INSTRUCTION_RE = re.compile(r"^\s*([A-Z]+)\s+(.*)$")


def _parse(dockerfile: str) -> List[Instruction]:
    """Split a Dockerfile into instructions, handling line continuations."""
    out: List[Instruction] = []
    physical_lines = dockerfile.splitlines()

    buffer: List[str] = []
    start_line: Optional[int] = None

    for i, raw in enumerate(physical_lines, start=1):
        stripped = raw.rstrip()
        if not stripped.strip() or stripped.strip().startswith("#"):
            continue
        if start_line is None:
            start_line = i
        # Handle continuation
        if stripped.endswith("\\"):
            buffer.append(stripped[:-1].rstrip())
            continue
        buffer.append(stripped)
        joined = " ".join(buffer).strip()
        buffer = []
        m = _INSTRUCTION_RE.match(joined)
        if m:
            out.append(Instruction(line=start_line, cmd=m.group(1).upper(), args=m.group(2).strip()))
        start_line = None
    return out


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


RuleFn = Callable[[List[Instruction]], Iterable[Finding]]


def _rule_no_latest_tag(instrs: List[Instruction]) -> Iterable[Finding]:
    for ins in instrs:
        if ins.cmd != "FROM":
            continue
        image = ins.args.split()[0]
        if ":" not in image and "@" not in image:
            yield Finding(
                rule_id="PR001",
                severity=Severity.MEDIUM,
                line=ins.line,
                message=f"FROM {image!r} has no tag — effectively pins to :latest",
                hint="Pin an immutable tag or digest: `FROM image:1.2.3` or `FROM image@sha256:...`",
            )
        elif image.endswith(":latest"):
            yield Finding(
                rule_id="PR001",
                severity=Severity.MEDIUM,
                line=ins.line,
                message=f"FROM {image!r} uses the :latest tag",
                hint="Pin a specific version so builds are reproducible.",
            )


def _rule_runs_as_root(instrs: List[Instruction]) -> Iterable[Finding]:
    user_set = False
    last_user_line = 0
    for ins in instrs:
        if ins.cmd == "USER":
            user_set = ins.args.strip() not in ("root", "0")
            last_user_line = ins.line
    if not user_set:
        yield Finding(
            rule_id="PR002",
            severity=Severity.HIGH,
            line=last_user_line or instrs[-1].line if instrs else 1,
            message="Image ends as root (no non-root USER set)",
            hint="Add `RUN adduser -D app && USER app` (or similar) before the final CMD.",
        )


def _rule_apt_no_cache(instrs: List[Instruction]) -> Iterable[Finding]:
    for ins in instrs:
        if ins.cmd != "RUN":
            continue
        low = ins.args.lower()
        if "apt-get install" in low and "rm -rf /var/lib/apt/lists" not in low:
            yield Finding(
                rule_id="PR003",
                severity=Severity.LOW,
                line=ins.line,
                message="apt-get install without clearing /var/lib/apt/lists",
                hint="Append `&& rm -rf /var/lib/apt/lists/*` to the same RUN so the layer ships trim.",
            )
        if "apk add" in low and "--no-cache" not in low:
            yield Finding(
                rule_id="PR003",
                severity=Severity.LOW,
                line=ins.line,
                message="apk add without --no-cache bloats the image layer",
                hint="Use `apk add --no-cache ...` so Alpine doesn't keep the index around.",
            )


def _rule_curl_pipe_sh(instrs: List[Instruction]) -> Iterable[Finding]:
    for ins in instrs:
        if ins.cmd != "RUN":
            continue
        if re.search(r"(curl|wget)[^|]*\|\s*(bash|sh)\b", ins.args):
            yield Finding(
                rule_id="PR004",
                severity=Severity.HIGH,
                line=ins.line,
                message="Remote installer piped straight to a shell (`curl ... | sh`)",
                hint="Download, verify checksum, *then* execute. Pipes hide supply-chain swaps.",
            )


def _rule_add_instead_of_copy(instrs: List[Instruction]) -> Iterable[Finding]:
    for ins in instrs:
        if ins.cmd != "ADD":
            continue
        src = ins.args.split()[0] if ins.args else ""
        if src.startswith(("http://", "https://")):
            yield Finding(
                rule_id="PR005",
                severity=Severity.MEDIUM,
                line=ins.line,
                message="ADD used to fetch a remote URL — no integrity check, no cache control",
                hint="Use `RUN curl -fsSLo file URL && sha256sum ...` with an explicit checksum.",
            )
        else:
            yield Finding(
                rule_id="PR005",
                severity=Severity.LOW,
                line=ins.line,
                message="ADD used for a local path",
                hint="Prefer `COPY` — same outcome without ADD's surprise tar/url handling.",
            )


def _rule_hardcoded_secret(instrs: List[Instruction]) -> Iterable[Finding]:
    secret_re = re.compile(
        r"(password|passwd|secret|api[_-]?key|token|aws_secret_access_key)\s*=\s*[^\s$]{4,}",
        re.IGNORECASE,
    )
    for ins in instrs:
        if ins.cmd not in {"ENV", "ARG", "RUN"}:
            continue
        if secret_re.search(ins.args):
            yield Finding(
                rule_id="PR006",
                severity=Severity.CRITICAL,
                line=ins.line,
                message=f"Possible hard-coded secret in {ins.cmd} instruction",
                hint="Move to a build arg sourced from the CI secret store, or mount at runtime.",
            )


def _rule_privileged_sudo(instrs: List[Instruction]) -> Iterable[Finding]:
    for ins in instrs:
        if ins.cmd != "RUN":
            continue
        if re.search(r"\bsudo\b", ins.args):
            yield Finding(
                rule_id="PR007",
                severity=Severity.MEDIUM,
                line=ins.line,
                message="RUN invokes `sudo` — the builder is already root; `sudo` is a smell",
                hint="Drop the `sudo`; a Dockerfile build doesn't have a real user layer.",
            )


RULES: Tuple[RuleFn, ...] = (
    _rule_no_latest_tag,
    _rule_runs_as_root,
    _rule_apt_no_cache,
    _rule_curl_pipe_sh,
    _rule_add_instead_of_copy,
    _rule_hardcoded_secret,
    _rule_privileged_sudo,
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class Scanner:
    """Run every rule in :data:`RULES` against a parsed Dockerfile."""

    def scan(self, dockerfile_text: str) -> List[Finding]:
        instrs = _parse(dockerfile_text)
        findings: List[Finding] = []
        for rule in RULES:
            findings.extend(rule(instrs))
        findings.sort(key=lambda f: (_severity_rank(f.severity), f.line))
        return findings


def _severity_rank(sev: Severity) -> int:
    return ["critical", "high", "medium", "low", "info"].index(sev.value)


def scan_dockerfile(path: str | Path) -> List[Finding]:
    """Convenience helper: scan a file on disk."""
    return Scanner().scan(Path(path).read_text(encoding="utf-8"))
