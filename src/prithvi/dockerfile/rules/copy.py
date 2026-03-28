"""DSC-006: Avoid broad COPY instructions."""

from __future__ import annotations

from prithvi.dockerfile.parser import Instruction
from prithvi.dockerfile.rules.base import BaseRule
from prithvi.models import Finding, Severity


class NoBroadCopyRule(BaseRule):
    rule_id = "DSC-006"
    title = "Overly broad COPY or ADD instruction"
    severity = Severity.MEDIUM
    description = (
        "COPY . . or ADD . . copies the entire build context, which may include "
        "secrets, unnecessary files, and bloat the image."
    )
    remediation = "Copy only required files explicitly, and use a .dockerignore file."

    def check(self, instructions: list[Instruction], filepath: str = "Dockerfile") -> list[Finding]:
        findings: list[Finding] = []

        for instr in instructions:
            if instr.keyword not in ("COPY", "ADD"):
                continue

            args = instr.arguments.strip()
            # Remove --from=... or --chown=... flags
            parts = [p for p in args.split() if not p.startswith("--")]

            if len(parts) >= 2 and parts[0] == "." and parts[1] in (".", "./"):
                findings.append(self._make_finding(f"{filepath}:{instr.line_number}"))

        return findings
