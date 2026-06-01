"""DSC-009: Detect pip install without --no-cache-dir."""

from __future__ import annotations

from prithvi.dockerfile.parser import Instruction
from prithvi.dockerfile.rules.base import BaseRule
from prithvi.models import Finding, Severity


class PipNoCacheDirRule(BaseRule):
    rule_id = "DSC-009"
    title = "pip install without --no-cache-dir"
    severity = Severity.LOW
    description = (
        "pip install without --no-cache-dir leaves the pip "
        "cache in the image layer, bloating image size."
    )
    remediation = (
        "Use: RUN pip install --no-cache-dir <packages>"
    )

    def check(
        self,
        instructions: list[Instruction],
        filepath: str = "Dockerfile",
    ) -> list[Finding]:
        findings: list[Finding] = []

        for instr in instructions:
            if instr.keyword != "RUN":
                continue

            args = instr.arguments
            if "pip install" not in args:
                continue

            if "--no-cache-dir" not in args:
                findings.append(
                    self._make_finding(
                        f"{filepath}:{instr.line_number}"
                    )
                )

        return findings
