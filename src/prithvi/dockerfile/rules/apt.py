"""DSC-005: apt-get best practices."""

from __future__ import annotations

from prithvi.dockerfile.parser import Instruction
from prithvi.dockerfile.rules.base import BaseRule
from prithvi.models import Finding, Severity


class AptBestPracticesRule(BaseRule):
    rule_id = "DSC-005"
    title = "apt-get best practices violation"
    severity = Severity.MEDIUM
    description = (
        "apt-get install should use --no-install-recommends and clean up "
        "/var/lib/apt/lists/* in the same layer to minimize image size and attack surface."
    )
    remediation = (
        "Use: RUN apt-get update && apt-get install --no-install-recommends -y <packages> "
        "&& rm -rf /var/lib/apt/lists/*"
    )

    def check(self, instructions: list[Instruction], filepath: str = "Dockerfile") -> list[Finding]:
        findings: list[Finding] = []

        for instr in instructions:
            if instr.keyword != "RUN":
                continue

            args = instr.arguments

            if "apt-get install" not in args:
                continue

            if "--no-install-recommends" not in args:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title="Missing --no-install-recommends",
                    severity=self.severity,
                    description="apt-get install without --no-install-recommends installs unnecessary packages.",
                    location=f"{filepath}:{instr.line_number}",
                    remediation=self.remediation,
                ))

            if "rm -rf /var/lib/apt/lists" not in args:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title="Missing apt cache cleanup",
                    severity=Severity.LOW,
                    description="apt cache not cleaned in the same RUN layer, increasing image size.",
                    location=f"{filepath}:{instr.line_number}",
                    remediation=self.remediation,
                ))

        return findings
