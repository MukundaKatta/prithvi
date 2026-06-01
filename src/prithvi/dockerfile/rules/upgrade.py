"""DSC-014: Detect apt-get upgrade/dist-upgrade."""

from __future__ import annotations

from prithvi.dockerfile.parser import Instruction
from prithvi.dockerfile.rules.base import BaseRule
from prithvi.models import Finding, Severity


class AptGetUpgradeRule(BaseRule):
    rule_id = "DSC-014"
    title = "apt-get upgrade in RUN instruction"
    severity = Severity.MEDIUM
    description = (
        "apt-get upgrade or dist-upgrade in a Dockerfile "
        "produces non-deterministic builds and may "
        "introduce untested package versions."
    )
    remediation = (
        "Pin specific package versions instead of running "
        "a blanket upgrade. Use apt-get install pkg=version."
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
            if (
                "apt-get upgrade" in args
                or "apt-get dist-upgrade" in args
            ):
                findings.append(
                    self._make_finding(
                        f"{filepath}:{instr.line_number}"
                    )
                )

        return findings
