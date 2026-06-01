"""DSC-013: Detect sudo in RUN instructions."""

from __future__ import annotations

from prithvi.dockerfile.parser import Instruction
from prithvi.dockerfile.rules.base import BaseRule
from prithvi.models import Finding, Severity


class SudoInRunRule(BaseRule):
    rule_id = "DSC-013"
    title = "sudo used in RUN instruction"
    severity = Severity.INFO
    description = (
        "Using sudo in a Dockerfile is unnecessary because "
        "commands already run as root by default. sudo adds "
        "complexity and potential security issues."
    )
    remediation = (
        "Remove sudo from RUN instructions. Use USER to "
        "switch users when needed."
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

            # Check for sudo as a standalone word
            args = instr.arguments
            if "sudo " in args or args.startswith("sudo"):
                findings.append(
                    self._make_finding(
                        f"{filepath}:{instr.line_number}"
                    )
                )

        return findings
