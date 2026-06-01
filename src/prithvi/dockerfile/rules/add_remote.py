"""DSC-008: Detect ADD with remote URLs."""

from __future__ import annotations

from prithvi.dockerfile.parser import Instruction
from prithvi.dockerfile.rules.base import BaseRule
from prithvi.models import Finding, Severity


class AddRemoteUrlRule(BaseRule):
    rule_id = "DSC-008"
    title = "ADD with remote URL"
    severity = Severity.HIGH
    description = (
        "ADD with remote URLs downloads content without "
        "checksum verification, risking supply-chain attacks."
    )
    remediation = (
        "Use COPY with a locally downloaded file, or use "
        "curl/wget with checksum verification in a RUN step."
    )

    def check(
        self,
        instructions: list[Instruction],
        filepath: str = "Dockerfile",
    ) -> list[Finding]:
        findings: list[Finding] = []

        for instr in instructions:
            if instr.keyword != "ADD":
                continue

            args = instr.arguments
            if "http://" in args or "https://" in args:
                findings.append(
                    self._make_finding(
                        f"{filepath}:{instr.line_number}"
                    )
                )

        return findings
