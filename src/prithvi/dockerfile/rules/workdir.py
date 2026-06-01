"""DSC-010 / DSC-012: WORKDIR security rules."""

from __future__ import annotations

from prithvi.dockerfile.parser import Instruction
from prithvi.dockerfile.rules.base import BaseRule
from prithvi.models import Finding, Severity


class RelativeWorkdirRule(BaseRule):
    rule_id = "DSC-010"
    title = "WORKDIR with relative path"
    severity = Severity.LOW
    description = (
        "WORKDIR should use an absolute path to avoid "
        "ambiguity about the working directory."
    )
    remediation = (
        "Use an absolute path for WORKDIR, e.g. "
        "WORKDIR /app"
    )

    def check(
        self,
        instructions: list[Instruction],
        filepath: str = "Dockerfile",
    ) -> list[Finding]:
        findings: list[Finding] = []

        for instr in instructions:
            if instr.keyword != "WORKDIR":
                continue

            path = instr.arguments.strip()
            if not path.startswith("/"):
                findings.append(
                    self._make_finding(
                        f"{filepath}:{instr.line_number}"
                    )
                )

        return findings


class MissingWorkdirRule(BaseRule):
    rule_id = "DSC-012"
    title = "Missing WORKDIR instruction"
    severity = Severity.LOW
    description = (
        "No WORKDIR instruction found. Without WORKDIR the "
        "build relies on the base image default, which may "
        "be the filesystem root."
    )
    remediation = (
        "Add a WORKDIR instruction, e.g. WORKDIR /app"
    )

    def check(
        self,
        instructions: list[Instruction],
        filepath: str = "Dockerfile",
    ) -> list[Finding]:
        has_workdir = any(
            i.keyword == "WORKDIR" for i in instructions
        )
        if not has_workdir:
            return [self._make_finding(filepath)]
        return []
