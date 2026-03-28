"""DSC-001: Container should not run as root."""

from __future__ import annotations

from prithvi.dockerfile.parser import Instruction
from prithvi.dockerfile.rules.base import BaseRule
from prithvi.models import Finding, Severity


class NoRootUserRule(BaseRule):
    rule_id = "DSC-001"
    title = "Container runs as root"
    severity = Severity.HIGH
    description = (
        "No USER instruction found, or the final USER is root. "
        "Running containers as root increases the attack surface."
    )
    remediation = "Add a USER instruction to switch to a non-root user before CMD/ENTRYPOINT."

    def check(self, instructions: list[Instruction], filepath: str = "Dockerfile") -> list[Finding]:
        user_instructions = [i for i in instructions if i.keyword == "USER"]

        if not user_instructions:
            return [self._make_finding(f"{filepath}:1")]

        last_user = user_instructions[-1]
        username = last_user.arguments.strip().split(":")[0]
        if username in ("root", "0"):
            return [self._make_finding(f"{filepath}:{last_user.line_number}")]

        return []
