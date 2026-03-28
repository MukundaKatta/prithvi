"""DSC-004: Avoid exposing privileged ports."""

from __future__ import annotations

from prithvi.dockerfile.parser import Instruction
from prithvi.dockerfile.rules.base import BaseRule
from prithvi.models import Finding, Severity


class PrivilegedPortRule(BaseRule):
    rule_id = "DSC-004"
    title = "Privileged port exposed"
    severity = Severity.LOW
    description = (
        "EXPOSE instruction uses a privileged port (< 1024). "
        "This typically requires the container to run as root."
    )
    remediation = "Use non-privileged ports (>= 1024) and map them externally if needed."

    def check(self, instructions: list[Instruction], filepath: str = "Dockerfile") -> list[Finding]:
        findings: list[Finding] = []

        for instr in instructions:
            if instr.keyword != "EXPOSE":
                continue

            for port_str in instr.arguments.split():
                # Remove protocol suffix like /tcp or /udp
                port_num = port_str.split("/")[0]
                try:
                    if int(port_num) < 1024:
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            severity=self.severity,
                            description=f"Port {port_num} is a privileged port.",
                            location=f"{filepath}:{instr.line_number}",
                            remediation=self.remediation,
                        ))
                except ValueError:
                    pass

        return findings
