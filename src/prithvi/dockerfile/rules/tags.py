"""DSC-002: Use pinned image tags instead of 'latest'."""

from __future__ import annotations

from prithvi.dockerfile.parser import Instruction
from prithvi.dockerfile.rules.base import BaseRule
from prithvi.models import Finding, Severity


class PinnedTagRule(BaseRule):
    rule_id = "DSC-002"
    title = "Unpinned base image tag"
    severity = Severity.MEDIUM
    description = (
        "Base image uses 'latest' tag or no tag at all, which makes builds non-reproducible "
        "and may introduce unexpected vulnerabilities."
    )
    remediation = "Pin base images to a specific version tag or digest (e.g., python:3.12-slim)."

    def check(self, instructions: list[Instruction], filepath: str = "Dockerfile") -> list[Finding]:
        findings: list[Finding] = []

        for instr in instructions:
            if instr.keyword != "FROM":
                continue

            image = instr.arguments.split()[0]  # handle "FROM image AS builder"

            # Skip scratch and ARG-based images
            if image == "scratch" or image.startswith("$"):
                continue

            # Check for digest pinning (always okay)
            if "@sha256:" in image:
                continue

            # Split image:tag
            if ":" in image:
                tag = image.split(":")[-1]
                if tag == "latest":
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        description=f"Image '{image}' uses 'latest' tag.",
                        location=f"{filepath}:{instr.line_number}",
                        remediation=self.remediation,
                    ))
            else:
                # No tag specified (defaults to latest)
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    description=f"Image '{image}' has no tag (defaults to 'latest').",
                    location=f"{filepath}:{instr.line_number}",
                    remediation=self.remediation,
                ))

        return findings
