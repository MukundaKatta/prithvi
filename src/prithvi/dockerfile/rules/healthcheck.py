"""DSC-007: Dockerfile should include a HEALTHCHECK."""

from __future__ import annotations

from prithvi.dockerfile.parser import Instruction
from prithvi.dockerfile.rules.base import BaseRule
from prithvi.models import Finding, Severity


class HealthcheckRule(BaseRule):
    rule_id = "DSC-007"
    title = "Missing HEALTHCHECK instruction"
    severity = Severity.LOW
    description = (
        "No HEALTHCHECK instruction found. Without a health check, Docker and orchestrators "
        "cannot automatically detect if the application inside the container is healthy."
    )
    remediation = "Add a HEALTHCHECK instruction (e.g., HEALTHCHECK CMD curl -f http://localhost/ || exit 1)."

    def check(self, instructions: list[Instruction], filepath: str = "Dockerfile") -> list[Finding]:
        has_healthcheck = any(i.keyword == "HEALTHCHECK" for i in instructions)
        if not has_healthcheck:
            return [self._make_finding(f"{filepath}:1")]
        return []
