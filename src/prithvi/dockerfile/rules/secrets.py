"""DSC-003: No secrets in ENV or ARG instructions."""

from __future__ import annotations

import re

from prithvi.dockerfile.parser import Instruction
from prithvi.dockerfile.rules.base import BaseRule
from prithvi.models import Finding, Severity

SECRET_PATTERNS = re.compile(
    r"(password|passwd|secret|token|api_key|apikey|access_key|private_key|credentials)",
    re.IGNORECASE,
)


class NoSecretsInEnvRule(BaseRule):
    rule_id = "DSC-003"
    title = "Potential secret in environment variable"
    severity = Severity.CRITICAL
    description = (
        "ENV or ARG instruction contains a variable name that suggests a secret. "
        "Secrets baked into images are visible to anyone with access to the image."
    )
    remediation = (
        "Use Docker secrets, build-time secrets (--mount=type=secret), "
        "or runtime environment injection instead of hardcoding secrets."
    )

    def check(self, instructions: list[Instruction], filepath: str = "Dockerfile") -> list[Finding]:
        findings: list[Finding] = []

        for instr in instructions:
            if instr.keyword not in ("ENV", "ARG"):
                continue

            # Extract variable name(s) from the instruction
            var_name = instr.arguments.split("=")[0].split()[0]

            if SECRET_PATTERNS.search(var_name):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    description=f"Variable '{var_name}' in {instr.keyword} may contain a secret.",
                    location=f"{filepath}:{instr.line_number}",
                    remediation=self.remediation,
                ))

        return findings
