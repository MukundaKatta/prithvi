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

            for var_name in _extract_var_names(instr):
                if SECRET_PATTERNS.search(var_name):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        description=(
                        f"Variable '{var_name}' in "
                        f"{instr.keyword} may contain a secret."
                    ),
                        location=f"{filepath}:{instr.line_number}",
                        remediation=self.remediation,
                    ))

        return findings


def _extract_var_names(instr: Instruction) -> list[str]:
    """Extract all variable names from an ENV or ARG instruction."""
    args = instr.arguments.strip()
    if not args:
        return []

    # ARG has a single variable
    if instr.keyword == "ARG":
        return [args.split("=")[0].strip()]

    # ENV KEY=VAL KEY2=VAL2 (multi-variable form with =)
    if "=" in args:
        names = []
        remaining = args
        while remaining:
            remaining = remaining.strip()
            if not remaining:
                break
            eq_pos = remaining.find("=")
            if eq_pos == -1:
                break
            key_part = remaining[:eq_pos].rsplit(None, 1)
            name = key_part[-1] if key_part else remaining[:eq_pos]
            names.append(name)
            # Skip past the value
            after_eq = remaining[eq_pos + 1:]
            if after_eq.startswith('"'):
                end = after_eq.find('"', 1)
                remaining = after_eq[end + 1:] if end != -1 else ""
            elif after_eq.startswith("'"):
                end = after_eq.find("'", 1)
                remaining = after_eq[end + 1:] if end != -1 else ""
            else:
                parts = after_eq.split(None, 1)
                remaining = parts[1] if len(parts) > 1 else ""
        return names

    # ENV KEY VALUE (legacy single-variable form without =)
    return [args.split()[0]]
