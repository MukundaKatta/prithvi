"""DSC-011: Detect curl/wget piped to shell."""

from __future__ import annotations

import re

from prithvi.dockerfile.parser import Instruction
from prithvi.dockerfile.rules.base import BaseRule
from prithvi.models import Finding, Severity

_CURL_PIPE_RE = re.compile(
    r"(curl|wget)\s+.*\|\s*(sh|bash|zsh)"
)


class CurlPipeShellRule(BaseRule):
    rule_id = "DSC-011"
    title = "curl/wget piped to shell"
    severity = Severity.CRITICAL
    description = (
        "Piping curl or wget output directly into a shell "
        "executes unverified remote code, enabling "
        "supply-chain attacks."
    )
    remediation = (
        "Download the script first, verify its checksum, "
        "then execute it in a separate step."
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

            if _CURL_PIPE_RE.search(instr.arguments):
                findings.append(
                    self._make_finding(
                        f"{filepath}:{instr.line_number}"
                    )
                )

        return findings
