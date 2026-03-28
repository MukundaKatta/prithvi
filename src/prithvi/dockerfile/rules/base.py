"""Base class for Dockerfile security rules."""

from __future__ import annotations

from abc import ABC, abstractmethod

from prithvi.dockerfile.parser import Instruction
from prithvi.models import Finding, Severity


class BaseRule(ABC):
    """Abstract base class for Dockerfile security rules."""

    rule_id: str
    title: str
    severity: Severity
    description: str
    remediation: str

    @abstractmethod
    def check(self, instructions: list[Instruction], filepath: str = "Dockerfile") -> list[Finding]:
        """Check instructions against this rule and return findings."""
        ...

    def _make_finding(self, location: str) -> Finding:
        """Create a Finding from this rule's metadata."""
        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            severity=self.severity,
            description=self.description,
            location=location,
            remediation=self.remediation,
        )
