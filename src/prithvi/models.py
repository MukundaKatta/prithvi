"""Core data models for scan findings and results."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum


class Severity(StrEnum):
    """Severity levels for security findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def numeric(self) -> int:
        """Return numeric value for comparison (higher = more severe)."""
        return {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }[self]

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.numeric >= other.numeric

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.numeric > other.numeric

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.numeric <= other.numeric

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.numeric < other.numeric


@dataclass(frozen=True)
class Finding:
    """A single security finding from a scan."""

    rule_id: str
    title: str
    severity: Severity
    description: str
    location: str
    remediation: str


@dataclass
class ScanResult:
    """Aggregated result of a security scan."""

    target: str
    scan_type: str
    findings: list[Finding] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = None
    metadata: dict[str, str] = field(default_factory=dict)

    @property
    def severity_counts(self) -> dict[str, int]:
        """Count findings by severity."""
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    @property
    def has_critical(self) -> bool:
        return any(f.severity == Severity.CRITICAL for f in self.findings)

    @property
    def has_high_or_above(self) -> bool:
        return any(f.severity >= Severity.HIGH for f in self.findings)

    def findings_above(self, threshold: Severity) -> list[Finding]:
        """Return findings at or above the given severity."""
        return [
            f for f in self.findings if f.severity >= threshold
        ]

    @property
    def grade(self) -> str:
        """Letter grade based on worst finding severity."""
        if not self.findings:
            return "A"
        worst = max(f.severity for f in self.findings)
        if worst == Severity.CRITICAL:
            return "F"
        if worst == Severity.HIGH:
            return "D"
        if worst == Severity.MEDIUM:
            return "C"
        return "B"  # LOW or INFO only

    @property
    def score(self) -> int:
        """Numeric score (0-100) based on findings."""
        penalties = {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 8,
            Severity.LOW: 3,
            Severity.INFO: 1,
        }
        total = 100
        for f in self.findings:
            total -= penalties[f.severity]
        return max(total, 0)

    def complete(self) -> None:
        """Mark the scan as completed."""
        self.finished_at = datetime.now(UTC)
