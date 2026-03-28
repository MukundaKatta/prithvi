"""Dockerfile security analyzer."""

from __future__ import annotations

from pathlib import Path

from prithvi.dockerfile.parser import parse_dockerfile
from prithvi.dockerfile.rules import get_all_rules
from prithvi.models import ScanResult


def analyze_dockerfile(filepath: str | Path, ignore_rules: list[str] | None = None) -> ScanResult:
    """Analyze a Dockerfile for security issues.

    Args:
        filepath: Path to the Dockerfile.
        ignore_rules: List of rule IDs to skip.

    Returns:
        ScanResult with all findings.
    """
    filepath = Path(filepath)
    content = filepath.read_text()
    return analyze_dockerfile_content(content, str(filepath), ignore_rules)


def analyze_dockerfile_content(
    content: str, name: str = "Dockerfile", ignore_rules: list[str] | None = None
) -> ScanResult:
    """Analyze Dockerfile content string for security issues."""
    ignore = set(ignore_rules or [])
    instructions = parse_dockerfile(content)
    rules = get_all_rules()

    result = ScanResult(target=name, scan_type="dockerfile")

    for rule in rules:
        if rule.rule_id in ignore:
            continue
        findings = rule.check(instructions, filepath=name)
        result.findings.extend(findings)

    # Sort by severity (most severe first)
    result.findings.sort(key=lambda f: f.severity.numeric, reverse=True)
    result.complete()
    return result
