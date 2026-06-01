"""Tests for SARIF reporter."""

import json

from prithvi.models import Finding, ScanResult, Severity
from prithvi.reporting.sarif_reporter import SarifReporter


class TestSarifReporter:
    def test_valid_sarif_structure(self):
        result = ScanResult(
            target="test-image",
            scan_type="dockerfile",
        )
        result.findings = [
            Finding(
                "DSC-001",
                "Root user",
                Severity.HIGH,
                "Running as root",
                "Dockerfile:5",
                "Add USER directive",
            ),
        ]
        result.complete()

        reporter = SarifReporter()
        output = reporter.render(result)
        data = json.loads(output)

        assert data["version"] == "2.1.0"
        assert "$schema" in data
        assert len(data["runs"]) == 1

        run = data["runs"][0]
        driver = run["tool"]["driver"]
        assert driver["name"] == "Prithvi"
        assert driver["version"] is not None
        assert len(driver["rules"]) == 1
        assert driver["rules"][0]["id"] == "DSC-001"

        assert len(run["results"]) == 1
        r = run["results"][0]
        assert r["ruleId"] == "DSC-001"
        assert r["ruleIndex"] == 0
        loc = r["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "Dockerfile"
        assert loc["region"]["startLine"] == 5

    def test_severity_mapping(self):
        result = ScanResult(
            target="test",
            scan_type="dockerfile",
        )
        result.findings = [
            Finding(
                "R1", "Crit", Severity.CRITICAL,
                "d", "f:1", "r",
            ),
            Finding(
                "R2", "High", Severity.HIGH,
                "d", "f:2", "r",
            ),
            Finding(
                "R3", "Med", Severity.MEDIUM,
                "d", "f:3", "r",
            ),
            Finding(
                "R4", "Low", Severity.LOW,
                "d", "f:4", "r",
            ),
            Finding(
                "R5", "Info", Severity.INFO,
                "d", "f:5", "r",
            ),
        ]
        result.complete()

        reporter = SarifReporter()
        output = reporter.render(result)
        data = json.loads(output)

        levels = [
            r["level"] for r in data["runs"][0]["results"]
        ]
        assert levels == [
            "error", "error", "warning", "note", "note",
        ]

    def test_empty_findings(self):
        result = ScanResult(
            target="clean",
            scan_type="dockerfile",
        )
        result.complete()

        reporter = SarifReporter()
        output = reporter.render(result)
        data = json.loads(output)

        run = data["runs"][0]
        assert run["results"] == []
        assert run["tool"]["driver"]["rules"] == []

    def test_location_without_line_number(self):
        result = ScanResult(
            target="test",
            scan_type="dockerfile",
        )
        result.findings = [
            Finding(
                "R1", "Title", Severity.MEDIUM,
                "desc", "Dockerfile", "fix",
            ),
        ]
        result.complete()

        reporter = SarifReporter()
        output = reporter.render(result)
        data = json.loads(output)

        loc = (
            data["runs"][0]["results"][0]
            ["locations"][0]["physicalLocation"]
        )
        assert loc["artifactLocation"]["uri"] == "Dockerfile"
        assert "region" not in loc

    def test_duplicate_rule_ids_share_index(self):
        result = ScanResult(
            target="test",
            scan_type="dockerfile",
        )
        result.findings = [
            Finding(
                "R1", "Title A", Severity.HIGH,
                "desc1", "f:1", "fix",
            ),
            Finding(
                "R1", "Title A", Severity.HIGH,
                "desc2", "f:2", "fix",
            ),
        ]
        result.complete()

        reporter = SarifReporter()
        output = reporter.render(result)
        data = json.loads(output)

        run = data["runs"][0]
        assert len(run["tool"]["driver"]["rules"]) == 1
        assert run["results"][0]["ruleIndex"] == 0
        assert run["results"][1]["ruleIndex"] == 0
