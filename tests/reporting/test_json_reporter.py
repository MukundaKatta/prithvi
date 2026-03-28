"""Tests for JSON reporter."""

import json
from prithvi.models import Finding, ScanResult, Severity
from prithvi.reporting.json_reporter import JsonReporter


class TestJsonReporter:
    def test_valid_json(self):
        result = ScanResult(target="test", scan_type="dockerfile")
        result.findings = [
            Finding("DSC-001", "Test", Severity.HIGH, "desc", "loc", "fix"),
        ]
        result.complete()
        reporter = JsonReporter()
        output = reporter.render(result)
        data = json.loads(output)
        assert data["target"] == "test"
        assert data["total_findings"] == 1
        assert data["findings"][0]["rule_id"] == "DSC-001"

    def test_empty_findings(self):
        result = ScanResult(target="test", scan_type="dockerfile")
        result.complete()
        reporter = JsonReporter()
        output = reporter.render(result)
        data = json.loads(output)
        assert data["total_findings"] == 0
        assert data["findings"] == []
