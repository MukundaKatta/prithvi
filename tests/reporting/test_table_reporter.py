"""Tests for table reporter."""

from prithvi.models import Finding, ScanResult, Severity
from prithvi.reporting.table_reporter import TableReporter


class TestTableReporter:
    def test_renders_findings(self):
        result = ScanResult(target="test", scan_type="dockerfile")
        result.findings = [
            Finding("DSC-001", "Root user", Severity.HIGH, "runs as root", "Dockerfile:1", "fix"),
        ]
        result.complete()
        reporter = TableReporter()
        output = reporter.render(result)
        assert "Prithvi Scan Report" in output
        assert "HIGH" in output

    def test_empty_findings(self):
        result = ScanResult(target="test", scan_type="dockerfile")
        result.complete()
        reporter = TableReporter()
        output = reporter.render(result)
        assert "No issues found" in output
