"""Tests for HTML reporter."""

from prithvi.models import Finding, ScanResult, Severity
from prithvi.reporting.html_reporter import HtmlReporter


class TestHtmlReporter:
    def test_renders_html(self):
        result = ScanResult(target="test", scan_type="dockerfile")
        result.findings = [
            Finding("DSC-001", "Root user", Severity.HIGH, "runs as root", "Dockerfile:1", "fix"),
        ]
        result.complete()
        reporter = HtmlReporter()
        output = reporter.render(result)
        assert "<!DOCTYPE html>" in output
        assert "DSC-001" in output
        assert "Prithvi Scan Report" in output

    def test_empty_findings_html(self):
        result = ScanResult(target="test", scan_type="dockerfile")
        result.complete()
        reporter = HtmlReporter()
        output = reporter.render(result)
        assert "No security issues found" in output
