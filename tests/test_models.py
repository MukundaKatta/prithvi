"""Tests for core data models."""

from prithvi.models import Finding, ScanResult, Severity


class TestSeverity:
    def test_ordering(self):
        assert Severity.CRITICAL > Severity.HIGH
        assert Severity.HIGH > Severity.MEDIUM
        assert Severity.MEDIUM > Severity.LOW
        assert Severity.LOW > Severity.INFO

    def test_numeric(self):
        assert Severity.CRITICAL.numeric == 5
        assert Severity.INFO.numeric == 1

    def test_equality(self):
        assert Severity.HIGH == Severity.HIGH
        assert Severity.HIGH >= Severity.HIGH

    def test_comparison_with_non_severity(self):
        assert Severity.HIGH.__gt__("not a severity") is NotImplemented


class TestFinding:
    def test_creation(self):
        f = Finding(
            rule_id="TEST-001",
            title="Test finding",
            severity=Severity.HIGH,
            description="A test",
            location="Dockerfile:1",
            remediation="Fix it",
        )
        assert f.rule_id == "TEST-001"
        assert f.severity == Severity.HIGH

    def test_immutable(self):
        f = Finding(
            rule_id="TEST-001",
            title="Test",
            severity=Severity.LOW,
            description="",
            location="",
            remediation="",
        )
        try:
            f.rule_id = "CHANGED"
            raise AssertionError("Should not allow mutation")
        except AttributeError:
            pass


class TestScanResult:
    def test_severity_counts(self):
        result = ScanResult(target="test", scan_type="dockerfile")
        result.findings = [
            Finding("A", "a", Severity.HIGH, "", "", ""),
            Finding("B", "b", Severity.HIGH, "", "", ""),
            Finding("C", "c", Severity.LOW, "", "", ""),
        ]
        counts = result.severity_counts
        assert counts["HIGH"] == 2
        assert counts["LOW"] == 1
        assert counts["CRITICAL"] == 0

    def test_has_critical(self):
        result = ScanResult(target="test", scan_type="dockerfile")
        assert not result.has_critical
        result.findings = [Finding("A", "a", Severity.CRITICAL, "", "", "")]
        assert result.has_critical

    def test_findings_above(self):
        result = ScanResult(target="test", scan_type="dockerfile")
        result.findings = [
            Finding("A", "a", Severity.CRITICAL, "", "", ""),
            Finding("B", "b", Severity.LOW, "", "", ""),
            Finding("C", "c", Severity.HIGH, "", "", ""),
        ]
        high_plus = result.findings_above(Severity.HIGH)
        assert len(high_plus) == 2

    def test_complete(self):
        result = ScanResult(
            target="test", scan_type="dockerfile",
        )
        assert result.finished_at is None
        result.complete()
        assert result.finished_at is not None

    def test_grade_a_no_findings(self):
        result = ScanResult(
            target="test", scan_type="dockerfile",
        )
        assert result.grade == "A"

    def test_grade_b_low_only(self):
        result = ScanResult(
            target="test", scan_type="dockerfile",
        )
        result.findings = [
            Finding("A", "a", Severity.LOW, "", "", ""),
            Finding("B", "b", Severity.INFO, "", "", ""),
        ]
        assert result.grade == "B"

    def test_grade_c_medium(self):
        result = ScanResult(
            target="test", scan_type="dockerfile",
        )
        result.findings = [
            Finding("A", "a", Severity.MEDIUM, "", "", ""),
        ]
        assert result.grade == "C"

    def test_grade_d_high(self):
        result = ScanResult(
            target="test", scan_type="dockerfile",
        )
        result.findings = [
            Finding("A", "a", Severity.HIGH, "", "", ""),
        ]
        assert result.grade == "D"

    def test_grade_f_critical(self):
        result = ScanResult(
            target="test", scan_type="dockerfile",
        )
        result.findings = [
            Finding("A", "a", Severity.CRITICAL, "", "", ""),
        ]
        assert result.grade == "F"

    def test_score_perfect(self):
        result = ScanResult(
            target="test", scan_type="dockerfile",
        )
        assert result.score == 100

    def test_score_deductions(self):
        result = ScanResult(
            target="test", scan_type="dockerfile",
        )
        result.findings = [
            Finding("A", "a", Severity.CRITICAL, "", "", ""),
            Finding("B", "b", Severity.HIGH, "", "", ""),
            Finding("C", "c", Severity.MEDIUM, "", "", ""),
            Finding("D", "d", Severity.LOW, "", "", ""),
            Finding("E", "e", Severity.INFO, "", "", ""),
        ]
        # 100 - 25 - 15 - 8 - 3 - 1 = 48
        assert result.score == 48

    def test_score_floor_at_zero(self):
        result = ScanResult(
            target="test", scan_type="dockerfile",
        )
        result.findings = [
            Finding(
                f"C{i}", "c", Severity.CRITICAL,
                "", "", "",
            )
            for i in range(10)
        ]
        # 100 - 10*25 = -150, floored to 0
        assert result.score == 0
