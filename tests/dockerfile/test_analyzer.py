"""Tests for the Dockerfile analyzer."""

from prithvi.dockerfile.analyzer import analyze_dockerfile_content


class TestAnalyzer:
    def test_good_dockerfile(self, good_dockerfile):
        result = analyze_dockerfile_content(good_dockerfile, "Dockerfile.good")
        assert result.scan_type == "dockerfile"
        assert result.target == "Dockerfile.good"
        # Good Dockerfile should have minimal findings
        critical = [f for f in result.findings if f.severity.value == "CRITICAL"]
        assert len(critical) == 0

    def test_bad_dockerfile(self, bad_dockerfile):
        result = analyze_dockerfile_content(bad_dockerfile, "Dockerfile.bad")
        assert len(result.findings) > 5  # Should trigger many rules
        # Should have secrets
        secrets = [f for f in result.findings if f.rule_id == "DSC-003"]
        assert len(secrets) >= 2
        # Should have unpinned tag
        tags = [f for f in result.findings if f.rule_id == "DSC-002"]
        assert len(tags) >= 1

    def test_ignore_rules(self, bad_dockerfile):
        result = analyze_dockerfile_content(
            bad_dockerfile, "Dockerfile.bad", ignore_rules=["DSC-001", "DSC-003"]
        )
        rule_ids = {f.rule_id for f in result.findings}
        assert "DSC-001" not in rule_ids
        assert "DSC-003" not in rule_ids

    def test_sorted_by_severity(self, bad_dockerfile):
        result = analyze_dockerfile_content(bad_dockerfile)
        for i in range(len(result.findings) - 1):
            assert result.findings[i].severity.numeric >= result.findings[i + 1].severity.numeric

    def test_completed(self, bad_dockerfile):
        result = analyze_dockerfile_content(bad_dockerfile)
        assert result.finished_at is not None
