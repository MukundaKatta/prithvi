"""Tests for the CLI interface."""

import pytest
from click.testing import CliRunner
from prithvi.cli import main


@pytest.fixture
def runner():
    return CliRunner()


class TestCLI:
    def test_version(self, runner):
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_help(self, runner):
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "Container Security Scanner" in result.output

    def test_scan_dockerfile_good(self, runner, tmp_path):
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text(
            "FROM python:3.12-slim\nUSER appuser\nEXPOSE 8080\n"
            "HEALTHCHECK CMD curl -f http://localhost/\nCMD ['python']\n"
        )
        result = runner.invoke(main, ["scan", "dockerfile", str(dockerfile)])
        assert result.exit_code == 0

    def test_scan_dockerfile_bad(self, runner, tmp_path):
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM python:latest\nENV API_KEY=secret\nCMD ['python']\n")
        result = runner.invoke(main, ["scan", "dockerfile", str(dockerfile)])
        assert result.exit_code == 1  # has HIGH+ findings

    def test_scan_dockerfile_json(self, runner, tmp_path):
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM python:3.12-slim\nUSER app\nHEALTHCHECK CMD true\nCMD ['python']\n")
        result = runner.invoke(main, ["scan", "dockerfile", str(dockerfile), "-f", "json"])
        assert result.exit_code == 0
        assert '"scan_type": "dockerfile"' in result.output

    def test_scan_dockerfile_output_file(self, runner, tmp_path):
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM python:3.12-slim\nUSER app\nHEALTHCHECK CMD true\nCMD ['python']\n")
        out = tmp_path / "report.json"
        result = runner.invoke(main, ["scan", "dockerfile", str(dockerfile), "-f", "json", "-o", str(out)])
        assert result.exit_code == 0
        assert out.exists()

    def test_scan_dockerfile_ignore(self, runner, tmp_path):
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM python:latest\nCMD ['python']\n")
        result = runner.invoke(main, [
            "scan", "dockerfile", str(dockerfile), "-i", "DSC-001", "-i", "DSC-002", "-i", "DSC-007"
        ])
        assert result.exit_code == 0

    def test_rules_command(self, runner):
        result = runner.invoke(main, ["rules"])
        assert result.exit_code == 0
        assert "DSC-001" in result.output

    def test_scan_dockerfile_severity_threshold(self, runner, tmp_path):
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM python:latest\nCMD ['python']\n")
        result = runner.invoke(main, [
            "scan", "dockerfile", str(dockerfile), "-s", "CRITICAL"
        ])
        # Only CRITICAL findings shown, so no HIGH+ exit code
        assert result.exit_code == 0
