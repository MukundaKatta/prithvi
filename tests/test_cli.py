"""Tests for the CLI interface."""

import json

import pytest
from click.testing import CliRunner

from prithvi.cli import main


@pytest.fixture
def runner():
    return CliRunner()


GOOD_DOCKERFILE = (
    "FROM python:3.12-slim\nWORKDIR /app\n"
    "USER appuser\nEXPOSE 8080\n"
    "HEALTHCHECK CMD curl -f http://localhost/\n"
    "CMD ['python']\n"
)

BAD_DOCKERFILE = (
    "FROM python:latest\n"
    "ENV API_KEY=secret\n"
    "CMD ['python']\n"
)


class TestCLI:
    def test_version(self, runner):
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_help(self, runner):
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "Container Security Scanner" in result.output

    def test_scan_dockerfile_good(
        self, runner, tmp_path,
    ):
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text(GOOD_DOCKERFILE)
        result = runner.invoke(
            main,
            ["scan", "dockerfile", str(dockerfile)],
        )
        assert result.exit_code == 0

    def test_scan_dockerfile_bad(
        self, runner, tmp_path,
    ):
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text(BAD_DOCKERFILE)
        result = runner.invoke(
            main,
            ["scan", "dockerfile", str(dockerfile)],
        )
        assert result.exit_code == 1

    def test_scan_dockerfile_json(
        self, runner, tmp_path,
    ):
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text(
            "FROM python:3.12-slim\nWORKDIR /app\n"
            "USER app\nHEALTHCHECK CMD true\n"
            "CMD ['python']\n"
        )
        result = runner.invoke(
            main,
            [
                "scan", "dockerfile",
                str(dockerfile), "-f", "json",
            ],
        )
        assert result.exit_code == 0
        assert '"scan_type": "dockerfile"' in result.output

    def test_scan_dockerfile_output_file(
        self, runner, tmp_path,
    ):
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text(
            "FROM python:3.12-slim\nWORKDIR /app\n"
            "USER app\nHEALTHCHECK CMD true\n"
            "CMD ['python']\n"
        )
        out = tmp_path / "report.json"
        result = runner.invoke(
            main,
            [
                "scan", "dockerfile", str(dockerfile),
                "-f", "json", "-o", str(out),
            ],
        )
        assert result.exit_code == 0
        assert out.exists()

    def test_scan_dockerfile_ignore(
        self, runner, tmp_path,
    ):
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text(
            "FROM python:latest\nCMD ['python']\n",
        )
        result = runner.invoke(main, [
            "scan", "dockerfile", str(dockerfile),
            "-i", "DSC-001", "-i", "DSC-002",
            "-i", "DSC-007", "-i", "DSC-012",
            "-s", "MEDIUM",
        ])
        assert result.exit_code == 0

    def test_rules_command(self, runner):
        result = runner.invoke(main, ["rules"])
        assert result.exit_code == 0
        assert "DSC-001" in result.output

    def test_scan_dockerfile_severity_threshold(
        self, runner, tmp_path,
    ):
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text(
            "FROM python:latest\nCMD ['python']\n",
        )
        result = runner.invoke(main, [
            "scan", "dockerfile",
            str(dockerfile), "-s", "HIGH",
        ])
        assert result.exit_code == 1
        result = runner.invoke(main, [
            "scan", "dockerfile",
            str(dockerfile), "-s", "CRITICAL",
        ])
        assert result.exit_code == 0


class TestStdinSupport:
    """Tests for Feature 1: stdin support (Issue #11)."""

    def test_stdin_good_dockerfile(self, runner):
        result = runner.invoke(
            main,
            ["scan", "dockerfile", "-"],
            input=GOOD_DOCKERFILE,
        )
        assert result.exit_code == 0

    def test_stdin_bad_dockerfile(self, runner):
        result = runner.invoke(
            main,
            ["scan", "dockerfile", "-"],
            input=BAD_DOCKERFILE,
        )
        assert result.exit_code == 1

    def test_stdin_json_output(self, runner):
        result = runner.invoke(
            main,
            [
                "scan", "dockerfile",
                "-", "-f", "json",
            ],
            input=GOOD_DOCKERFILE,
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["target"] == "<stdin>"
        assert data["scan_type"] == "dockerfile"

    def test_stdin_with_ignore(self, runner):
        result = runner.invoke(
            main,
            [
                "scan", "dockerfile", "-",
                "-i", "DSC-001",
                "-i", "DSC-002",
                "-i", "DSC-003",
                "-i", "DSC-007",
                "-i", "DSC-012",
                "-s", "MEDIUM",
            ],
            input=BAD_DOCKERFILE,
        )
        assert result.exit_code == 0

    def test_nonexistent_path_errors(self, runner):
        result = runner.invoke(
            main,
            ["scan", "dockerfile", "/no/such/file"],
        )
        assert result.exit_code != 0


class TestQuietMode:
    """Tests for Feature 2: quiet mode (Issue #10)."""

    def test_quiet_pass(self, runner, tmp_path):
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text(GOOD_DOCKERFILE)
        result = runner.invoke(
            main,
            [
                "scan", "dockerfile",
                str(dockerfile), "-q",
            ],
        )
        assert result.exit_code == 0
        assert result.output.strip() == "PASS: 0 findings"

    def test_quiet_fail(self, runner, tmp_path):
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text(BAD_DOCKERFILE)
        result = runner.invoke(
            main,
            [
                "scan", "dockerfile",
                str(dockerfile), "--quiet",
            ],
        )
        assert result.exit_code == 1
        output = result.output.strip()
        assert output.startswith("FAIL:")
        assert "findings" in output

    def test_quiet_no_report_output(
        self, runner, tmp_path,
    ):
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text(GOOD_DOCKERFILE)
        result = runner.invoke(
            main,
            [
                "scan", "dockerfile",
                str(dockerfile), "-q",
            ],
        )
        lines = result.output.strip().splitlines()
        assert len(lines) == 1

    def test_quiet_with_threshold(
        self, runner, tmp_path,
    ):
        # Dockerfile with HIGH but no CRITICAL findings
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text(
            "FROM python:latest\nCMD ['python']\n",
        )
        result = runner.invoke(
            main,
            [
                "scan", "dockerfile",
                str(dockerfile),
                "-q", "-s", "CRITICAL",
            ],
        )
        assert result.exit_code == 0
        assert result.output.strip() == "PASS: 0 findings"

    def test_quiet_stdin_combined(self, runner):
        result = runner.invoke(
            main,
            ["scan", "dockerfile", "-", "-q"],
            input=GOOD_DOCKERFILE,
        )
        assert result.exit_code == 0
        assert result.output.strip() == "PASS: 0 findings"


class TestConfigFile:
    """Tests for Feature 3: .prithvi.toml (Issue #8)."""

    def test_from_file_defaults(self, tmp_path):
        from prithvi.config import Config

        cfg = Config.from_file(
            tmp_path / ".prithvi.toml",
        )
        assert cfg.severity_threshold.value == "LOW"
        assert cfg.output_format == "table"
        assert cfg.ignore_rules == []

    def test_from_file_reads_toml(self, tmp_path):
        from prithvi.config import Config
        from prithvi.models import Severity

        toml_path = tmp_path / ".prithvi.toml"
        toml_path.write_text(
            'severity_threshold = "MEDIUM"\n'
            'output_format = "json"\n'
            'ignore_rules = ["DSC-004", "DSC-007"]\n'
        )
        cfg = Config.from_file(toml_path)
        assert cfg.severity_threshold == Severity.MEDIUM
        assert cfg.output_format == "json"
        assert cfg.ignore_rules == [
            "DSC-004", "DSC-007",
        ]

    def test_from_file_partial(self, tmp_path):
        from prithvi.config import Config
        from prithvi.models import Severity

        toml_path = tmp_path / ".prithvi.toml"
        toml_path.write_text(
            'severity_threshold = "HIGH"\n',
        )
        cfg = Config.from_file(toml_path)
        assert cfg.severity_threshold == Severity.HIGH
        assert cfg.output_format == "table"

    def test_load_cli_overrides_env(
        self, tmp_path, monkeypatch,
    ):
        from prithvi.config import Config
        from prithvi.models import Severity

        monkeypatch.setenv(
            "PRITHVI_SEVERITY_THRESHOLD", "HIGH",
        )
        cfg = Config.load(
            config_path=tmp_path / ".prithvi.toml",
            cli_overrides={
                "severity_threshold": Severity.CRITICAL,
            },
        )
        assert (
            cfg.severity_threshold == Severity.CRITICAL
        )

    def test_load_env_overrides_file(
        self, tmp_path, monkeypatch,
    ):
        from prithvi.config import Config
        from prithvi.models import Severity

        toml_path = tmp_path / ".prithvi.toml"
        toml_path.write_text(
            'severity_threshold = "MEDIUM"\n',
        )
        monkeypatch.setenv(
            "PRITHVI_SEVERITY_THRESHOLD", "HIGH",
        )
        cfg = Config.load(config_path=toml_path)
        assert cfg.severity_threshold == Severity.HIGH

    def test_load_file_over_defaults(
        self, tmp_path, monkeypatch,
    ):
        from prithvi.config import Config

        monkeypatch.delenv(
            "PRITHVI_OUTPUT_FORMAT", raising=False,
        )
        toml_path = tmp_path / ".prithvi.toml"
        toml_path.write_text(
            'output_format = "html"\n',
        )
        cfg = Config.load(config_path=toml_path)
        assert cfg.output_format == "html"

    def test_load_none_cli_overrides_ignored(
        self, tmp_path,
    ):
        from prithvi.config import Config
        from prithvi.models import Severity

        toml_path = tmp_path / ".prithvi.toml"
        toml_path.write_text(
            'severity_threshold = "HIGH"\n',
        )
        cfg = Config.load(
            config_path=toml_path,
            cli_overrides={
                "severity_threshold": None,
            },
        )
        assert cfg.severity_threshold == Severity.HIGH


class TestJsonMetadata:
    """Tests for Feature 4: version + duration (#12)."""

    def test_json_has_scanner_version(
        self, runner, tmp_path,
    ):
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text(GOOD_DOCKERFILE)
        result = runner.invoke(
            main,
            [
                "scan", "dockerfile",
                str(dockerfile), "-f", "json",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "scanner_version" in data
        assert data["scanner_version"] == "0.1.0"

    def test_json_has_duration_ms(
        self, runner, tmp_path,
    ):
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text(GOOD_DOCKERFILE)
        result = runner.invoke(
            main,
            [
                "scan", "dockerfile",
                str(dockerfile), "-f", "json",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "duration_ms" in data
        assert isinstance(data["duration_ms"], float)
        assert data["duration_ms"] >= 0

    def test_duration_ms_none_without_finish(self):
        from prithvi.models import ScanResult
        from prithvi.reporting.json_reporter import (
            _compute_duration_ms,
        )

        r = ScanResult(
            target="test", scan_type="test",
        )
        assert _compute_duration_ms(r) is None

    def test_duration_ms_computed(self):
        from datetime import UTC, datetime, timedelta

        from prithvi.models import ScanResult
        from prithvi.reporting.json_reporter import (
            _compute_duration_ms,
        )

        start = datetime(2024, 1, 1, tzinfo=UTC)
        end = start + timedelta(milliseconds=1234)
        r = ScanResult(
            target="t",
            scan_type="t",
            started_at=start,
            finished_at=end,
        )
        assert _compute_duration_ms(r) == 1234.0
