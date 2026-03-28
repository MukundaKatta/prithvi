"""Tests for individual Dockerfile security rules."""

from prithvi.dockerfile.parser import parse_dockerfile
from prithvi.dockerfile.rules.apt import AptBestPracticesRule
from prithvi.dockerfile.rules.copy import NoBroadCopyRule
from prithvi.dockerfile.rules.healthcheck import HealthcheckRule
from prithvi.dockerfile.rules.ports import PrivilegedPortRule
from prithvi.dockerfile.rules.secrets import NoSecretsInEnvRule
from prithvi.dockerfile.rules.tags import PinnedTagRule
from prithvi.dockerfile.rules.user import NoRootUserRule


class TestNoRootUserRule:
    rule = NoRootUserRule()

    def test_no_user_instruction(self):
        instructions = parse_dockerfile("FROM alpine\nCMD ['sh']\n")
        findings = self.rule.check(instructions)
        assert len(findings) == 1
        assert findings[0].rule_id == "DSC-001"

    def test_explicit_root(self):
        instructions = parse_dockerfile("FROM alpine\nUSER root\nCMD ['sh']\n")
        findings = self.rule.check(instructions)
        assert len(findings) == 1

    def test_non_root_user(self):
        instructions = parse_dockerfile("FROM alpine\nUSER appuser\nCMD ['sh']\n")
        findings = self.rule.check(instructions)
        assert len(findings) == 0

    def test_user_zero(self):
        instructions = parse_dockerfile("FROM alpine\nUSER 0\nCMD ['sh']\n")
        findings = self.rule.check(instructions)
        assert len(findings) == 1


class TestPinnedTagRule:
    rule = PinnedTagRule()

    def test_latest_tag(self):
        instructions = parse_dockerfile("FROM python:latest\n")
        findings = self.rule.check(instructions)
        assert len(findings) == 1

    def test_no_tag(self):
        instructions = parse_dockerfile("FROM python\n")
        findings = self.rule.check(instructions)
        assert len(findings) == 1

    def test_pinned_tag(self):
        instructions = parse_dockerfile("FROM python:3.12-slim\n")
        findings = self.rule.check(instructions)
        assert len(findings) == 0

    def test_digest_pinning(self):
        instructions = parse_dockerfile("FROM python@sha256:abc123\n")
        findings = self.rule.check(instructions)
        assert len(findings) == 0

    def test_scratch_ignored(self):
        instructions = parse_dockerfile("FROM scratch\n")
        findings = self.rule.check(instructions)
        assert len(findings) == 0

    def test_arg_based_image(self):
        instructions = parse_dockerfile("ARG BASE=python:3.12\nFROM $BASE\n")
        findings = self.rule.check(instructions)
        assert len(findings) == 0


class TestNoSecretsInEnvRule:
    rule = NoSecretsInEnvRule()

    def test_secret_in_env(self):
        instructions = parse_dockerfile("ENV API_KEY=mysecret\n")
        findings = self.rule.check(instructions)
        assert len(findings) == 1
        assert findings[0].severity.value == "CRITICAL"

    def test_secret_in_arg(self):
        instructions = parse_dockerfile("ARG DB_PASSWORD\n")
        findings = self.rule.check(instructions)
        assert len(findings) == 1

    def test_normal_env(self):
        instructions = parse_dockerfile("ENV APP_PORT=8080\n")
        findings = self.rule.check(instructions)
        assert len(findings) == 0

    def test_multiple_secrets(self):
        instructions = parse_dockerfile("ENV API_KEY=x\nENV SECRET_TOKEN=y\n")
        findings = self.rule.check(instructions)
        assert len(findings) == 2


class TestPrivilegedPortRule:
    rule = PrivilegedPortRule()

    def test_privileged_port(self):
        instructions = parse_dockerfile("EXPOSE 80\n")
        findings = self.rule.check(instructions)
        assert len(findings) == 1

    def test_non_privileged_port(self):
        instructions = parse_dockerfile("EXPOSE 8080\n")
        findings = self.rule.check(instructions)
        assert len(findings) == 0

    def test_multiple_ports(self):
        instructions = parse_dockerfile("EXPOSE 22 80 8080\n")
        findings = self.rule.check(instructions)
        assert len(findings) == 2  # 22 and 80


class TestAptBestPracticesRule:
    rule = AptBestPracticesRule()

    def test_missing_no_install_recommends(self):
        instructions = parse_dockerfile("RUN apt-get update && apt-get install -y curl\n")
        findings = self.rule.check(instructions)
        assert any("--no-install-recommends" in f.title for f in findings)

    def test_missing_cleanup(self):
        instructions = parse_dockerfile("RUN apt-get update && apt-get install -y curl\n")
        findings = self.rule.check(instructions)
        assert any("cleanup" in f.title.lower() for f in findings)

    def test_proper_apt_usage(self):
        instructions = parse_dockerfile(
            "RUN apt-get update && apt-get install --no-install-recommends -y curl "
            "&& rm -rf /var/lib/apt/lists/*\n"
        )
        findings = self.rule.check(instructions)
        assert len(findings) == 0

    def test_no_apt_instructions(self):
        instructions = parse_dockerfile("RUN echo hello\n")
        findings = self.rule.check(instructions)
        assert len(findings) == 0


class TestNoBroadCopyRule:
    rule = NoBroadCopyRule()

    def test_broad_copy(self):
        instructions = parse_dockerfile("COPY . .\n")
        findings = self.rule.check(instructions)
        assert len(findings) == 1

    def test_specific_copy(self):
        instructions = parse_dockerfile("COPY requirements.txt .\n")
        findings = self.rule.check(instructions)
        assert len(findings) == 0

    def test_copy_with_chown(self):
        instructions = parse_dockerfile("COPY --chown=app:app . .\n")
        findings = self.rule.check(instructions)
        assert len(findings) == 1


class TestHealthcheckRule:
    rule = HealthcheckRule()

    def test_no_healthcheck(self):
        instructions = parse_dockerfile("FROM alpine\nCMD ['sh']\n")
        findings = self.rule.check(instructions)
        assert len(findings) == 1

    def test_has_healthcheck(self):
        instructions = parse_dockerfile(
            "FROM alpine\n"
            "HEALTHCHECK CMD curl -f http://localhost/\n"
            "CMD ['sh']\n"
        )
        findings = self.rule.check(instructions)
        assert len(findings) == 0
