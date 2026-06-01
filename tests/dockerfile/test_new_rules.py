"""Tests for new Dockerfile security rules (DSC-008 through DSC-014)."""

from prithvi.dockerfile.parser import parse_dockerfile
from prithvi.dockerfile.rules.add_remote import AddRemoteUrlRule
from prithvi.dockerfile.rules.curl_pipe import CurlPipeShellRule
from prithvi.dockerfile.rules.pip import PipNoCacheDirRule
from prithvi.dockerfile.rules.sudo import SudoInRunRule
from prithvi.dockerfile.rules.upgrade import AptGetUpgradeRule
from prithvi.dockerfile.rules.workdir import (
    MissingWorkdirRule,
    RelativeWorkdirRule,
)


class TestAddRemoteUrlRule:
    rule = AddRemoteUrlRule()

    def test_add_with_http_url(self):
        instructions = parse_dockerfile(
            "ADD http://example.com/file.tar.gz /app/\n"
        )
        findings = self.rule.check(instructions)
        assert len(findings) == 1
        assert findings[0].rule_id == "DSC-008"

    def test_add_with_https_url(self):
        instructions = parse_dockerfile(
            "ADD https://example.com/file.tar.gz /app/\n"
        )
        findings = self.rule.check(instructions)
        assert len(findings) == 1

    def test_add_local_file(self):
        instructions = parse_dockerfile("ADD app.tar.gz /app/\n")
        findings = self.rule.check(instructions)
        assert len(findings) == 0

    def test_copy_with_url_ignored(self):
        """COPY doesn't support URLs, rule should not fire."""
        instructions = parse_dockerfile(
            "COPY http://example.com/file /app/\n"
        )
        findings = self.rule.check(instructions)
        assert len(findings) == 0


class TestPipNoCacheDirRule:
    rule = PipNoCacheDirRule()

    def test_pip_install_no_cache_flag(self):
        instructions = parse_dockerfile(
            "RUN pip install flask\n"
        )
        findings = self.rule.check(instructions)
        assert len(findings) == 1
        assert findings[0].rule_id == "DSC-009"

    def test_pip_install_with_cache_flag(self):
        instructions = parse_dockerfile(
            "RUN pip install --no-cache-dir flask\n"
        )
        findings = self.rule.check(instructions)
        assert len(findings) == 0

    def test_pip3_install(self):
        instructions = parse_dockerfile(
            "RUN pip3 install requests\n"
        )
        # "pip install" is not in "pip3 install" literally
        # but "pip install" IS a substring if we check
        # carefully -- pip3 does NOT contain "pip install"
        findings = self.rule.check(instructions)
        assert len(findings) == 0

    def test_no_pip_instruction(self):
        instructions = parse_dockerfile("RUN echo hello\n")
        findings = self.rule.check(instructions)
        assert len(findings) == 0


class TestRelativeWorkdirRule:
    rule = RelativeWorkdirRule()

    def test_relative_workdir(self):
        instructions = parse_dockerfile("WORKDIR app\n")
        findings = self.rule.check(instructions)
        assert len(findings) == 1
        assert findings[0].rule_id == "DSC-010"

    def test_absolute_workdir(self):
        instructions = parse_dockerfile("WORKDIR /app\n")
        findings = self.rule.check(instructions)
        assert len(findings) == 0

    def test_relative_workdir_with_subdir(self):
        instructions = parse_dockerfile("WORKDIR src/app\n")
        findings = self.rule.check(instructions)
        assert len(findings) == 1


class TestMissingWorkdirRule:
    rule = MissingWorkdirRule()

    def test_no_workdir(self):
        instructions = parse_dockerfile(
            "FROM alpine\nCMD ['sh']\n"
        )
        findings = self.rule.check(instructions)
        assert len(findings) == 1
        assert findings[0].rule_id == "DSC-012"

    def test_has_workdir(self):
        instructions = parse_dockerfile(
            "FROM alpine\nWORKDIR /app\nCMD ['sh']\n"
        )
        findings = self.rule.check(instructions)
        assert len(findings) == 0

    def test_even_relative_workdir_counts(self):
        """MissingWorkdirRule only checks presence."""
        instructions = parse_dockerfile(
            "FROM alpine\nWORKDIR app\nCMD ['sh']\n"
        )
        findings = self.rule.check(instructions)
        assert len(findings) == 0


class TestCurlPipeShellRule:
    rule = CurlPipeShellRule()

    def test_curl_pipe_bash(self):
        instructions = parse_dockerfile(
            "RUN curl -fsSL https://example.com/setup | bash\n"
        )
        findings = self.rule.check(instructions)
        assert len(findings) == 1
        assert findings[0].rule_id == "DSC-011"
        assert findings[0].severity.value == "CRITICAL"

    def test_wget_pipe_sh(self):
        instructions = parse_dockerfile(
            "RUN wget -qO- https://example.com/i.sh | sh\n"
        )
        findings = self.rule.check(instructions)
        assert len(findings) == 1

    def test_curl_without_pipe(self):
        instructions = parse_dockerfile(
            "RUN curl -fsSL https://example.com/file -o f\n"
        )
        findings = self.rule.check(instructions)
        assert len(findings) == 0

    def test_wget_pipe_zsh(self):
        instructions = parse_dockerfile(
            "RUN wget https://example.com/s.sh | zsh\n"
        )
        findings = self.rule.check(instructions)
        assert len(findings) == 1


class TestSudoInRunRule:
    rule = SudoInRunRule()

    def test_sudo_in_run(self):
        instructions = parse_dockerfile(
            "RUN sudo apt-get install curl\n"
        )
        findings = self.rule.check(instructions)
        assert len(findings) == 1
        assert findings[0].rule_id == "DSC-013"

    def test_sudo_in_chain(self):
        instructions = parse_dockerfile(
            "RUN echo hi && sudo rm -rf /tmp/*\n"
        )
        findings = self.rule.check(instructions)
        assert len(findings) == 1

    def test_no_sudo(self):
        instructions = parse_dockerfile(
            "RUN apt-get install curl\n"
        )
        findings = self.rule.check(instructions)
        assert len(findings) == 0


class TestAptGetUpgradeRule:
    rule = AptGetUpgradeRule()

    def test_apt_get_upgrade(self):
        instructions = parse_dockerfile(
            "RUN apt-get update && apt-get upgrade -y\n"
        )
        findings = self.rule.check(instructions)
        assert len(findings) == 1
        assert findings[0].rule_id == "DSC-014"

    def test_apt_get_dist_upgrade(self):
        instructions = parse_dockerfile(
            "RUN apt-get update && apt-get dist-upgrade\n"
        )
        findings = self.rule.check(instructions)
        assert len(findings) == 1

    def test_apt_get_install_only(self):
        instructions = parse_dockerfile(
            "RUN apt-get update && apt-get install -y curl\n"
        )
        findings = self.rule.check(instructions)
        assert len(findings) == 0
