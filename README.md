# Prithvi — Container Security Scanner

> **Hindu Mythology**: Named after the Earth Goddess — protecting the foundation of your infrastructure

[![GitHub Pages](https://img.shields.io/badge/Live_Demo-Visit_Site-blue?style=for-the-badge)](https://MukundaKatta.github.io/prithvi/)
[![GitHub](https://img.shields.io/github/license/MukundaKatta/prithvi?style=flat-square)](LICENSE)
[![Stars](https://img.shields.io/github/stars/MukundaKatta/prithvi?style=flat-square)](https://github.com/MukundaKatta/prithvi/stargazers)

## Overview

Prithvi is a Python-based container security scanner that analyzes Dockerfiles and container images for security vulnerabilities and best-practice violations. It provides actionable findings with severity ratings, remediation guidance, and multiple output formats suitable for both developer workflows and CI/CD pipelines.

**Tech Stack:** Python 3.11+

## Features

- **Dockerfile Analysis** — 7 built-in rules checking for root users, unpinned tags, hardcoded secrets, privileged ports, apt best practices, broad COPY statements, and missing healthchecks
- **Image Scanning** — Inspect container images (tarball or daemon) for oversized layers, root execution, and environment secrets
- **CVE Database** — Local SQLite-based vulnerability database for offline package-CVE matching
- **Multiple Report Formats** — Rich CLI tables, JSON for CI/CD integration, and self-contained HTML reports
- **CI/CD Ready** — Non-zero exit codes on HIGH+ findings make Prithvi a drop-in security gate
- **Configurable** — Severity thresholds, rule exclusions, and environment variable overrides

## Quick Start

```bash
git clone https://github.com/MukundaKatta/prithvi.git
cd prithvi
pip install -e ".[dev]"
```

## Usage

```bash
# Scan a Dockerfile (rich table output)
prithvi scan dockerfile ./Dockerfile

# JSON output for CI pipelines
prithvi scan dockerfile ./Dockerfile --format json

# HTML report
prithvi scan dockerfile ./Dockerfile --format html --output report.html

# Only show HIGH and CRITICAL findings
prithvi scan dockerfile ./Dockerfile --severity-threshold HIGH

# Ignore specific rules
prithvi scan dockerfile ./Dockerfile --ignore DSC-004 --ignore DSC-007

# Scan a container image (requires docker)
prithvi scan image myapp:latest

# List all available rules
prithvi rules
```

## Security Rules

### Dockerfile Rules

| ID | Severity | Rule |
|----|----------|------|
| DSC-001 | HIGH | Container should not run as root |
| DSC-002 | MEDIUM | Use pinned image tags (not `latest`) |
| DSC-003 | CRITICAL | No secrets in ENV/ARG instructions |
| DSC-004 | LOW | Avoid privileged ports (< 1024) |
| DSC-005 | MEDIUM | apt-get best practices (--no-install-recommends, cleanup) |
| DSC-006 | MEDIUM | Avoid broad COPY/ADD (`. .`) |
| DSC-007 | LOW | Include HEALTHCHECK instruction |

### Image Rules

| ID | Severity | Rule |
|----|----------|------|
| IMG-001 | LOW | Oversized image layer |
| IMG-002 | HIGH | Image runs as root |
| IMG-003 | CRITICAL | Secrets in image environment variables |

## Architecture

```
src/prithvi/
├── cli.py                  # Click CLI entry point
├── models.py               # Finding, Severity, ScanResult
├── config.py               # Configuration management
├── dockerfile/
│   ├── parser.py           # Instruction-level Dockerfile parser
│   ├── analyzer.py         # Analysis orchestrator
│   └── rules/              # 7 security rules (DSC-001 to DSC-007)
│       ├── base.py         # Abstract rule base class
│       ├── user.py         # Root user detection
│       ├── tags.py         # Unpinned tag detection
│       ├── secrets.py      # Secret leak detection
│       ├── ports.py        # Privileged port detection
│       ├── apt.py          # apt-get best practices
│       ├── copy.py         # Broad COPY detection
│       └── healthcheck.py  # Missing healthcheck
├── image/
│   ├── inspector.py        # Tarball + daemon image inspection
│   ├── layer.py            # Layer-level security checks
│   ├── packages.py         # OS package extraction (dpkg, apk)
│   └── analyzer.py         # Image scan orchestrator
├── cve/
│   ├── database.py         # SQLite CVE storage
│   └── matcher.py          # Package-CVE matching
├── reporting/
│   ├── json_reporter.py    # JSON output
│   ├── table_reporter.py   # Rich CLI table output
│   ├── html_reporter.py    # Jinja2 HTML reports
│   └── templates/          # HTML report template
└── utils/
    └── version.py          # Semver comparison utilities
```

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
make test

# Lint
make lint

# Format code
make format
```

## CI/CD Integration

Prithvi exits with code 1 when HIGH or CRITICAL findings are detected, making it usable as a pipeline gate:

```yaml
# GitHub Actions example
- name: Scan Dockerfile
  run: prithvi scan dockerfile ./Dockerfile --severity-threshold HIGH
```

## Live Demo

Visit the landing page: **https://MukundaKatta.github.io/prithvi/**

## License

MIT License
