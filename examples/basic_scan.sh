#!/usr/bin/env bash
# Prithvi - Basic Usage Examples

# Install
pip install -e ".[dev]"

# Scan a Dockerfile (table output)
prithvi scan dockerfile ./Dockerfile

# Scan with JSON output (for CI/CD)
prithvi scan dockerfile ./Dockerfile --format json

# Generate HTML report
prithvi scan dockerfile ./Dockerfile --format html --output report.html

# Only show HIGH and CRITICAL findings
prithvi scan dockerfile ./Dockerfile --severity-threshold HIGH

# Ignore specific rules
prithvi scan dockerfile ./Dockerfile --ignore DSC-004 --ignore DSC-007

# List all rules
prithvi rules

# CI/CD gate example - exits non-zero if HIGH+ findings
prithvi scan dockerfile ./Dockerfile --severity-threshold HIGH || exit 1
