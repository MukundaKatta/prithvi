#!/usr/bin/env python3
"""Example: Using Prithvi as a Python library."""

from prithvi.dockerfile.analyzer import analyze_dockerfile_content
from prithvi.reporting import get_reporter
from prithvi.models import Severity

# Sample Dockerfile content
dockerfile_content = """\
FROM python:latest
ENV SECRET_KEY=mysupersecret
RUN apt-get update && apt-get install -y curl
COPY . .
EXPOSE 80
CMD ["python", "app.py"]
"""

# Analyze
result = analyze_dockerfile_content(dockerfile_content, "example/Dockerfile")

# Print summary
print(f"Target: {result.target}")
print(f"Total findings: {len(result.findings)}")
print(f"Severity counts: {result.severity_counts}")
print()

# Filter by severity
critical = result.findings_above(Severity.HIGH)
print(f"HIGH+ findings: {len(critical)}")
for finding in critical:
    print(f"  [{finding.severity.value}] {finding.rule_id}: {finding.title}")
    print(f"    Location: {finding.location}")
    print(f"    Fix: {finding.remediation}")
    print()

# Generate JSON report
reporter = get_reporter("json")
json_report = reporter.render(result)
print("JSON Report:")
print(json_report[:200] + "...")
