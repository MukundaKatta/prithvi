"""Layer-level security analysis."""

from __future__ import annotations

from prithvi.image.inspector import ImageMetadata, LayerInfo
from prithvi.models import Finding, Severity

DEFAULT_MAX_LAYER_MB = 100

DANGEROUS_BINARIES = {"curl", "wget", "nc", "ncat", "netcat", "telnet", "nmap"}


def check_layer_sizes(metadata: ImageMetadata, max_mb: int = DEFAULT_MAX_LAYER_MB) -> list[Finding]:
    """Flag layers that exceed the size threshold."""
    findings: list[Finding] = []
    max_bytes = max_mb * 1024 * 1024

    for layer in metadata.layers:
        if layer.size_bytes > max_bytes:
            size_mb = layer.size_bytes / (1024 * 1024)
            findings.append(Finding(
                rule_id="IMG-001",
                title="Oversized layer",
                severity=Severity.LOW,
                description=f"Layer {layer.digest[:12]} is {size_mb:.1f}MB (threshold: {max_mb}MB).",
                location=f"{metadata.name}:{layer.digest[:12]}",
                remediation="Combine commands in a single RUN to reduce layer size, or use multi-stage builds.",
            ))

    return findings


def check_running_as_root(metadata: ImageMetadata) -> list[Finding]:
    """Check if the image runs as root."""
    if not metadata.user or metadata.user in ("root", "0"):
        return [Finding(
            rule_id="IMG-002",
            title="Image runs as root",
            severity=Severity.HIGH,
            description="The container image is configured to run as root user.",
            location=metadata.name,
            remediation="Set a non-root USER in the Dockerfile.",
        )]
    return []


def check_env_secrets(metadata: ImageMetadata) -> list[Finding]:
    """Check for potential secrets in environment variables."""
    import re

    secret_pattern = re.compile(
        r"(password|passwd|secret|token|api_key|apikey|access_key|private_key|credentials)",
        re.IGNORECASE,
    )
    findings: list[Finding] = []

    for env in metadata.env_vars:
        key = env.split("=")[0]
        if secret_pattern.search(key):
            findings.append(Finding(
                rule_id="IMG-003",
                title="Potential secret in image environment",
                severity=Severity.CRITICAL,
                description=f"Environment variable '{key}' may contain a secret baked into the image.",
                location=metadata.name,
                remediation="Use runtime environment injection or Docker secrets instead.",
            ))

    return findings
