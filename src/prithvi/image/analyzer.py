"""Image security analyzer - orchestrates image inspection and analysis."""

from __future__ import annotations

from pathlib import Path

from prithvi.image.inspector import inspect_tarball, inspect_daemon
from prithvi.image.layer import check_layer_sizes, check_running_as_root, check_env_secrets
from prithvi.models import ScanResult


def analyze_image(target: str, max_layer_mb: int = 100) -> ScanResult:
    """Analyze a container image for security issues.

    Args:
        target: Path to a .tar file or image name for Docker daemon inspection.
        max_layer_mb: Maximum acceptable layer size in MB.

    Returns:
        ScanResult with findings.
    """
    result = ScanResult(target=target, scan_type="image")

    # Determine inspection mode
    target_path = Path(target)
    if target_path.exists() and target_path.suffix in (".tar", ".gz"):
        metadata = inspect_tarball(target_path)
    else:
        metadata = inspect_daemon(target)

    result.metadata = {
        "os": metadata.os,
        "architecture": metadata.architecture,
        "layers": str(len(metadata.layers)),
        "user": metadata.user or "root (default)",
    }

    # Run all checks
    result.findings.extend(check_layer_sizes(metadata, max_mb=max_layer_mb))
    result.findings.extend(check_running_as_root(metadata))
    result.findings.extend(check_env_secrets(metadata))

    # Sort by severity
    result.findings.sort(key=lambda f: f.severity.numeric, reverse=True)
    result.complete()
    return result
