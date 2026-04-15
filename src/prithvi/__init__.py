"""Prithvi — static security scanner for Dockerfiles.

Prithvi reads a Dockerfile (or a stream of them), walks every instruction,
and returns a list of :class:`Finding`\\s — concrete, actionable, grouped
by severity. No image pulls, no CVE database, no internet access: every
check is a deterministic lint against the file itself.

This is the 80% of container security you should catch *before* you push
to a registry.
"""

from .core import Finding, Scanner, Severity, scan_dockerfile

__version__ = "0.1.0"
__all__ = ["Finding", "Scanner", "Severity", "scan_dockerfile"]
