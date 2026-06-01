"""Match installed packages against CVE database."""

from __future__ import annotations

from prithvi.cve.database import CVEDatabase
from prithvi.image.packages import InstalledPackage
from prithvi.models import Finding, Severity
from prithvi.utils.version import is_version_in_range

SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def match_packages(
    packages: list[InstalledPackage],
    db: CVEDatabase | None = None,
) -> list[Finding]:
    """Match installed packages against the CVE database.

    Args:
        packages: List of installed packages to check.
        db: CVE database instance. Uses default if None.

    Returns:
        List of findings for vulnerable packages.
    """
    owns_db = db is None
    if owns_db:
        db = CVEDatabase()

    try:
        return _do_match(packages, db)
    finally:
        if owns_db:
            db.close()


def _do_match(
    packages: list[InstalledPackage],
    db: CVEDatabase,
) -> list[Finding]:
    findings: list[Finding] = []

    for pkg in packages:
        records = db.lookup(pkg.name, pkg.ecosystem)

        for record in records:
            if is_version_in_range(
                pkg.version, record.version_start, record.version_end
            ):
                severity = SEVERITY_MAP.get(
                    record.severity.upper(), Severity.MEDIUM
                )
                findings.append(Finding(
                    rule_id=record.cve_id,
                    title=f"Vulnerable package: {pkg.name} {pkg.version}",
                    severity=severity,
                    description=(
                        record.description
                        or f"{record.cve_id} affects {pkg.name}"
                    ),
                    location=f"{pkg.name}@{pkg.version} ({pkg.ecosystem})",
                    remediation=(
                        f"Upgrade {pkg.name} to a version "
                        f"not affected by {record.cve_id}."
                    ),
                ))

    return findings
