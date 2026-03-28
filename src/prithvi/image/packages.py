"""Extract installed packages from a container image filesystem."""

from __future__ import annotations

import re
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class InstalledPackage:
    """An installed system package."""

    name: str
    version: str
    ecosystem: str  # 'deb', 'rpm', 'apk'


def extract_packages_from_tarball(tar_path: str | Path) -> list[InstalledPackage]:
    """Extract installed packages from a Docker image tarball."""
    tar_path = Path(tar_path)
    packages: list[InstalledPackage] = []

    with tempfile.TemporaryDirectory() as tmpdir:
        with tarfile.open(tar_path, "r") as tar:
            tar.extractall(tmpdir, filter="data")

        tmppath = Path(tmpdir)

        # Check all layer tarballs for package databases
        for layer_tar in tmppath.rglob("layer.tar"):
            with tarfile.open(layer_tar, "r") as lt:
                lt.extractall(tmppath / "fs", filter="data")

        fs_root = tmppath / "fs"

        # Debian/Ubuntu dpkg
        dpkg_status = fs_root / "var/lib/dpkg/status"
        if dpkg_status.exists():
            packages.extend(_parse_dpkg(dpkg_status))

        # Alpine apk
        apk_installed = fs_root / "lib/apk/db/installed"
        if apk_installed.exists():
            packages.extend(_parse_apk(apk_installed))

    return packages


def _parse_dpkg(status_file: Path) -> list[InstalledPackage]:
    """Parse dpkg status file."""
    packages: list[InstalledPackage] = []
    current_name = ""
    current_version = ""

    for line in status_file.read_text(errors="replace").splitlines():
        if line.startswith("Package: "):
            current_name = line.split(": ", 1)[1].strip()
        elif line.startswith("Version: "):
            current_version = line.split(": ", 1)[1].strip()
        elif line == "" and current_name:
            if current_version:
                packages.append(InstalledPackage(
                    name=current_name, version=current_version, ecosystem="deb"
                ))
            current_name = ""
            current_version = ""

    # Handle last entry
    if current_name and current_version:
        packages.append(InstalledPackage(
            name=current_name, version=current_version, ecosystem="deb"
        ))

    return packages


def _parse_apk(installed_file: Path) -> list[InstalledPackage]:
    """Parse Alpine apk installed file."""
    packages: list[InstalledPackage] = []
    current_name = ""
    current_version = ""

    for line in installed_file.read_text(errors="replace").splitlines():
        if line.startswith("P:"):
            current_name = line[2:].strip()
        elif line.startswith("V:"):
            current_version = line[2:].strip()
        elif line == "" and current_name:
            if current_version:
                packages.append(InstalledPackage(
                    name=current_name, version=current_version, ecosystem="apk"
                ))
            current_name = ""
            current_version = ""

    if current_name and current_version:
        packages.append(InstalledPackage(
            name=current_name, version=current_version, ecosystem="apk"
        ))

    return packages
