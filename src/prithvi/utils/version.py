"""Version comparison utilities."""

from __future__ import annotations

from packaging.version import InvalidVersion, Version


def is_version_in_range(
    version_str: str,
    start: str | None = None,
    end: str | None = None,
) -> bool:
    """Check if a version falls within a range [start, end).

    Args:
        version_str: The version to check.
        start: Minimum version (inclusive). None means no lower bound.
        end: Maximum version (exclusive). None means no upper bound.
    """
    try:
        ver = Version(version_str)
    except InvalidVersion:
        return False

    if start:
        try:
            if ver < Version(start):
                return False
        except InvalidVersion:
            return False

    if end:
        try:
            if ver >= Version(end):
                return False
        except InvalidVersion:
            return False

    return True
