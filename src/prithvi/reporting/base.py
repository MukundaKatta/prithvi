"""Base reporter interface."""

from __future__ import annotations

from abc import ABC, abstractmethod

from prithvi.models import ScanResult


class BaseReporter(ABC):
    """Abstract base for scan result reporters."""

    @abstractmethod
    def render(self, result: ScanResult) -> str:
        """Render scan result to a string."""
        ...
