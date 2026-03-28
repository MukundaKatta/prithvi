"""Configuration management for Prithvi."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from prithvi.models import Severity


@dataclass
class Config:
    """Scanner configuration."""

    severity_threshold: Severity = Severity.LOW
    max_layer_size_mb: int = 100
    data_dir: Path = field(default_factory=lambda: Path.home() / ".prithvi")
    output_format: str = "table"
    ignore_rules: list[str] = field(default_factory=list)

    @classmethod
    def from_env(cls) -> Config:
        """Create config from environment variables."""
        kwargs: dict = {}
        if threshold := os.environ.get("PRITHVI_SEVERITY_THRESHOLD"):
            kwargs["severity_threshold"] = Severity(threshold.upper())
        if max_layer := os.environ.get("PRITHVI_MAX_LAYER_SIZE_MB"):
            kwargs["max_layer_size_mb"] = int(max_layer)
        if data_dir := os.environ.get("PRITHVI_DATA_DIR"):
            kwargs["data_dir"] = Path(data_dir)
        if fmt := os.environ.get("PRITHVI_OUTPUT_FORMAT"):
            kwargs["output_format"] = fmt
        if ignore := os.environ.get("PRITHVI_IGNORE_RULES"):
            kwargs["ignore_rules"] = [r.strip() for r in ignore.split(",")]
        return cls(**kwargs)
