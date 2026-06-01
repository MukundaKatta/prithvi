"""Configuration management for Prithvi."""

from __future__ import annotations

import contextlib
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from prithvi.models import Severity

CONFIG_FILENAME = ".prithvi.toml"


@dataclass
class Config:
    """Scanner configuration."""

    severity_threshold: Severity = Severity.LOW
    max_layer_size_mb: int = 100
    data_dir: Path = field(
        default_factory=lambda: Path.home() / ".prithvi",
    )
    output_format: str = "table"
    ignore_rules: list[str] = field(default_factory=list)

    @classmethod
    def from_file(
        cls, path: str | Path | None = None,
    ) -> Config:
        """Load config from a .prithvi.toml file.

        Args:
            path: Explicit path to the TOML file.
                  If None, searches the current directory.

        Returns:
            Config populated from the file, or defaults
            if the file does not exist.
        """
        resolved = (
            Path.cwd() / CONFIG_FILENAME
            if path is None
            else Path(path)
        )

        if not resolved.is_file():
            return cls()

        with open(resolved, "rb") as fh:
            data = tomllib.load(fh)

        kwargs: dict = {}
        if "severity_threshold" in data:
            kwargs["severity_threshold"] = Severity(
                str(data["severity_threshold"]).upper(),
            )
        if "max_layer_size_mb" in data:
            kwargs["max_layer_size_mb"] = int(
                data["max_layer_size_mb"],
            )
        if "data_dir" in data:
            kwargs["data_dir"] = Path(data["data_dir"])
        if "output_format" in data:
            kwargs["output_format"] = str(
                data["output_format"],
            )
        if "ignore_rules" in data:
            kwargs["ignore_rules"] = [
                str(r) for r in data["ignore_rules"]
            ]
        return cls(**kwargs)

    @classmethod
    def from_env(cls) -> Config:
        """Create config from environment variables."""
        kwargs: dict = {}
        if threshold := os.environ.get(
            "PRITHVI_SEVERITY_THRESHOLD",
        ):
            kwargs["severity_threshold"] = Severity(
                threshold.upper(),
            )
        if max_layer := os.environ.get(
            "PRITHVI_MAX_LAYER_SIZE_MB",
        ):
            with contextlib.suppress(ValueError):
                kwargs["max_layer_size_mb"] = int(max_layer)
        if data_dir := os.environ.get("PRITHVI_DATA_DIR"):
            kwargs["data_dir"] = Path(data_dir)
        if fmt := os.environ.get("PRITHVI_OUTPUT_FORMAT"):
            kwargs["output_format"] = fmt
        if ignore := os.environ.get("PRITHVI_IGNORE_RULES"):
            kwargs["ignore_rules"] = [
                r.strip() for r in ignore.split(",")
            ]
        return cls(**kwargs)

    @classmethod
    def load(
        cls,
        config_path: str | Path | None = None,
        cli_overrides: dict | None = None,
    ) -> Config:
        """Merge config: file < env < CLI overrides.

        Args:
            config_path: Path to .prithvi.toml (or None
                for auto-discovery).
            cli_overrides: Dict of CLI-provided values.
                None values are ignored.

        Returns:
            Merged Config instance.
        """
        file_cfg = cls.from_file(config_path)
        env_cfg = cls.from_env()
        defaults = cls()

        merged: dict = {}
        for fld in (
            "severity_threshold",
            "max_layer_size_mb",
            "data_dir",
            "output_format",
            "ignore_rules",
        ):
            file_val = getattr(file_cfg, fld)
            env_val = getattr(env_cfg, fld)
            default_val = getattr(defaults, fld)

            # Start with file value
            val = file_val

            # Env overrides file if env differs from default
            if env_val != default_val:
                val = env_val

            merged[fld] = val

        # CLI overrides everything
        if cli_overrides:
            for k, v in cli_overrides.items():
                if v is not None:
                    merged[k] = v

        return cls(**merged)
