"""Container image inspection - extract metadata and filesystem info."""

from __future__ import annotations

import json
import tarfile
import tempfile
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class LayerInfo:
    """Information about a single image layer."""

    digest: str
    size_bytes: int
    command: str = ""


@dataclass
class ImageMetadata:
    """Extracted image metadata."""

    name: str
    layers: list[LayerInfo] = field(default_factory=list)
    os: str = ""
    architecture: str = ""
    env_vars: list[str] = field(default_factory=list)
    exposed_ports: list[str] = field(default_factory=list)
    user: str = ""
    entrypoint: list[str] = field(default_factory=list)
    cmd: list[str] = field(default_factory=list)


def inspect_tarball(tar_path: str | Path) -> ImageMetadata:
    """Inspect a Docker image saved as a tarball (docker save output).

    Args:
        tar_path: Path to the .tar file.

    Returns:
        ImageMetadata with layer info and config.
    """
    tar_path = Path(tar_path)
    if not tar_path.exists():
        raise FileNotFoundError(f"Image tarball not found: {tar_path}")

    with tempfile.TemporaryDirectory() as tmpdir:
        with tarfile.open(tar_path, "r") as tar:
            tar.extractall(tmpdir, filter="data")

        tmppath = Path(tmpdir)

        # Read manifest
        manifest_path = tmppath / "manifest.json"
        if not manifest_path.exists():
            raise ValueError("Invalid Docker image tarball: missing manifest.json")

        manifest = json.loads(manifest_path.read_text())
        config_file = manifest[0].get("Config", "")
        layer_paths = manifest[0].get("Layers", [])
        repo_tags = manifest[0].get("RepoTags", [])

        name = repo_tags[0] if repo_tags else tar_path.stem

        # Read config
        config = {}
        if config_file:
            config_path = tmppath / config_file
            if config_path.exists():
                config = json.loads(config_path.read_text())

        container_config = config.get("config", {})

        # Build layer info
        layers: list[LayerInfo] = []
        history = config.get("history", [])
        for idx, layer_path in enumerate(layer_paths):
            layer_file = tmppath / layer_path
            size = layer_file.stat().st_size if layer_file.exists() else 0
            cmd = ""
            if idx < len(history):
                cmd = history[idx].get("created_by", "")
            layers.append(LayerInfo(digest=layer_path, size_bytes=size, command=cmd))

        return ImageMetadata(
            name=name,
            layers=layers,
            os=config.get("os", ""),
            architecture=config.get("architecture", ""),
            env_vars=container_config.get("Env", []),
            exposed_ports=list((container_config.get("ExposedPorts") or {}).keys()),
            user=container_config.get("User", ""),
            entrypoint=container_config.get("Entrypoint") or [],
            cmd=container_config.get("Cmd") or [],
        )


def inspect_daemon(image_name: str) -> ImageMetadata:
    """Inspect an image via the Docker daemon.

    Requires docker Python package and a running Docker daemon.
    """
    try:
        import docker
    except ImportError as err:
        raise RuntimeError(
            "Docker Python package is required for daemon mode. "
            "Install with: pip install prithvi[image]"
        ) from err

    client = docker.from_env()
    try:
        image = client.images.get(image_name)
    except docker.errors.ImageNotFound as err:
        raise ValueError(
            f"Image not found: {image_name}"
        ) from err

    attrs = image.attrs
    config = attrs.get("Config", {})
    history = image.history()

    layers = []
    for entry in history:
        layers.append(LayerInfo(
            digest=entry.get("Id", "")[:20],
            size_bytes=entry.get("Size", 0),
            command=entry.get("CreatedBy", ""),
        ))

    return ImageMetadata(
        name=image_name,
        layers=layers,
        os=attrs.get("Os", ""),
        architecture=attrs.get("Architecture", ""),
        env_vars=config.get("Env", []),
        exposed_ports=list((config.get("ExposedPorts") or {}).keys()),
        user=config.get("User", ""),
        entrypoint=config.get("Entrypoint") or [],
        cmd=config.get("Cmd") or [],
    )
