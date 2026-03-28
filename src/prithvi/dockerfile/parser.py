"""Dockerfile parser that produces a list of instructions."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Instruction:
    """A single Dockerfile instruction."""

    keyword: str
    arguments: str
    line_number: int
    raw: str


def parse_dockerfile(content: str) -> list[Instruction]:
    """Parse Dockerfile content into a list of instructions.

    Handles continuation lines (backslash), comments, and blank lines.
    """
    instructions: list[Instruction] = []
    lines = content.splitlines()
    i = 0

    while i < len(lines):
        line = lines[i].strip()

        # Skip blank lines and comments
        if not line or line.startswith("#"):
            i += 1
            continue

        # Handle continuation lines
        start_line = i + 1  # 1-indexed
        full_line = line
        while full_line.endswith("\\") and i + 1 < len(lines):
            i += 1
            full_line = full_line[:-1] + " " + lines[i].strip()

        # Split into keyword and arguments
        parts = full_line.split(None, 1)
        if parts:
            keyword = parts[0].upper()
            arguments = parts[1] if len(parts) > 1 else ""
            instructions.append(
                Instruction(
                    keyword=keyword,
                    arguments=arguments,
                    line_number=start_line,
                    raw=full_line,
                )
            )

        i += 1

    return instructions
