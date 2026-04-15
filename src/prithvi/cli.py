"""`prithvi` CLI.

    prithvi scan Dockerfile
    prithvi scan path/Dockerfile --min high
    prithvi scan Dockerfile --json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .core import Scanner, Severity


_LEVELS = {s.value: i for i, s in enumerate([Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO])}


def _cmd_scan(args: argparse.Namespace) -> int:
    path = Path(args.path)
    if not path.exists():
        print(f"error: {path} not found", file=sys.stderr)
        return 2
    findings = Scanner().scan(path.read_text(encoding="utf-8"))

    min_rank = _LEVELS[args.min.lower()] if args.min else _LEVELS[Severity.INFO.value]
    findings = [f for f in findings if _LEVELS[f.severity.value] <= min_rank]

    if args.json:
        print(
            json.dumps(
                [
                    {
                        "rule_id": f.rule_id,
                        "severity": f.severity.value,
                        "line": f.line,
                        "message": f.message,
                        "hint": f.hint,
                    }
                    for f in findings
                ],
                indent=2,
            )
        )
    else:
        if not findings:
            print(f"✔ {path}: no findings at severity >= {args.min or 'info'}")
        else:
            for f in findings:
                print(f.pretty())
            counts = {s.value: 0 for s in Severity}
            for f in findings:
                counts[f.severity.value] += 1
            parts = [f"{v} {k}" for k, v in counts.items() if v]
            print()
            print(f"{len(findings)} findings: {', '.join(parts)}")

    # Non-zero exit when we hit the fail threshold (default: any finding at
    # HIGH or above).
    fail_rank = _LEVELS[args.fail_on.lower()] if args.fail_on else _LEVELS[Severity.HIGH.value]
    if any(_LEVELS[f.severity.value] <= fail_rank for f in findings):
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="prithvi", description="Static security scanner for Dockerfiles.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Scan a Dockerfile.")
    p_scan.add_argument("path", help="Path to a Dockerfile.")
    p_scan.add_argument("--min", choices=[s.value for s in Severity], help="Suppress findings below this severity.")
    p_scan.add_argument("--fail-on", choices=[s.value for s in Severity],
                        help="Exit non-zero if any finding >= this severity (default: high).")
    p_scan.add_argument("--json", action="store_true", help="Emit JSON instead of human-readable output.")
    p_scan.set_defaults(func=_cmd_scan)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
