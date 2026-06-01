"""Prithvi CLI - Container Security Scanner."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from prithvi import __version__
from prithvi.models import Severity


def _quiet_summary(result) -> str:
    """Build a one-line quiet-mode summary string."""
    total = len(result.findings)
    if total == 0:
        return "PASS: 0 findings"
    counts = result.severity_counts
    parts = [
        f"{v} {k}"
        for k, v in counts.items()
        if v > 0
    ]
    detail = ", ".join(parts)
    return f"FAIL: {total} findings ({detail})"


@click.group()
@click.version_option(version=__version__, prog_name="prithvi")
def main() -> None:
    """Prithvi - Container Security Scanner.

    Analyze Dockerfiles and container images for
    security vulnerabilities and best-practice violations.
    """


@main.group()
def scan() -> None:
    """Run security scans."""


@scan.command("dockerfile")
@click.argument("path", type=click.Path())
@click.option(
    "--format", "-f",
    "output_format",
    type=click.Choice(["table", "json", "html", "sarif"]),
    default="table",
    help="Output format.",
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    default=None,
    help="Write report to file instead of stdout.",
)
@click.option(
    "--severity-threshold", "-s",
    type=click.Choice(
        [s.value for s in Severity],
        case_sensitive=False,
    ),
    default="LOW",
    help="Minimum severity to report.",
)
@click.option(
    "--ignore", "-i",
    multiple=True,
    help="Rule IDs to ignore (can be repeated).",
)
@click.option(
    "--quiet", "-q",
    is_flag=True,
    default=False,
    help="Only print a one-line pass/fail summary.",
)
def scan_dockerfile(
    path: str,
    output_format: str,
    output: str | None,
    severity_threshold: str,
    ignore: tuple[str, ...],
    quiet: bool,
) -> None:
    """Scan a Dockerfile for security issues."""
    from prithvi.dockerfile.analyzer import (
        analyze_dockerfile,
        analyze_dockerfile_content,
    )
    from prithvi.reporting import get_reporter

    if path == "-":
        content = sys.stdin.read()
        result = analyze_dockerfile_content(
            content, name="<stdin>", ignore_rules=list(ignore),
        )
    else:
        real = Path(path)
        if not real.exists():
            raise click.BadParameter(
                f"Path '{path}' does not exist.",
                param_hint="'PATH'",
            )
        result = analyze_dockerfile(
            path, ignore_rules=list(ignore),
        )

    threshold = Severity(severity_threshold.upper())

    result.findings = [
        f for f in result.findings if f.severity >= threshold
    ]

    if quiet:
        click.echo(_quiet_summary(result))
    else:
        reporter = get_reporter(output_format)
        report = reporter.render(result)
        if output:
            Path(output).write_text(report)
            click.echo(f"Report written to {output}")
        else:
            click.echo(report)

    if result.findings:
        sys.exit(1)


@scan.command("image")
@click.argument("target")
@click.option(
    "--format", "-f", "output_format",
    type=click.Choice(["table", "json", "html", "sarif"]),
    default="table",
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    default=None,
)
@click.option(
    "--severity-threshold", "-s",
    type=click.Choice(
        [s.value for s in Severity],
        case_sensitive=False,
    ),
    default="LOW",
    help="Minimum severity to report.",
)
@click.option(
    "--quiet", "-q",
    is_flag=True,
    default=False,
    help="Only print a one-line pass/fail summary.",
)
def scan_image(
    target: str,
    output_format: str,
    output: str | None,
    severity_threshold: str,
    quiet: bool,
) -> None:
    """Scan a container image for vulnerabilities."""
    from prithvi.image.analyzer import analyze_image
    from prithvi.reporting import get_reporter

    result = analyze_image(target)
    threshold = Severity(severity_threshold.upper())

    result.findings = [
        f for f in result.findings if f.severity >= threshold
    ]

    if quiet:
        click.echo(_quiet_summary(result))
    else:
        reporter = get_reporter(output_format)
        report = reporter.render(result)
        if output:
            Path(output).write_text(report)
            click.echo(f"Report written to {output}")
        else:
            click.echo(report)

    if result.findings:
        sys.exit(1)


@main.command("rules")
def list_rules() -> None:
    """List all available security rules."""
    from rich.console import Console
    from rich.table import Table

    from prithvi.dockerfile.rules import get_all_rules

    console = Console()
    table = Table(title="Prithvi Security Rules", show_header=True, header_style="bold")
    table.add_column("ID", style="dim", width=8)
    table.add_column("Severity", width=10)
    table.add_column("Title", width=40)
    table.add_column("Description")

    for rule in get_all_rules():
        table.add_row(rule.rule_id, rule.severity.value, rule.title, rule.description)

    console.print(table)


if __name__ == "__main__":
    main()
