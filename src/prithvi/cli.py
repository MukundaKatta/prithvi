"""Prithvi CLI - Container Security Scanner."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from prithvi import __version__
from prithvi.models import Severity


@click.group()
@click.version_option(version=__version__, prog_name="prithvi")
def main() -> None:
    """Prithvi - Container Security Scanner.

    Analyze Dockerfiles and container images for security vulnerabilities
    and best-practice violations.
    """


@main.group()
def scan() -> None:
    """Run security scans."""


@scan.command("dockerfile")
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--format", "-f",
    "output_format",
    type=click.Choice(["table", "json", "html"]),
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
    type=click.Choice([s.value for s in Severity], case_sensitive=False),
    default="LOW",
    help="Minimum severity to report.",
)
@click.option(
    "--ignore", "-i",
    multiple=True,
    help="Rule IDs to ignore (can be repeated).",
)
def scan_dockerfile(
    path: str,
    output_format: str,
    output: str | None,
    severity_threshold: str,
    ignore: tuple[str, ...],
) -> None:
    """Scan a Dockerfile for security issues."""
    from prithvi.dockerfile.analyzer import analyze_dockerfile
    from prithvi.reporting import get_reporter

    result = analyze_dockerfile(path, ignore_rules=list(ignore))
    threshold = Severity(severity_threshold.upper())

    # Filter by threshold
    result.findings = [f for f in result.findings if f.severity >= threshold]

    reporter = get_reporter(output_format)
    report = reporter.render(result)

    if output:
        Path(output).write_text(report)
        click.echo(f"Report written to {output}")
    else:
        click.echo(report)

    # Exit with non-zero if findings above threshold
    if result.has_high_or_above:
        sys.exit(1)


@scan.command("image")
@click.argument("target")
@click.option("--format", "-f", "output_format", type=click.Choice(["table", "json", "html"]), default="table")
@click.option("--output", "-o", type=click.Path(), default=None)
def scan_image(target: str, output_format: str, output: str | None) -> None:
    """Scan a container image for vulnerabilities."""
    from prithvi.image.analyzer import analyze_image
    from prithvi.reporting import get_reporter

    result = analyze_image(target)

    reporter = get_reporter(output_format)
    report = reporter.render(result)

    if output:
        Path(output).write_text(report)
        click.echo(f"Report written to {output}")
    else:
        click.echo(report)

    if result.has_high_or_above:
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
