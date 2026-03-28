"""Rich table report output."""

from __future__ import annotations

from io import StringIO

from rich.console import Console
from rich.table import Table
from rich.text import Text

from prithvi.models import ScanResult, Severity
from prithvi.reporting.base import BaseReporter

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


class TableReporter(BaseReporter):
    """Render scan results as a rich CLI table."""

    def render(self, result: ScanResult) -> str:
        buf = StringIO()
        console = Console(file=buf, force_terminal=True, width=120)

        # Header
        console.print()
        console.print(f"[bold]Prithvi Scan Report[/bold] - {result.target}")
        console.print(f"Type: {result.scan_type} | Findings: {len(result.findings)}")

        # Summary bar
        counts = result.severity_counts
        parts = []
        for sev in Severity:
            count = counts[sev.value]
            if count > 0:
                color = SEVERITY_COLORS[sev]
                parts.append(f"[{color}]{sev.value}: {count}[/{color}]")
        if parts:
            console.print(" | ".join(parts))
        else:
            console.print("[green]No issues found![/green]")
        console.print()

        if not result.findings:
            return buf.getvalue()

        # Findings table
        table = Table(show_header=True, header_style="bold", expand=True)
        table.add_column("Rule", style="dim", width=8)
        table.add_column("Severity", width=10)
        table.add_column("Title", width=35)
        table.add_column("Location", width=20)
        table.add_column("Description", width=45)

        for finding in result.findings:
            color = SEVERITY_COLORS[finding.severity]
            table.add_row(
                finding.rule_id,
                Text(finding.severity.value, style=color),
                finding.title,
                finding.location,
                finding.description,
            )

        console.print(table)
        return buf.getvalue()
