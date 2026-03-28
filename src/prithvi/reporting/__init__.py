"""Report generation for scan results."""

from __future__ import annotations

from prithvi.reporting.json_reporter import JsonReporter
from prithvi.reporting.table_reporter import TableReporter
from prithvi.reporting.html_reporter import HtmlReporter

REPORTERS = {
    "json": JsonReporter,
    "table": TableReporter,
    "html": HtmlReporter,
}


def get_reporter(format_name: str):
    """Get a reporter by format name."""
    reporter_cls = REPORTERS.get(format_name)
    if not reporter_cls:
        raise ValueError(f"Unknown format: {format_name}. Choose from: {', '.join(REPORTERS)}")
    return reporter_cls()
