"""HTML report output using Jinja2."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from prithvi.models import ScanResult
from prithvi.reporting.base import BaseReporter

TEMPLATE_DIR = Path(__file__).parent / "templates"


class HtmlReporter(BaseReporter):
    """Render scan results as a self-contained HTML file."""

    def render(self, result: ScanResult) -> str:
        env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True)
        template = env.get_template("report.html.j2")
        return template.render(
            result=result,
            severity_counts=result.severity_counts,
            total=len(result.findings),
        )
