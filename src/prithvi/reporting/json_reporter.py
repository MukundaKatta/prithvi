"""JSON report output."""

from __future__ import annotations

import json

from prithvi.models import ScanResult
from prithvi.reporting.base import BaseReporter


class JsonReporter(BaseReporter):
    """Render scan results as JSON."""

    def render(self, result: ScanResult) -> str:
        data = {
            "target": result.target,
            "scan_type": result.scan_type,
            "summary": result.severity_counts,
            "total_findings": len(result.findings),
            "started_at": result.started_at.isoformat(),
            "finished_at": result.finished_at.isoformat() if result.finished_at else None,
            "metadata": result.metadata,
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "description": f.description,
                    "location": f.location,
                    "remediation": f.remediation,
                }
                for f in result.findings
            ],
        }
        return json.dumps(data, indent=2)
