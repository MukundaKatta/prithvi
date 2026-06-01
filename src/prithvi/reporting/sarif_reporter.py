"""SARIF v2.1.0 report output."""

from __future__ import annotations

import json
import re

from prithvi import __version__
from prithvi.models import ScanResult, Severity
from prithvi.reporting.base import BaseReporter

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/"
    "sarif-spec/main/sarif-2.1/"
    "schema/sarif-schema-2.1.0.json"
)

_SEVERITY_MAP: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

_LEVEL_FOR_CONFIG = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

_LOC_RE = re.compile(r"^(.+):(\d+)$")


def _parse_location(raw: str) -> dict:
    """Parse 'file:line' into a SARIF physical location."""
    m = _LOC_RE.match(raw)
    if m:
        return {
            "physicalLocation": {
                "artifactLocation": {"uri": m.group(1)},
                "region": {
                    "startLine": int(m.group(2)),
                },
            }
        }
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": raw},
        }
    }


class SarifReporter(BaseReporter):
    """Render scan results as SARIF v2.1.0 JSON."""

    def render(self, result: ScanResult) -> str:
        rules: list[dict] = []
        rule_indices: dict[str, int] = {}
        results: list[dict] = []

        for finding in result.findings:
            if finding.rule_id not in rule_indices:
                idx = len(rules)
                rule_indices[finding.rule_id] = idx
                level = _LEVEL_FOR_CONFIG[finding.severity]
                rules.append({
                    "id": finding.rule_id,
                    "shortDescription": {
                        "text": finding.title,
                    },
                    "defaultConfiguration": {
                        "level": level,
                    },
                })

            sarif_result: dict = {
                "ruleId": finding.rule_id,
                "ruleIndex": rule_indices[finding.rule_id],
                "level": _SEVERITY_MAP[finding.severity],
                "message": {"text": finding.description},
                "locations": [_parse_location(finding.location)],
            }
            results.append(sarif_result)

        sarif = {
            "$schema": _SARIF_SCHEMA,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Prithvi",
                            "version": __version__,
                            "rules": rules,
                        },
                    },
                    "results": results,
                }
            ],
        }
        return json.dumps(sarif, indent=2)
