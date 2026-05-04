"""Serialize ``ScanResult`` into JSON, SARIF, or markdown reports."""

from __future__ import annotations

import json
import logging
import sys
from dataclasses import fields, is_dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import UUID

from shieldclaw.models import SASTFindingReport, ScanResult

_LOG = logging.getLogger(__name__)
_SARIF_SCHEMA_URI = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)


def _jsonable(value: Any) -> Any:
    """Recursively convert values into JSON-serializable primitives."""
    if value is None:
        return None
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return {f.name: _jsonable(getattr(value, f.name)) for f in fields(value)}
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _sarif_level(severity: str) -> str:
    """Map ShieldClaw severities to SARIF result levels."""
    if severity == "ERROR":
        return "error"
    if severity == "WARNING":
        return "warning"
    return "note"


def _finding_message(finding: SASTFindingReport) -> str:
    """Return the most useful human-readable summary for a finding."""
    return finding.verdict_summary or finding.triage_reason or finding.rule_id


class ReportBuilder:
    """Turns scan outcomes into stable operator-facing report formats."""

    def build(self, result: ScanResult, *, output_format: str = "json") -> str:
        """Serialize a ``ScanResult`` into the requested report format."""
        normalized = output_format.lower()
        if normalized == "json":
            payload = _jsonable(result)
            assert isinstance(payload, dict)
            return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        if normalized == "sarif":
            return self._build_sarif(result)
        if normalized == "markdown":
            return self._build_markdown(result)
        raise ValueError(f"Unsupported output format: {output_format!r}")

    def write(self, report: str, output_path: str | None) -> None:
        """Emit a report to a file or standard output."""
        if output_path is None:
            sys.stdout.write(report)
            return
        try:
            Path(output_path).expanduser().write_text(report, encoding="utf-8")
        except OSError as exc:
            _LOG.error("Failed to write report to %s: %s", output_path, exc)
            sys.stdout.write(report)

    def _build_sarif(self, result: ScanResult) -> str:
        """Serialize findings as a SARIF 2.1.0 document."""
        findings = list(result.findings or ())
        rules: list[dict[str, Any]] = []
        rule_indices: dict[str, int] = {}
        results: list[dict[str, Any]] = []

        for finding in findings:
            if finding.rule_id not in rule_indices:
                rule_indices[finding.rule_id] = len(rules)
                rules.append(
                    {
                        "id": finding.rule_id,
                        "name": finding.rule_id,
                        "shortDescription": {"text": finding.rule_id},
                        "fullDescription": {"text": _finding_message(finding)},
                        "properties": {"tags": [finding.severity, *finding.cwe]},
                    }
                )

            results.append(
                {
                    "ruleId": finding.rule_id,
                    "ruleIndex": rule_indices[finding.rule_id],
                    "level": _sarif_level(finding.severity),
                    "message": {"text": _finding_message(finding)},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": finding.path},
                                "region": {
                                    "startLine": finding.start_line,
                                    "endLine": finding.end_line,
                                },
                            }
                        }
                    ],
                    "partialFingerprints": {
                        "shieldclaw/finding_id": str(finding.finding_id),
                    },
                    "properties": {
                        "state": finding.state,
                        "triage_verdict": finding.triage_verdict,
                        "triage_reason": finding.triage_reason,
                        "verdict": finding.verdict,
                        "verdict_confidence": finding.verdict_confidence,
                        "verdict_summary": finding.verdict_summary,
                        "cwe": list(finding.cwe),
                        "observer_warnings": _jsonable(finding.observer_warnings),
                    },
                }
            )

        payload = {
            "$schema": _SARIF_SCHEMA_URI,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "ShieldClaw",
                            "rules": rules,
                        }
                    },
                    "results": results,
                    "properties": {
                        "result_id": str(result.result_id),
                        "scan_id": str(result.scan_id) if result.scan_id is not None else None,
                        "pipeline_error": result.pipeline_error,
                        "duration_seconds": result.duration_seconds,
                    },
                }
            ],
        }
        return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"

    def _build_markdown(self, result: ScanResult) -> str:
        """Render a human-readable markdown summary grouped by verdict/state."""
        lines = [
            "# ShieldClaw Report",
            "",
            f"- result_id: {result.result_id}",
            f"- scan_id: {result.scan_id if result.scan_id is not None else 'none'}",
            f"- pipeline_error: {result.pipeline_error or 'none'}",
            (
                f"- duration_seconds: {result.duration_seconds}"
                if result.duration_seconds is not None
                else "- duration_seconds: none"
            ),
        ]

        findings = list(result.findings or ())
        if not findings:
            lines.extend(["", "No findings in report."])
            return "\n".join(lines) + "\n"

        grouped: dict[str, list[SASTFindingReport]] = {}
        for finding in findings:
            group = finding.verdict or finding.state
            grouped.setdefault(group, []).append(finding)

        for group_name in sorted(grouped):
            lines.extend(["", f"## {group_name}", ""])
            for finding in grouped[group_name]:
                lines.extend(
                    [
                        f"### {finding.rule_id}",
                        f"- location: {finding.path}:{finding.start_line}-{finding.end_line}",
                        f"- severity: {finding.severity}",
                        f"- state: {finding.state}",
                        f"- cwe: {', '.join(finding.cwe) if finding.cwe else 'none'}",
                        f"- triage_verdict: {finding.triage_verdict or 'none'}",
                        f"- triage_reason: {finding.triage_reason or 'none'}",
                        f"- verdict: {finding.verdict or 'none'}",
                        (
                            f"- verdict_confidence: {finding.verdict_confidence}"
                            if finding.verdict_confidence is not None
                            else "- verdict_confidence: none"
                        ),
                        f"- verdict_summary: {finding.verdict_summary or 'none'}",
                    ]
                )
                if finding.observer_warnings:
                    lines.append("- observer_warnings:")
                    for warning in finding.observer_warnings:
                        lines.append(f"  - {warning.observer_name}: {warning.message}")
                else:
                    lines.append("- observer_warnings: none")
                lines.append("")

        while lines and lines[-1] == "":
            lines.pop()
        normalized_lines: list[str] = []
        for line in lines:
            if line == "" and normalized_lines and normalized_lines[-1] == "":
                continue
            normalized_lines.append(line)
        return "\n".join(normalized_lines) + "\n"
