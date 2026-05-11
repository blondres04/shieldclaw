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

from shieldclaw.models import SASTFindingReport, ScanResult, has_mvp_supported_cwe

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


_DETONATION_VERDICTS = frozenset({"TRUE_POSITIVE", "FALSE_POSITIVE", "INCONCLUSIVE"})


def _mvp_support_metadata(finding: SASTFindingReport) -> dict[str, str]:
    """Describe whether a finding is inside the default SQLi-only MVP boundary."""
    if has_mvp_supported_cwe(finding.cwe):
        return {
            "mvp_support": "SUPPORTED_SQLI",
            "mvp_support_reason": (
                "CWE-89 SQL injection is the only default MVP-supported validation class."
            ),
        }
    if finding.triage_verdict == "DYNAMICALLY_VERIFIABLE":
        return {
            "mvp_support": "DEFERRED_NON_MVP",
            "mvp_support_reason": (
                "The active CWE config treats this as dynamically verifiable, but it is "
                "outside the default SQLi-only MVP claim."
            ),
        }
    if finding.triage_verdict == "OUT_OF_SCOPE":
        return {
            "mvp_support": "OUT_OF_SCOPE",
            "mvp_support_reason": "Out-of-scope findings are visible but not validated.",
        }
    if finding.triage_verdict == "STATIC_ONLY":
        return {
            "mvp_support": "STATIC_ONLY",
            "mvp_support_reason": "Static-only findings are visible but not detonated.",
        }
    return {
        "mvp_support": "UNKNOWN",
        "mvp_support_reason": "MVP support could not be determined from the report entry.",
    }


def _outcome_metadata(finding: SASTFindingReport) -> dict[str, str]:
    """Return a stable operator-facing outcome label and explanation."""
    if finding.verdict in _DETONATION_VERDICTS:
        summary = finding.verdict_summary or "Detonation completed."
        if finding.verdict == "TRUE_POSITIVE":
            summary = (
                "TRUE_POSITIVE required exit-code evidence plus Tier-2 corroboration. " + summary
            )
        return {
            "outcome": finding.verdict,
            "outcome_kind": "DETONATION_VERDICT",
            "outcome_summary": summary,
        }

    if finding.state == "REJECTED":
        return {
            "outcome": "REJECTED",
            "outcome_kind": "NO_DETONATION",
            "outcome_summary": (
                "No PoC was generated or detonated because the operator rejected approval."
            ),
        }

    if finding.state == "REFUSED" or finding.verdict == "REFUSED":
        return {
            "outcome": "REFUSED",
            "outcome_kind": "NO_DETONATION",
            "outcome_summary": finding.verdict_summary
            or "The LLM refused to generate a PoC; no detonation verdict exists.",
        }

    if finding.state == "AWAITING_APPROVAL" or finding.state == "SCORED":
        return {
            "outcome": "AWAITING_APPROVAL",
            "outcome_kind": "PENDING_OPERATOR_DECISION",
            "outcome_summary": "Scoring is complete; operator approval is required.",
        }

    support = _mvp_support_metadata(finding)
    if support["mvp_support"] in {"DEFERRED_NON_MVP", "STATIC_ONLY", "OUT_OF_SCOPE"}:
        return {
            "outcome": support["mvp_support"],
            "outcome_kind": "NO_DETONATION",
            "outcome_summary": support["mvp_support_reason"],
        }

    return {
        "outcome": finding.state,
        "outcome_kind": "PIPELINE_STATE",
        "outcome_summary": finding.verdict_summary or finding.triage_reason or finding.state,
    }


def _finding_report_dict(finding: SASTFindingReport) -> dict[str, Any]:
    """Serialize a finding and attach derived SQLi MVP outcome metadata."""
    payload = _jsonable(finding)
    assert isinstance(payload, dict)
    payload.update(_mvp_support_metadata(finding))
    payload.update(_outcome_metadata(finding))
    return payload


class ReportBuilder:
    """Turns scan outcomes into stable operator-facing report formats."""

    def build(self, result: ScanResult, *, output_format: str = "json") -> str:
        """Serialize a ``ScanResult`` into the requested report format."""
        normalized = output_format.lower()
        if normalized == "json":
            payload = _jsonable(result)
            assert isinstance(payload, dict)
            if result.findings is not None:
                payload["findings"] = [_finding_report_dict(finding) for finding in result.findings]
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
                        **_mvp_support_metadata(finding),
                        **_outcome_metadata(finding),
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
            group = _outcome_metadata(finding)["outcome"]
            grouped.setdefault(group, []).append(finding)

        for group_name in sorted(grouped):
            lines.extend(["", f"## {group_name}", ""])
            for finding in grouped[group_name]:
                support = _mvp_support_metadata(finding)
                outcome = _outcome_metadata(finding)
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
                        f"- mvp_support: {support['mvp_support']}",
                        f"- mvp_support_reason: {support['mvp_support_reason']}",
                        f"- outcome_kind: {outcome['outcome_kind']}",
                        f"- outcome: {outcome['outcome']}",
                        f"- outcome_summary: {outcome['outcome_summary']}",
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
