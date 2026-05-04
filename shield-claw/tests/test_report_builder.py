"""Tests for ``ReportBuilder`` JSON serialization."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest
from pytest_mock import MockerFixture

from shieldclaw.models import (
    ContainerState,
    ContainerStatus,
    ExploitPayload,
    ObserverWarning,
    SASTFindingReport,
    ScanResult,
)
from shieldclaw.reporting.builder import ReportBuilder

_SARIF_SCHEMA = Path(__file__).parent / "fixtures" / "sarif-schema-2.1.0.json"


def _sample_sast_result() -> ScanResult:
    return ScanResult(
        result_id=uuid.UUID("aaaaaaaa-bbbb-4ccc-dddd-eeeeeeeeeeee"),
        scan_id=uuid.UUID("99999999-8888-4777-9666-555555555555"),
        duration_seconds=4.2,
        findings=(
            SASTFindingReport(
                finding_id=uuid.UUID("11111111-2222-4333-8444-555555555555"),
                rule_id="python.flask.sqli",
                severity="ERROR",
                path="app.py",
                start_line=42,
                end_line=42,
                cwe=("CWE-89",),
                state="VERDICTED",
                triage_verdict="DYNAMICALLY_VERIFIABLE",
                triage_reason="SQL injection is dynamically verifiable",
                verdict="TRUE_POSITIVE",
                verdict_confidence=0.9,
                verdict_summary="Exit code and logs confirm exploitability.",
                observer_warnings=(
                    ObserverWarning(
                        observer_name="target_logs",
                        message="log stream unavailable",
                    ),
                ),
            ),
            SASTFindingReport(
                finding_id=uuid.UUID("66666666-7777-4888-9999-000000000000"),
                rule_id="python.flask.cmdi",
                severity="WARNING",
                path="worker.py",
                start_line=18,
                end_line=18,
                cwe=("CWE-78",),
                state="REJECTED",
                triage_verdict="DYNAMICALLY_VERIFIABLE",
                triage_reason="Command injection is dynamically verifiable",
                verdict=None,
                verdict_confidence=None,
                verdict_summary=None,
                observer_warnings=(),
            ),
        ),
    )


def test_build_full_vulnerable_result() -> None:
    """A populated scan should round-trip through JSON with expected keys."""
    rid = uuid.UUID("aaaaaaaa-bbbb-4ccc-dddd-eeeeeeeeeeee")
    pid = uuid.UUID("11111111-2222-4333-8444-555555555555")
    payload = ExploitPayload(
        payload_id=pid,
        raw_code="import sys\nsys.exit(0)\n",
        target_dns="web",
        execution_command="python -",
        language="python",
    )
    state = ContainerState(
        status=ContainerStatus.STOPPED,
        attacker_container_id="abc123",
        startup_logs="done\n",
    )
    result = ScanResult(
        result_id=rid,
        exit_code=0,
        is_vulnerable=True,
        pipeline_error=None,
        duration_seconds=3.5,
        exploit_payload=payload,
        container_state=state,
    )
    raw = ReportBuilder().build(result)
    data = json.loads(raw)
    assert data["result_id"] == str(rid)
    assert data["exit_code"] == 0
    assert data["is_vulnerable"] is True
    assert data["pipeline_error"] is None
    assert data["duration_seconds"] == 3.5
    assert data["exploit_payload"]["payload_id"] == str(pid)
    assert data["exploit_payload"]["language"] == "python"
    assert data["container_state"]["status"] == "STOPPED"
    assert data["container_state"]["attacker_container_id"] == "abc123"


def test_build_failed_early_minimal_fields() -> None:
    """Early failures should serialize explicit nulls for absent stages."""
    rid = uuid.uuid4()
    result = ScanResult(
        result_id=rid,
        exit_code=None,
        is_vulnerable=None,
        pipeline_error="LLM refused request",
        duration_seconds=None,
        exploit_payload=None,
        container_state=None,
    )
    raw = ReportBuilder().build(result)
    data = json.loads(raw)
    assert data["result_id"] == str(rid)
    assert data["exit_code"] is None
    assert data["is_vulnerable"] is None
    assert data["pipeline_error"] == "LLM refused request"
    assert data["duration_seconds"] is None
    assert data["exploit_payload"] is None
    assert data["container_state"] is None


def test_write_to_stdout(capsys) -> None:
    """``output_path=None`` should mirror JSON to stdout."""
    result = ScanResult(result_id=uuid.uuid4(), exit_code=1)
    builder = ReportBuilder()
    report = builder.build(result)
    builder.write(report, None)
    captured = capsys.readouterr().out
    assert captured == report


def test_write_creates_file(tmp_path: Path) -> None:
    """Happy path file writes should persist UTF-8 JSON."""
    out = tmp_path / "report.json"
    result = ScanResult(result_id=uuid.uuid4(), is_vulnerable=False)
    builder = ReportBuilder()
    report = builder.build(result)
    builder.write(report, str(out))
    assert out.read_text(encoding="utf-8") == report


def test_write_file_fallback_on_error(tmp_path: Path, mocker: MockerFixture, capsys) -> None:
    """Broken file paths should log an error and still print JSON."""
    result = ScanResult(result_id=uuid.uuid4())
    report = ReportBuilder().build(result)
    bad_path = tmp_path / "missing" / "nested" / "out.json"
    log_mock = mocker.patch("shieldclaw.reporting.builder._LOG.error")
    ReportBuilder().write(report, str(bad_path))
    log_mock.assert_called_once()
    assert json.loads(capsys.readouterr().out) == json.loads(report)


def test_build_sast_report_includes_observer_warnings_per_finding() -> None:
    """SAST findings should serialize failed observer warnings in report output."""
    result = ScanResult(
        result_id=uuid.uuid4(),
        scan_id=uuid.UUID("aaaaaaaa-bbbb-4ccc-dddd-eeeeeeeeeeee"),
        findings=(
            SASTFindingReport(
                finding_id=uuid.UUID("11111111-2222-4333-8444-555555555555"),
                rule_id="python.flask.sqli",
                severity="ERROR",
                path="app.py",
                start_line=42,
                end_line=42,
                cwe=("CWE-89",),
                state="VERDICTED",
                triage_verdict="DYNAMICALLY_VERIFIABLE",
                triage_reason="SQL injection is dynamically verifiable",
                verdict="TRUE_POSITIVE",
                verdict_confidence=0.9,
                verdict_summary="Exit code and logs confirm exploitability.",
                observer_warnings=(
                    ObserverWarning(
                        observer_name="target_logs",
                        message="log stream unavailable",
                    ),
                ),
            ),
        ),
    )

    data = json.loads(ReportBuilder().build(result))

    assert data["findings"][0]["observer_warnings"] == [
        {
            "message": "log stream unavailable",
            "observer_name": "target_logs",
        }
    ]


def test_build_sast_report_serializes_empty_observer_warnings() -> None:
    """Successful observer runs should serialize an empty warning list."""
    result = ScanResult(
        result_id=uuid.uuid4(),
        scan_id=uuid.UUID("aaaaaaaa-bbbb-4ccc-dddd-eeeeeeeeeeee"),
        findings=(
            SASTFindingReport(
                finding_id=uuid.UUID("11111111-2222-4333-8444-555555555555"),
                rule_id="python.flask.sqli",
                severity="ERROR",
                path="app.py",
                start_line=42,
                end_line=42,
                cwe=("CWE-89",),
                state="VERDICTED",
                triage_verdict="DYNAMICALLY_VERIFIABLE",
                triage_reason="SQL injection is dynamically verifiable",
                verdict="TRUE_POSITIVE",
                verdict_confidence=0.9,
                verdict_summary="Exit code confirms exploitability.",
                observer_warnings=(),
            ),
        ),
    )

    data = json.loads(ReportBuilder().build(result))

    assert data["findings"][0]["observer_warnings"] == []


def test_build_json_output_matches_snapshot() -> None:
    """Default JSON output should remain stable and include observer warnings."""
    result = _sample_sast_result()

    data = json.loads(ReportBuilder().build(result))

    assert data == {
        "container_state": None,
        "duration_seconds": 4.2,
        "exit_code": None,
        "exploit_payload": None,
        "findings": [
            {
                "cwe": ["CWE-89"],
                "end_line": 42,
                "finding_id": "11111111-2222-4333-8444-555555555555",
                "observer_warnings": [
                    {
                        "message": "log stream unavailable",
                        "observer_name": "target_logs",
                    }
                ],
                "path": "app.py",
                "rule_id": "python.flask.sqli",
                "severity": "ERROR",
                "start_line": 42,
                "state": "VERDICTED",
                "triage_reason": "SQL injection is dynamically verifiable",
                "triage_verdict": "DYNAMICALLY_VERIFIABLE",
                "verdict": "TRUE_POSITIVE",
                "verdict_confidence": 0.9,
                "verdict_summary": "Exit code and logs confirm exploitability.",
            },
            {
                "cwe": ["CWE-78"],
                "end_line": 18,
                "finding_id": "66666666-7777-4888-9999-000000000000",
                "observer_warnings": [],
                "path": "worker.py",
                "rule_id": "python.flask.cmdi",
                "severity": "WARNING",
                "start_line": 18,
                "state": "REJECTED",
                "triage_reason": "Command injection is dynamically verifiable",
                "triage_verdict": "DYNAMICALLY_VERIFIABLE",
                "verdict": None,
                "verdict_confidence": None,
                "verdict_summary": None,
            },
        ],
        "is_vulnerable": None,
        "pipeline_error": None,
        "result_id": "aaaaaaaa-bbbb-4ccc-dddd-eeeeeeeeeeee",
        "scan_id": "99999999-8888-4777-9666-555555555555",
    }


def test_build_sarif_output_matches_snapshot() -> None:
    """SARIF output should contain GitHub-uploadable findings and warnings."""
    result = _sample_sast_result()

    data = json.loads(ReportBuilder().build(result, output_format="sarif"))

    assert data == {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "runs": [
            {
                "properties": {
                    "duration_seconds": 4.2,
                    "pipeline_error": None,
                    "result_id": "aaaaaaaa-bbbb-4ccc-dddd-eeeeeeeeeeee",
                    "scan_id": "99999999-8888-4777-9666-555555555555",
                },
                "results": [
                    {
                        "level": "error",
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app.py"},
                                    "region": {"endLine": 42, "startLine": 42},
                                }
                            }
                        ],
                        "message": {"text": "Exit code and logs confirm exploitability."},
                        "partialFingerprints": {
                            "shieldclaw/finding_id": "11111111-2222-4333-8444-555555555555"
                        },
                        "properties": {
                            "cwe": ["CWE-89"],
                            "observer_warnings": [
                                {
                                    "message": "log stream unavailable",
                                    "observer_name": "target_logs",
                                }
                            ],
                            "state": "VERDICTED",
                            "triage_reason": "SQL injection is dynamically verifiable",
                            "triage_verdict": "DYNAMICALLY_VERIFIABLE",
                            "verdict": "TRUE_POSITIVE",
                            "verdict_confidence": 0.9,
                            "verdict_summary": "Exit code and logs confirm exploitability.",
                        },
                        "ruleId": "python.flask.sqli",
                        "ruleIndex": 0,
                    },
                    {
                        "level": "warning",
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "worker.py"},
                                    "region": {"endLine": 18, "startLine": 18},
                                }
                            }
                        ],
                        "message": {"text": "Command injection is dynamically verifiable"},
                        "partialFingerprints": {
                            "shieldclaw/finding_id": "66666666-7777-4888-9999-000000000000"
                        },
                        "properties": {
                            "cwe": ["CWE-78"],
                            "observer_warnings": [],
                            "state": "REJECTED",
                            "triage_reason": "Command injection is dynamically verifiable",
                            "triage_verdict": "DYNAMICALLY_VERIFIABLE",
                            "verdict": None,
                            "verdict_confidence": None,
                            "verdict_summary": None,
                        },
                        "ruleId": "python.flask.cmdi",
                        "ruleIndex": 1,
                    },
                ],
                "tool": {
                    "driver": {
                        "name": "ShieldClaw",
                        "rules": [
                            {
                                "fullDescription": {
                                    "text": "Exit code and logs confirm exploitability."
                                },
                                "id": "python.flask.sqli",
                                "name": "python.flask.sqli",
                                "properties": {"tags": ["ERROR", "CWE-89"]},
                                "shortDescription": {"text": "python.flask.sqli"},
                            },
                            {
                                "fullDescription": {
                                    "text": "Command injection is dynamically verifiable"
                                },
                                "id": "python.flask.cmdi",
                                "name": "python.flask.cmdi",
                                "properties": {"tags": ["WARNING", "CWE-78"]},
                                "shortDescription": {"text": "python.flask.cmdi"},
                            },
                        ],
                    }
                },
            }
        ],
        "version": "2.1.0",
    }


def test_build_markdown_output_matches_snapshot() -> None:
    """Markdown output should group findings by verdict/state and show warnings."""
    result = _sample_sast_result()

    report = ReportBuilder().build(result, output_format="markdown")

    assert report == (
        "# ShieldClaw Report\n\n"
        "- result_id: aaaaaaaa-bbbb-4ccc-dddd-eeeeeeeeeeee\n"
        "- scan_id: 99999999-8888-4777-9666-555555555555\n"
        "- pipeline_error: none\n"
        "- duration_seconds: 4.2\n\n"
        "## REJECTED\n\n"
        "### python.flask.cmdi\n"
        "- location: worker.py:18-18\n"
        "- severity: WARNING\n"
        "- state: REJECTED\n"
        "- cwe: CWE-78\n"
        "- triage_verdict: DYNAMICALLY_VERIFIABLE\n"
        "- triage_reason: Command injection is dynamically verifiable\n"
        "- verdict: none\n"
        "- verdict_confidence: none\n"
        "- verdict_summary: none\n"
        "- observer_warnings: none\n\n"
        "## TRUE_POSITIVE\n\n"
        "### python.flask.sqli\n"
        "- location: app.py:42-42\n"
        "- severity: ERROR\n"
        "- state: VERDICTED\n"
        "- cwe: CWE-89\n"
        "- triage_verdict: DYNAMICALLY_VERIFIABLE\n"
        "- triage_reason: SQL injection is dynamically verifiable\n"
        "- verdict: TRUE_POSITIVE\n"
        "- verdict_confidence: 0.9\n"
        "- verdict_summary: Exit code and logs confirm exploitability.\n"
        "- observer_warnings:\n"
        "  - target_logs: log stream unavailable\n"
    )


@pytest.mark.integration
def test_sarif_output_validates_against_official_schema() -> None:
    """SARIF output should validate against the official 2.1.0 schema."""
    import jsonschema

    result = _sample_sast_result()
    schema = json.loads(_SARIF_SCHEMA.read_text(encoding="utf-8"))
    report = json.loads(ReportBuilder().build(result, output_format="sarif"))

    jsonschema.validate(instance=report, schema=schema)
