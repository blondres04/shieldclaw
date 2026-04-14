"""Tests for ``ReportBuilder`` JSON serialization."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

from pytest_mock import MockerFixture

from shieldclaw.models import ContainerState, ContainerStatus, ExploitPayload, ScanResult
from shieldclaw.reporting.builder import ReportBuilder


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
