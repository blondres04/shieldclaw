"""Orchestrator state machine tests with mocked pipeline collaborators."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from shieldclaw.context.aggregator import ContextAggregator
from shieldclaw.exceptions import AggregationError, LLMRefusalError
from shieldclaw.intelligence.base import LLMProvider
from shieldclaw.models import ExploitPayload, ScanContext, ScanResult
from shieldclaw.orchestrator import Orchestrator, compose_default_network
from shieldclaw.reporting.builder import ReportBuilder
from shieldclaw.sandbox.docker_orchestrator import DockerOrchestrator


def _sample_context(repo: Path) -> ScanContext:
    return ScanContext(
        target_dir=str(repo),
        git_diff_content="diff --git a/x b/x\n",
        docker_compose_content="services: {}\n",
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
    )


def _sample_payload() -> ExploitPayload:
    return ExploitPayload(
        payload_id=uuid.uuid4(),
        raw_code="import sys\nsys.exit(0)\n",
        target_dns="web",
        execution_command="python -",
        language="python",
    )


@pytest.fixture
def repo_dir(tmp_path: Path) -> Path:
    """Minimal repo layout so compose discovery matches the aggregator contract."""
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  web:\n    image: alpine\n",
        encoding="utf-8",
    )
    return tmp_path


def test_happy_path_state_sequence(repo_dir: Path) -> None:
    """Mocks should observe aggregate → exploit → sandbox → detonate → teardown → report."""
    ctx = _sample_context(repo_dir)
    payload = _sample_payload()

    aggregator = MagicMock(spec=ContextAggregator)
    aggregator.aggregate.return_value = ctx

    provider = MagicMock(spec=LLMProvider)
    provider.generate_exploit.return_value = payload

    docker = MagicMock(spec=DockerOrchestrator)
    docker.detonate.return_value = 0

    reports = MagicMock(spec=ReportBuilder)
    reports.build.return_value = '{"ok": true}\n'

    orch = Orchestrator(
        context_aggregator=aggregator,
        docker_orchestrator=docker,
        report_builder=reports,
        provider_factory=lambda _name: provider,
    )

    result = orch.run(str(repo_dir), None, "ollama", 30, None)

    assert isinstance(result, ScanResult)
    assert result.is_vulnerable is True
    assert result.exit_code == 0
    assert result.pipeline_error is None
    assert result.exploit_payload == payload

    aggregator.aggregate.assert_called_once_with(str(repo_dir), None)
    provider.generate_exploit.assert_called_once_with(ctx)
    docker.start_sandbox.assert_called_once()
    sb_args, sb_kw = docker.start_sandbox.call_args
    assert sb_args[0].endswith("docker-compose.yml")
    assert isinstance(sb_args[1], str)

    docker.detonate.assert_called_once_with(
        payload,
        network_name=compose_default_network(sb_args[1]),
        result_id=sb_args[1],
        timeout=30,
    )

    docker.teardown.assert_called_once_with(sb_args[0], sb_args[1])
    reports.build.assert_called_once()
    reports.write.assert_called_once_with('{"ok": true}\n', None)


def test_aggregation_error_sets_pipeline_error(repo_dir: Path) -> None:
    """``AggregationError`` must populate ``pipeline_error`` and still clean up."""
    aggregator = MagicMock(spec=ContextAggregator)
    aggregator.aggregate.side_effect = AggregationError("no compose")

    docker = MagicMock(spec=DockerOrchestrator)
    reports = MagicMock(spec=ReportBuilder)
    reports.build.return_value = "{}"

    orch = Orchestrator(
        context_aggregator=aggregator,
        docker_orchestrator=docker,
        report_builder=reports,
        provider_factory=lambda _n: MagicMock(spec=LLMProvider),
    )

    result = orch.run(str(repo_dir), None, "ollama", 15, None)

    assert result.pipeline_error == "no compose"
    assert result.exploit_payload is None
    docker.teardown.assert_called_once()
    reports.write.assert_called_once()


def test_llm_refusal_sets_failed_pipeline(repo_dir: Path) -> None:
    """``LLMRefusalError`` should stop before Docker while still tearing down."""
    ctx = _sample_context(repo_dir)
    aggregator = MagicMock(spec=ContextAggregator)
    aggregator.aggregate.return_value = ctx

    provider = MagicMock(spec=LLMProvider)
    provider.generate_exploit.side_effect = LLMRefusalError("model declined")

    docker = MagicMock(spec=DockerOrchestrator)
    reports = MagicMock(spec=ReportBuilder)
    reports.build.return_value = "{}"

    orch = Orchestrator(
        context_aggregator=aggregator,
        docker_orchestrator=docker,
        report_builder=reports,
        provider_factory=lambda _n: provider,
    )

    result = orch.run(str(repo_dir), None, "ollama", 15, None)

    assert result.pipeline_error == "model declined"
    docker.start_sandbox.assert_not_called()
    docker.teardown.assert_called_once()
    reports.write.assert_called_once()


def test_unknown_provider_propagates(repo_dir: Path) -> None:
    """Factories that reject unknown names should not be swallowed as ``ShieldClawError``."""
    docker = MagicMock(spec=DockerOrchestrator)
    reports = MagicMock(spec=ReportBuilder)
    reports.build.return_value = "{}\n"
    orch = Orchestrator(docker_orchestrator=docker, report_builder=reports)
    with pytest.raises(ValueError, match="Unknown LLM provider"):
        orch.run(str(repo_dir), None, "unknown-vendor", 5, None)
    docker.teardown.assert_called_once()
    reports.write.assert_called_once()
