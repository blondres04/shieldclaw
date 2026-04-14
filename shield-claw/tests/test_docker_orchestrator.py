"""Unit tests for ``DockerOrchestrator`` with mocked ``subprocess.run``."""

from __future__ import annotations

import subprocess
import uuid
from pathlib import Path

import pytest
from pytest_mock import MockerFixture

from shieldclaw.exceptions import DetonationError, DockerNotAvailableError, SandboxStartError
from shieldclaw.models import ExploitPayload
from shieldclaw.sandbox.docker_orchestrator import (
    DockerOrchestrator,
    compose_default_network,
    compose_project_name,
    label_override_path,
)


def test_compose_project_name_is_stable() -> None:
    """Project slugs must be stable for a given ``result_id``."""
    assert compose_project_name("run-1") == compose_project_name("run-1")
    assert compose_project_name("run-1") != compose_project_name("run-2")


def test_compose_default_network_matches_project() -> None:
    """Default network names should follow Compose conventions."""
    rid = "abc"
    assert compose_default_network(rid) == f"{compose_project_name(rid)}_default"


def test_ensure_docker_raises_when_docker_missing(mocker: MockerFixture) -> None:
    """Missing Docker CLI should map to ``DockerNotAvailableError``."""
    mocker.patch(
        "shieldclaw.sandbox.docker_orchestrator.subprocess.run",
        side_effect=FileNotFoundError,
    )
    orch = DockerOrchestrator()
    with pytest.raises(DockerNotAvailableError):
        orch._ensure_docker()


def test_ensure_docker_raises_on_nonzero_exit(mocker: MockerFixture) -> None:
    """Non-zero ``docker version`` should surface ``DockerNotAvailableError``."""
    proc = subprocess.CompletedProcess(["docker", "version"], returncode=1, stdout="", stderr="boom")
    mocker.patch("shieldclaw.sandbox.docker_orchestrator.subprocess.run", return_value=proc)
    orch = DockerOrchestrator()
    with pytest.raises(DockerNotAvailableError) as excinfo:
        orch._ensure_docker()
    assert "boom" in str(excinfo.value)


def test_start_sandbox_invokes_compose_up(mocker: MockerFixture, tmp_path: Path) -> None:
    """``start_sandbox`` should run compose up and label discovered containers."""
    compose = tmp_path / "docker-compose.yml"
    compose.write_text("services:\n  web:\n    image: alpine\n", encoding="utf-8")
    result_id = "integration-test"

    mocker.patch.object(DockerOrchestrator, "_ensure_docker", autospec=True)
    mocker.patch.object(DockerOrchestrator, "_cleanup_stale", autospec=True)
    mocker.patch.object(DockerOrchestrator, "_wait_for_compose_ready", autospec=True)

    calls: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        if cmd[:2] == ["docker", "compose"] and cmd[-1] == "--services":
            return subprocess.CompletedProcess(cmd, 0, "web\n", "")
        if cmd[:2] == ["docker", "compose"] and cmd[-2:] == ["up", "-d"]:
            return subprocess.CompletedProcess(cmd, 0, "", "")
        raise AssertionError(f"Unexpected command: {cmd}")

    mocker.patch("shieldclaw.sandbox.docker_orchestrator.subprocess.run", side_effect=fake_run)

    orch = DockerOrchestrator(
        start_wait_seconds=1.0,
        start_poll_interval=0.01,
        post_up_grace_seconds=0.0,
    )
    orch.start_sandbox(str(compose), result_id)

    assert any(c[:2] == ["docker", "compose"] and c[-2:] == ["up", "-d"] for c in calls)
    override = label_override_path(compose, result_id)
    assert override.is_file()
    assert "shieldclaw.run" in override.read_text(encoding="utf-8")


def test_start_sandbox_raises_when_compose_missing(tmp_path: Path) -> None:
    """Missing compose files should raise ``SandboxStartError``."""
    orch = DockerOrchestrator()
    missing = tmp_path / "missing.yml"
    with pytest.raises(SandboxStartError):
        orch.start_sandbox(str(missing), "rid")


def test_detonate_timeout_returns_124(mocker: MockerFixture) -> None:
    """Timeouts must map to exit code ``124`` after forced removal."""
    mocker.patch.object(DockerOrchestrator, "_ensure_docker", autospec=True)
    mocker.patch(
        "shieldclaw.sandbox.docker_orchestrator.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd=["docker"], timeout=1),
    )
    kill_mock = mocker.patch.object(DockerOrchestrator, "_force_remove_container", autospec=True)
    payload = ExploitPayload(
        payload_id=uuid.uuid4(),
        raw_code="import sys\nsys.exit(0)\n",
        target_dns="web",
        execution_command="python -",
        language="python",
    )
    orch = DockerOrchestrator()
    code = orch.detonate(payload, "net", "rid", timeout=1)
    assert code == 124
    kill_mock.assert_called_once()


def test_detonate_raises_on_docker_client_error(mocker: MockerFixture) -> None:
    """Docker client failures should raise ``DetonationError``."""
    mocker.patch.object(DockerOrchestrator, "_ensure_docker", autospec=True)
    proc = subprocess.CompletedProcess(
        ["docker", "run"],
        returncode=125,
        stdout="",
        stderr="docker: invalid reference format.\n",
    )
    mocker.patch("shieldclaw.sandbox.docker_orchestrator.subprocess.run", return_value=proc)
    payload = ExploitPayload(
        payload_id=uuid.uuid4(),
        raw_code="print(1)",
        target_dns="web",
        execution_command="python -",
        language="python",
    )
    orch = DockerOrchestrator()
    with pytest.raises(DetonationError):
        orch.detonate(payload, "net", "rid", timeout=5)
