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
    _START_WAIT_SECONDS,
    DockerOrchestrator,
    compose_default_network,
    compose_project_name,
    compose_up_timeout_seconds,
    label_override_path,
    resolve_compose_start_wait_seconds,
)


def test_compose_project_name_is_stable() -> None:
    """Project slugs must be stable for a given ``result_id``."""
    assert compose_project_name("run-1") == compose_project_name("run-1")
    assert compose_project_name("run-1") != compose_project_name("run-2")


def test_compose_default_network_matches_project() -> None:
    """Default network names should follow Compose conventions."""
    rid = "abc"
    assert compose_default_network(rid) == f"{compose_project_name(rid)}_default"


def test_orchestrator_default_start_wait_uses_module_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When no env var is set, ``start_wait_seconds`` defaults to ``_START_WAIT_SECONDS``."""
    monkeypatch.delenv("SHIELDCLAW_COMPOSE_START_TIMEOUT", raising=False)
    orch = DockerOrchestrator()
    assert orch._start_wait == _START_WAIT_SECONDS


def test_orchestrator_start_wait_reads_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    """``SHIELDCLAW_COMPOSE_START_TIMEOUT`` overrides the default when ``start_wait_seconds`` is unset."""
    monkeypatch.setenv("SHIELDCLAW_COMPOSE_START_TIMEOUT", "240")
    orch = DockerOrchestrator()
    assert orch._start_wait == 240.0


def test_orchestrator_start_wait_explicit_overrides_env_var(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An explicit ``start_wait_seconds`` argument takes precedence over the env var."""
    monkeypatch.setenv("SHIELDCLAW_COMPOSE_START_TIMEOUT", "999")
    orch = DockerOrchestrator(start_wait_seconds=30.0)
    assert orch._start_wait == 30.0


def test_orchestrator_start_wait_invalid_env_var_uses_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An invalid ``SHIELDCLAW_COMPOSE_START_TIMEOUT`` value falls back to the module default."""
    monkeypatch.setenv("SHIELDCLAW_COMPOSE_START_TIMEOUT", "not-a-number")
    orch = DockerOrchestrator()
    assert orch._start_wait == _START_WAIT_SECONDS


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
    proc = subprocess.CompletedProcess(
        ["docker", "version"], returncode=1, stdout="", stderr="boom"
    )
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
    mocker.patch.object(DockerOrchestrator, "_probe_attacker_image", autospec=True)
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
    assert "networks:" in override.read_text(encoding="utf-8")
    assert "internal: true" in override.read_text(encoding="utf-8")


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
    outcome = orch.detonate(payload, "net", "rid", timeout=1)
    assert outcome.exit_code == 124
    kill_mock.assert_called_once()


def test_probe_attacker_image_raises_when_missing(mocker: MockerFixture) -> None:
    """``_probe_attacker_image`` must raise ``SandboxStartError`` when image absent."""
    proc = subprocess.CompletedProcess(["docker", "image", "inspect"], 1, "", "No such image")
    mocker.patch("shieldclaw.sandbox.docker_orchestrator.subprocess.run", return_value=proc)
    orch = DockerOrchestrator()
    with pytest.raises(SandboxStartError, match="not found"):
        orch._probe_attacker_image()


def test_probe_attacker_image_passes_when_present(mocker: MockerFixture) -> None:
    """``_probe_attacker_image`` must not raise when image is present."""
    proc = subprocess.CompletedProcess(["docker", "image", "inspect"], 0, "sha256:abc123", "")
    mocker.patch("shieldclaw.sandbox.docker_orchestrator.subprocess.run", return_value=proc)
    DockerOrchestrator()._probe_attacker_image()  # must not raise


def test_cleanup_stale_filters_by_result_id(mocker: MockerFixture) -> None:
    """``_cleanup_stale`` must scope docker ps to ``label=shieldclaw.run=<result_id>``."""
    no_containers = subprocess.CompletedProcess(["docker", "ps"], 0, "", "")
    run_mock = mocker.patch(
        "shieldclaw.sandbox.docker_orchestrator.subprocess.run",
        return_value=no_containers,
    )
    orch = DockerOrchestrator()
    orch._cleanup_stale("my-run-id")
    cmd = run_mock.call_args_list[0][0][0]
    assert "label=shieldclaw.run=my-run-id" in " ".join(cmd)


def test_cleanup_stale_does_not_touch_other_run_ids(mocker: MockerFixture) -> None:
    """A cleanup for run-A must not issue rm commands that would affect run-B."""
    no_containers = subprocess.CompletedProcess(["docker", "ps"], 0, "", "")
    run_mock = mocker.patch(
        "shieldclaw.sandbox.docker_orchestrator.subprocess.run",
        return_value=no_containers,
    )
    orch = DockerOrchestrator()
    orch._cleanup_stale("run-a")
    # Only one subprocess call (docker ps); no docker rm because nothing matched.
    assert run_mock.call_count == 1
    cmd = run_mock.call_args_list[0][0][0]
    # The filter must NOT be the broad "label=shieldclaw.run" (no value).
    assert "label=shieldclaw.run=" in " ".join(cmd)
    assert "label=shieldclaw.run " not in " ".join(cmd)


def test_is_service_healthy_healthy_with_healthcheck(mocker: MockerFixture) -> None:
    """``healthy`` + ``running`` should return ``True``."""
    proc = subprocess.CompletedProcess(["docker", "inspect"], 0, "healthy\trunning", "")
    mocker.patch("shieldclaw.sandbox.docker_orchestrator.subprocess.run", return_value=proc)
    assert DockerOrchestrator()._is_service_healthy("web", "proj", Path("/tmp"))


def test_is_service_healthy_no_healthcheck_counts_as_passing(mocker: MockerFixture) -> None:
    """``none`` health status (no healthcheck) must return ``True`` when running."""
    proc = subprocess.CompletedProcess(["docker", "inspect"], 0, "none\trunning", "")
    mocker.patch("shieldclaw.sandbox.docker_orchestrator.subprocess.run", return_value=proc)
    assert DockerOrchestrator()._is_service_healthy("web", "proj", Path("/tmp"))


def test_is_service_healthy_unhealthy_returns_false(mocker: MockerFixture) -> None:
    """``unhealthy`` status must return ``False``."""
    proc = subprocess.CompletedProcess(["docker", "inspect"], 0, "unhealthy\trunning", "")
    mocker.patch("shieldclaw.sandbox.docker_orchestrator.subprocess.run", return_value=proc)
    assert not DockerOrchestrator()._is_service_healthy("web", "proj", Path("/tmp"))


def test_is_service_healthy_not_running_returns_false(mocker: MockerFixture) -> None:
    """Container not yet in ``running`` state must return ``False``."""
    proc = subprocess.CompletedProcess(["docker", "inspect"], 0, "none\texited", "")
    mocker.patch("shieldclaw.sandbox.docker_orchestrator.subprocess.run", return_value=proc)
    assert not DockerOrchestrator()._is_service_healthy("web", "proj", Path("/tmp"))


def test_is_service_healthy_tries_legacy_naming_when_modern_fails(
    mocker: MockerFixture,
) -> None:
    """Legacy ``project_service_1`` form is tried when modern ``project-service-1`` fails."""
    calls: list[list[str]] = []

    def fake_inspect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        # First call (modern dash form) — container not found.
        if len(calls) == 1:
            return subprocess.CompletedProcess(cmd, 1, "", "No such container")
        # Second call (legacy underscore form) — success.
        return subprocess.CompletedProcess(cmd, 0, "none\trunning", "")

    mocker.patch("shieldclaw.sandbox.docker_orchestrator.subprocess.run", side_effect=fake_inspect)
    assert DockerOrchestrator()._is_service_healthy("web", "myproject", Path("/tmp"))
    assert len(calls) == 2
    assert "myproject-web-1" in calls[0]
    assert "myproject_web_1" in calls[1]


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


def test_resolve_compose_start_wait_seconds_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHIELDCLAW_COMPOSE_START_TIMEOUT", "240")
    assert resolve_compose_start_wait_seconds(120.0) == 240.0


def test_resolve_compose_start_wait_seconds_invalid_env_uses_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHIELDCLAW_COMPOSE_START_TIMEOUT", "bogus")
    assert resolve_compose_start_wait_seconds(85.5) == 85.5


def test_compose_up_timeout_seconds_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHIELDCLAW_COMPOSE_UP_TIMEOUT_SECONDS", "999")
    assert compose_up_timeout_seconds() == 999.0
