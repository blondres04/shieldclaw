"""Integration test exercising real Docker against the vulnerable Flask sample."""

from __future__ import annotations

import re
import shutil
import subprocess
import time
import uuid
from pathlib import Path

import pytest

from shieldclaw.models import ExploitPayload
from shieldclaw.sandbox.docker_orchestrator import (
    DockerOrchestrator,
    compose_default_network,
    compose_project_name,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_COMPOSE_SRC = _REPO_ROOT / "test_repos" / "vulnerable-flask-app" / "docker-compose.yml"
_APP_SRC = _REPO_ROOT / "test_repos" / "vulnerable-flask-app"


def _strip_host_port_mappings(raw: str) -> str:
    """Remove published ``ports`` blocks so stacks do not bind host ports."""
    return re.sub(
        r"^\s*ports:\s*\r?\n(?:^\s+-\s+.+\r?\n)+",
        "",
        raw,
        flags=re.MULTILINE,
    )


def _materialize_internal_only_stack(tmp_path: Path) -> Path:
    """Copy the vulnerable Flask fixtures without host port publishing."""
    for name in ("Dockerfile", "app.py", "init.sql"):
        shutil.copy2(_APP_SRC / name, tmp_path / name)
    compose_text = _strip_host_port_mappings(_COMPOSE_SRC.read_text(encoding="utf-8"))
    (tmp_path / "docker-compose.yml").write_text(compose_text, encoding="utf-8")
    return tmp_path / "docker-compose.yml"


@pytest.fixture
def integration_compose(tmp_path: Path) -> Path:
    """Provide an isolated compose file that avoids host port collisions."""
    return _materialize_internal_only_stack(tmp_path)


def _docker_available() -> bool:
    try:
        proc = subprocess.run(
            ["docker", "version"],
            capture_output=True,
            text=True,
            timeout=15.0,
        )
        return proc.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


@pytest.mark.skipif(not _COMPOSE_SRC.is_file(), reason="vulnerable-flask-app compose file missing")
@pytest.mark.skipif(not _docker_available(), reason="Docker engine not available")
def test_full_stack_detonate_and_teardown(integration_compose: Path) -> None:
    """Spin up the sample stack, run a trivial exploit script, and tear it down."""
    result_id = str(uuid.uuid4())
    project = compose_project_name(result_id)
    compose_dir = integration_compose.parent

    build = subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            str(integration_compose),
            "-p",
            project,
            "build",
        ],
        cwd=str(compose_dir),
        capture_output=True,
        text=True,
        timeout=600.0,
    )
    if build.returncode != 0:
        pytest.skip(f"docker compose build failed: {build.stderr}")

    orchestrator = DockerOrchestrator(start_wait_seconds=120.0, start_poll_interval=2.0)
    orchestrator.start_sandbox(str(integration_compose), result_id)
    try:
        time.sleep(5.0)
        network = compose_default_network(result_id)
        payload = ExploitPayload(
            payload_id=uuid.uuid4(),
            raw_code="import sys\nsys.exit(0)\n",
            target_dns="web",
            execution_command="python -",
            language="python",
        )
        exit_code = orchestrator.detonate(
            payload,
            network_name=network,
            result_id=result_id,
            timeout=60,
        )
        assert exit_code == 0
    finally:
        orchestrator.teardown(str(integration_compose), result_id)
