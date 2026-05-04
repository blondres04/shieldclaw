"""Integration test exercising real Docker against the vulnerable Flask sample."""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
import threading
import time
import uuid
from pathlib import Path

import pytest

from shieldclaw.models import ExploitPayload
from shieldclaw.sandbox.docker_orchestrator import (
    DockerOrchestrator,
    compose_default_network,
    compose_project_name,
    resolve_compose_start_wait_seconds,
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


def _build_attacker_image(tag: str) -> bool:
    """Build the attacker image used by real detonation integration tests."""
    dockerfile = _REPO_ROOT / "shield-claw" / "docker" / "attacker.Dockerfile"
    if not dockerfile.is_file():
        return False
    result = subprocess.run(
        [
            "docker",
            "build",
            "-f",
            str(dockerfile),
            "-t",
            tag,
            str(_REPO_ROOT / "shield-claw"),
        ],
        capture_output=True,
        text=True,
        timeout=300.0,
    )
    return result.returncode == 0


def _find_attacker_container_id(result_id: str) -> str | None:
    """Return the live attacker container ID for a run, if present."""
    result = subprocess.run(
        [
            "docker",
            "ps",
            "--filter",
            f"label=shieldclaw.run={result_id}",
            "--format",
            "{{.ID}}\t{{.Names}}",
        ],
        capture_output=True,
        text=True,
        timeout=15.0,
    )
    if result.returncode != 0:
        return None
    for line in result.stdout.splitlines():
        container_id, _, name = line.partition("\t")
        if name.startswith("shieldclaw-att-"):
            return container_id.strip() or None
    return None


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


@pytest.mark.integration
@pytest.mark.skipif(not _COMPOSE_SRC.is_file(), reason="vulnerable-flask-app compose file missing")
@pytest.mark.skipif(not _docker_available(), reason="Docker engine not available")
def test_full_stack_detonate_and_teardown(integration_compose: Path) -> None:
    """Spin up the sample stack, run a trivial exploit script, and tear it down."""
    result_id = str(uuid.uuid4())
    project = compose_project_name(result_id)
    compose_dir = integration_compose.parent
    attacker_tag = f"shieldclaw-attacker:test-{uuid.uuid4().hex[:12]}"

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
    if not _build_attacker_image(attacker_tag):
        pytest.skip("Failed to build attacker image")

    orchestrator = DockerOrchestrator(
        start_wait_seconds=resolve_compose_start_wait_seconds(120.0),
        start_poll_interval=2.0,
        post_up_grace_seconds=0.0,
    )
    original_tag = os.environ.get("SHIELDCLAW_ATTACKER_IMAGE")
    os.environ["SHIELDCLAW_ATTACKER_IMAGE"] = attacker_tag
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
        outcome = orchestrator.detonate(
            payload,
            network_name=network,
            result_id=result_id,
            timeout=60,
        )
        assert outcome.exit_code == 0
    finally:
        if original_tag is None:
            os.environ.pop("SHIELDCLAW_ATTACKER_IMAGE", None)
        else:
            os.environ["SHIELDCLAW_ATTACKER_IMAGE"] = original_tag
        orchestrator.teardown(str(integration_compose), result_id)


@pytest.mark.integration
@pytest.mark.skipif(not _COMPOSE_SRC.is_file(), reason="vulnerable-flask-app compose file missing")
@pytest.mark.skipif(not _docker_available(), reason="Docker engine not available")
def test_attacker_network_is_internal_and_blocks_egress(integration_compose: Path) -> None:
    """The attacker must reach compose services but not external hosts."""
    result_id = str(uuid.uuid4())
    project = compose_project_name(result_id)
    compose_dir = integration_compose.parent
    attacker_tag = f"shieldclaw-attacker:test-{uuid.uuid4().hex[:12]}"

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
    if not _build_attacker_image(attacker_tag):
        pytest.skip("Failed to build attacker image")

    orchestrator = DockerOrchestrator(
        start_wait_seconds=resolve_compose_start_wait_seconds(120.0),
        start_poll_interval=2.0,
        post_up_grace_seconds=0.0,
    )
    original_tag = os.environ.get("SHIELDCLAW_ATTACKER_IMAGE")
    os.environ["SHIELDCLAW_ATTACKER_IMAGE"] = attacker_tag
    orchestrator.start_sandbox(str(integration_compose), result_id)
    try:
        network = compose_default_network(result_id)
        inspect = subprocess.run(
            ["docker", "network", "inspect", "--format", "{{.Internal}}", network],
            capture_output=True,
            text=True,
            timeout=30.0,
        )
        assert inspect.returncode == 0, inspect.stderr
        assert inspect.stdout.strip() == "true"

        payload = ExploitPayload(
            payload_id=uuid.uuid4(),
            raw_code=(
                "import socket\n"
                "import sys\n"
                "import urllib.request\n"
                "\n"
                "response = urllib.request.urlopen('http://web:5000/user?id=1', timeout=5)\n"
                "body = response.read().decode('utf-8')\n"
                "assert 'Alice' in body, body\n"
                "\n"
                "try:\n"
                "    socket.create_connection(('8.8.8.8', 53), timeout=2)\n"
                "except OSError:\n"
                "    sys.exit(0)\n"
                "raise SystemExit('external egress unexpectedly succeeded')\n"
            ),
            target_dns="web",
            execution_command="python -",
            language="python",
        )
        outcome = orchestrator.detonate(
            payload,
            network_name=network,
            result_id=result_id,
            timeout=60,
        )
        assert outcome.exit_code == 0
    finally:
        if original_tag is None:
            os.environ.pop("SHIELDCLAW_ATTACKER_IMAGE", None)
        else:
            os.environ["SHIELDCLAW_ATTACKER_IMAGE"] = original_tag
        orchestrator.teardown(str(integration_compose), result_id)


@pytest.mark.integration
@pytest.mark.skipif(not _COMPOSE_SRC.is_file(), reason="vulnerable-flask-app compose file missing")
@pytest.mark.skipif(not _docker_available(), reason="Docker engine not available")
def test_attacker_container_uses_default_seccomp_profile(integration_compose: Path) -> None:
    """The live attacker container should expose the default seccomp profile via inspect."""
    result_id = str(uuid.uuid4())
    project = compose_project_name(result_id)
    compose_dir = integration_compose.parent
    attacker_tag = f"shieldclaw-attacker:test-{uuid.uuid4().hex[:12]}"

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
    if not _build_attacker_image(attacker_tag):
        pytest.skip("Failed to build attacker image")

    orchestrator = DockerOrchestrator(
        start_wait_seconds=resolve_compose_start_wait_seconds(120.0),
        start_poll_interval=2.0,
        post_up_grace_seconds=0.0,
    )
    original_tag = os.environ.get("SHIELDCLAW_ATTACKER_IMAGE")
    os.environ["SHIELDCLAW_ATTACKER_IMAGE"] = attacker_tag
    orchestrator.start_sandbox(str(integration_compose), result_id)

    outcome: dict[str, object] = {}

    def run_detonation() -> None:
        try:
            payload = ExploitPayload(
                payload_id=uuid.uuid4(),
                raw_code="import time\ntime.sleep(8)\nraise SystemExit(0)\n",
                target_dns="web",
                execution_command="python -",
                language="python",
            )
            outcome["result"] = orchestrator.detonate(
                payload,
                network_name=compose_default_network(result_id),
                result_id=result_id,
                timeout=60,
            )
        except Exception as exc:  # noqa: BLE001
            outcome["error"] = exc

    detonation_thread = threading.Thread(target=run_detonation, name="detonate-seccomp-check")
    detonation_thread.start()

    try:
        attacker_container_id: str | None = None
        deadline = time.monotonic() + 15.0
        while time.monotonic() < deadline:
            attacker_container_id = _find_attacker_container_id(result_id)
            if attacker_container_id:
                break
            time.sleep(0.25)

        assert attacker_container_id is not None, "attacker container never appeared in docker ps"

        inspect = subprocess.run(
            [
                "docker",
                "inspect",
                "--format",
                "{{json .HostConfig.SecurityOpt}}",
                attacker_container_id,
            ],
            capture_output=True,
            text=True,
            timeout=30.0,
        )
        assert inspect.returncode == 0, inspect.stderr
        security_opt = inspect.stdout.strip()
        assert "seccomp=unconfined" not in security_opt
        if platform.system().lower() == "windows":
            assert security_opt in ("null", "[]", "")
        else:
            assert "seccomp=default" in security_opt
    finally:
        detonation_thread.join(timeout=90.0)
        if original_tag is None:
            os.environ.pop("SHIELDCLAW_ATTACKER_IMAGE", None)
        else:
            os.environ["SHIELDCLAW_ATTACKER_IMAGE"] = original_tag
        orchestrator.teardown(str(integration_compose), result_id)

    assert "error" not in outcome, str(outcome.get("error"))
    assert "result" in outcome
    detonation_outcome = outcome["result"]
    assert detonation_outcome.exit_code == 0
