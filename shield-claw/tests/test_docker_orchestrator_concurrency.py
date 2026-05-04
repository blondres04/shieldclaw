"""Integration test: concurrent ShieldClaw runs must not destroy each other's containers.

Requires a running Docker daemon.  Run with::

    pytest -m integration tests/test_docker_orchestrator_concurrency.py -v

The test spins up two independent docker-compose stacks (each a single
``nginx:alpine`` service) on two threads.  Thread A starts its sandbox first,
signals readiness, then waits while thread B starts its own sandbox.  Thread B's
``start_sandbox`` triggers ``_cleanup_stale(result_id_b)``; because cleanup is
now scoped to the *calling* run's result_id, it leaves thread A's containers
untouched.  The test asserts this explicitly.
"""

from __future__ import annotations

import os
import subprocess
import threading
import uuid
from pathlib import Path

import pytest

from shieldclaw.sandbox.docker_orchestrator import (
    DockerOrchestrator,
    resolve_compose_start_wait_seconds,
)

_MINIMAL_COMPOSE = """\
services:
  web:
    image: nginx:alpine
"""

_REPO_ROOT = Path(__file__).resolve().parents[2]


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


def _containers_for_run(result_id: str) -> list[str]:
    """Return container IDs labeled with the given result_id."""
    proc = subprocess.run(
        ["docker", "ps", "-q", "--filter", f"label=shieldclaw.run={result_id}"],
        capture_output=True,
        text=True,
        timeout=15.0,
    )
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def _build_attacker_image(tag: str) -> bool:
    """Build the attacker image used by sandbox startup checks."""
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


@pytest.mark.integration
@pytest.mark.skipif(not _docker_available(), reason="Docker engine not available")
def test_concurrent_runs_do_not_interfere(tmp_path: Path) -> None:
    """Simultaneous runs scoped to different result_ids must not destroy each other."""
    dir_a = tmp_path / "run_a"
    dir_b = tmp_path / "run_b"
    dir_a.mkdir()
    dir_b.mkdir()
    (dir_a / "docker-compose.yml").write_text(_MINIMAL_COMPOSE, encoding="utf-8")
    (dir_b / "docker-compose.yml").write_text(_MINIMAL_COMPOSE, encoding="utf-8")
    attacker_tag = f"shieldclaw-attacker:test-{uuid.uuid4().hex[:12]}"
    if not _build_attacker_image(attacker_tag):
        pytest.skip("Failed to build attacker image")

    result_id_a = str(uuid.uuid4())
    result_id_b = str(uuid.uuid4())

    start_budget = resolve_compose_start_wait_seconds(120.0)
    thread_wait = start_budget + 180.0
    join_budget = max(900.0, 3.0 * start_budget + 240.0)

    orch_a = DockerOrchestrator(
        start_wait_seconds=start_budget,
        start_poll_interval=1.0,
        post_up_grace_seconds=0.0,
    )
    orch_b = DockerOrchestrator(
        start_wait_seconds=start_budget,
        start_poll_interval=1.0,
        post_up_grace_seconds=0.0,
    )

    a_sandbox_ready = threading.Event()
    b_cleanup_done = threading.Event()
    errors: list[Exception] = []
    original_tag = os.environ.get("SHIELDCLAW_ATTACKER_IMAGE")
    os.environ["SHIELDCLAW_ATTACKER_IMAGE"] = attacker_tag

    def run_a() -> None:
        try:
            orch_a.start_sandbox(str(dir_a / "docker-compose.yml"), result_id_a)
            a_sandbox_ready.set()
            # Wait for B to perform its startup (which includes _cleanup_stale).
            if not b_cleanup_done.wait(timeout=thread_wait):
                errors.append(TimeoutError("Thread B did not signal within expected time"))
                return
            # A's containers must still be alive after B's cleanup.
            containers = _containers_for_run(result_id_a)
            if not containers:
                errors.append(
                    AssertionError(
                        f"Run A's containers (result_id={result_id_a}) were destroyed "
                        "by run B's _cleanup_stale — concurrency isolation broken."
                    )
                )
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)
        finally:
            orch_a.teardown(str(dir_a / "docker-compose.yml"), result_id_a)

    def run_b() -> None:
        try:
            if not a_sandbox_ready.wait(timeout=thread_wait):
                errors.append(
                    TimeoutError(f"Thread A did not start sandbox within {thread_wait} s")
                )
                return
            # start_sandbox calls _cleanup_stale(result_id_b) — must not touch A.
            orch_b.start_sandbox(str(dir_b / "docker-compose.yml"), result_id_b)
            b_cleanup_done.set()
            # B's own containers must exist.
            containers = _containers_for_run(result_id_b)
            if not containers:
                errors.append(
                    AssertionError(
                        f"Run B's containers (result_id={result_id_b}) do not exist "
                        "after start_sandbox — something went wrong with labeling."
                    )
                )
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)
        finally:
            orch_b.teardown(str(dir_b / "docker-compose.yml"), result_id_b)

    thread_a = threading.Thread(target=run_a, name="orch-run-a", daemon=True)
    thread_b = threading.Thread(target=run_b, name="orch-run-b", daemon=True)

    thread_a.start()
    thread_b.start()
    thread_a.join(timeout=join_budget)
    thread_b.join(timeout=join_budget)

    if original_tag is None:
        os.environ.pop("SHIELDCLAW_ATTACKER_IMAGE", None)
    else:
        os.environ["SHIELDCLAW_ATTACKER_IMAGE"] = original_tag

    if errors:
        raise errors[0]
