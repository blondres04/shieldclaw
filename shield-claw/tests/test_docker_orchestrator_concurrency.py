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

import subprocess
import threading
import uuid
from pathlib import Path

import pytest

from shieldclaw.sandbox.docker_orchestrator import DockerOrchestrator

_MINIMAL_COMPOSE = """\
services:
  web:
    image: nginx:alpine
"""


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

    result_id_a = str(uuid.uuid4())
    result_id_b = str(uuid.uuid4())

    orch_a = DockerOrchestrator(
        start_wait_seconds=120.0,
        start_poll_interval=1.0,
        post_up_grace_seconds=0.0,
    )
    orch_b = DockerOrchestrator(
        start_wait_seconds=120.0,
        start_poll_interval=1.0,
        post_up_grace_seconds=0.0,
    )

    a_sandbox_ready = threading.Event()
    b_cleanup_done = threading.Event()
    errors: list[Exception] = []

    def run_a() -> None:
        try:
            orch_a.start_sandbox(str(dir_a / "docker-compose.yml"), result_id_a)
            a_sandbox_ready.set()
            # Wait for B to perform its startup (which includes _cleanup_stale).
            if not b_cleanup_done.wait(timeout=60):
                errors.append(TimeoutError("Thread B did not signal within 60 s"))
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
            if not a_sandbox_ready.wait(timeout=120):
                errors.append(TimeoutError("Thread A did not start sandbox within 120 s"))
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
    thread_a.join(timeout=300)
    thread_b.join(timeout=300)

    if errors:
        raise errors[0]
