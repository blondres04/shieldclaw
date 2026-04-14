"""Manage compose-backed targets and locked-down attacker containers for detonation.

Compose services receive ``shieldclaw.run`` labels via a generated override file so
engines that lack ``docker update --label-add`` (common on Windows Desktop) stay
compatible while still meeting labeling requirements.
"""

from __future__ import annotations

import hashlib
import logging
import subprocess
import time
import uuid
from pathlib import Path

from shieldclaw.exceptions import DetonationError, DockerNotAvailableError, SandboxStartError
from shieldclaw.models import ExploitPayload

_LOG = logging.getLogger(__name__)

_DOCKER_INFO_TIMEOUT = 15.0
_COMPOSE_UP_TIMEOUT = 120.0
_START_POLL_INTERVAL = 2.0
_START_WAIT_SECONDS = 60.0
_DETONATE_IMAGE = "python:3.11-slim"

# ``python:3.11-slim`` does not ship with ``requests``. The attacker runs as UID 1000 with a
# read-only rootfs, so dependencies are installed with ``pip --target`` under ``/tmp``.
_DETONATE_BOOTSTRAP = (
    "import os, subprocess, sys;"
    "os.makedirs('/tmp/pylib', exist_ok=True);"
    "subprocess.check_call("
    "[sys.executable, '-m', 'pip', 'install', '-q', '--disable-pip-version-check', "
    "'--target', '/tmp/pylib', 'requests', 'urllib3'],"
    "stdout=subprocess.DEVNULL,"
    ");"
    "sys.path.insert(0, '/tmp/pylib');"
    "code = sys.stdin.read();"
    "exec(compile(code, '<exploit>', 'exec'))"
)


def compose_project_name(result_id: str) -> str:
    """Return a deterministic Compose project slug derived from ``result_id``.

    Args:
        result_id: Stable identifier for this scan run.

    Returns:
        A Docker Compose project name containing only ``[a-z0-9]``.
    """
    digest = hashlib.sha256(result_id.encode("utf-8")).hexdigest()[:20]
    return f"sc{digest}"


def label_override_path(compose_file: Path, result_id: str) -> Path:
    """Return the path to the generated compose override that injects ShieldClaw labels."""
    return compose_file.parent / f".shieldclaw.labels.{compose_project_name(result_id)}.yml"


def compose_default_network(result_id: str) -> str:
    """Infer the default bridge network name Compose creates for the project.

    Args:
        result_id: Stable identifier for this scan run (used to derive the project).

    Returns:
        Network name of the form ``{project}_default``.
    """
    return f"{compose_project_name(result_id)}_default"


class DockerOrchestrator:
    """Coordinates ``docker compose`` stacks and ephemeral exploit runners."""

    def __init__(
        self,
        *,
        start_wait_seconds: float = _START_WAIT_SECONDS,
        start_poll_interval: float = _START_POLL_INTERVAL,
        post_up_grace_seconds: float = 10.0,
    ) -> None:
        """Create an orchestrator with configurable startup polling.

        Args:
            start_wait_seconds: Maximum time to wait for compose services after ``up``.
            start_poll_interval: Sleep interval between readiness probes.
            post_up_grace_seconds: Extra sleep after every service reports running so
                application processes (e.g. Flask + Postgres) can finish booting.
        """
        self._start_wait = start_wait_seconds
        self._poll_interval = start_poll_interval
        self._post_up_grace = post_up_grace_seconds

    def start_sandbox(self, compose_path: str, result_id: str) -> None:
        """Bring up a compose project, label its containers, and wait until healthy.

        Args:
            compose_path: Absolute or relative path to ``docker-compose.yml``.
            result_id: Identifier applied as ``shieldclaw.run`` on every container.

        Raises:
            DockerNotAvailableError: When the Docker daemon is unreachable.
            SandboxStartError: When compose ``up`` or readiness polling fails.
        """
        self._ensure_docker()
        self._cleanup_stale()
        compose_file = Path(compose_path).expanduser().resolve()
        if not compose_file.is_file():
            raise SandboxStartError(f"Compose file not found: {compose_file}")
        project = compose_project_name(result_id)
        cwd = compose_file.parent
        override = self._write_label_override(compose_file, result_id, cwd)
        up_cmd = self._compose_command_prefix(compose_file, override, project) + ["up", "-d"]
        self._run_required(
            up_cmd,
            cwd=cwd,
            timeout=_COMPOSE_UP_TIMEOUT,
            error_cls=SandboxStartError,
            error_prefix="docker compose up failed",
        )
        self._wait_for_compose_ready(compose_file, override, project, cwd)
        if self._post_up_grace > 0:
            time.sleep(self._post_up_grace)

    def detonate(
        self,
        payload: ExploitPayload,
        network_name: str,
        result_id: str,
        timeout: int = 15,
    ) -> int:
        """Run exploit code inside a hardened, ephemeral Python container.

        Args:
            payload: Generated exploit metadata including ``raw_code``.
            network_name: Docker network shared with the vulnerable stack.
            result_id: Label value for ``shieldclaw.run``.
            timeout: Seconds to wait for the container to exit.

        Returns:
            Process exit code from the exploit, or ``124`` when the run times out.

        Raises:
            DockerNotAvailableError: When Docker cannot be contacted.
            DetonationError: When the attacker container cannot be created or started.
        """
        self._ensure_docker()
        container_name = f"shieldclaw-att-{uuid.uuid4().hex[:20]}"
        cmd = [
            "docker",
            "run",
            "--name",
            container_name,
            "-i",
            "--rm",
            "--memory=256m",
            "--cpus=0.5",
            "--pids-limit=100",
            "--user=1000:1000",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=32m",
            f"--network={network_name}",
            f"--label=shieldclaw.run={result_id}",
            "-e",
            "PYTHONDONTWRITEBYTECODE=1",
            _DETONATE_IMAGE,
            "python",
            "-c",
            _DETONATE_BOOTSTRAP,
        ]
        _LOG.debug("Running command: %s", cmd)
        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=float(timeout),
                input=payload.raw_code,
            )
        except subprocess.TimeoutExpired:
            _LOG.warning("Detonation timed out after %s seconds; killing %s", timeout, container_name)
            self._force_remove_container(container_name)
            return 124
        except FileNotFoundError as exc:
            raise DetonationError("docker executable not found on PATH.") from exc
        except OSError as exc:
            raise DetonationError("Unable to execute docker run for detonation.") from exc

        if completed.returncode != 0 and self._looks_like_docker_client_error(completed.stderr):
            detail = (completed.stderr or "").strip() or "docker run failed without stderr."
            raise DetonationError(f"Failed to start attacker container: {detail}")

        if completed.returncode != 0 and self._looks_like_docker_client_error(completed.stdout):
            detail = (completed.stdout or "").strip()
            raise DetonationError(f"Failed to start attacker container: {detail}")

        if completed.returncode != 0:
            _LOG.info(
                "Exploit container exited %s; stdout=%r stderr=%r",
                completed.returncode,
                (completed.stdout or "")[:4000],
                (completed.stderr or "")[:4000],
            )

        return int(completed.returncode)

    def teardown(self, compose_path: str, result_id: str) -> None:
        """Tear down compose volumes and remove labeled containers best-effort.

        Args:
            compose_path: Path to the compose file used during ``start_sandbox``.
            result_id: Identifier used to derive the Compose project and labels.
        """
        compose_file = Path(compose_path).expanduser().resolve()
        project = compose_project_name(result_id)
        cwd = compose_file.parent if compose_file.is_file() else Path.cwd()
        override = label_override_path(compose_file, result_id)
        down_cmd = self._compose_command_prefix(compose_file, override, project) + ["down", "-v"]
        try:
            self._run_optional(down_cmd, cwd=cwd, timeout=_COMPOSE_UP_TIMEOUT)
        except Exception as exc:  # noqa: BLE001 - best-effort teardown
            _LOG.warning("docker compose down failed: %s", exc)

        if override.is_file():
            try:
                override.unlink()
            except OSError as exc:
                _LOG.warning("Unable to remove compose label override %s: %s", override, exc)

        prune_cmd = [
            "docker",
            "ps",
            "-qa",
            "--filter",
            f"label=shieldclaw.run={result_id}",
        ]
        try:
            listed = self._run_capture(prune_cmd, cwd=cwd, timeout=_DOCKER_INFO_TIMEOUT)
        except Exception as exc:  # noqa: BLE001
            _LOG.warning("Unable to list labeled containers for prune: %s", exc)
            return

        for cid in listed.stdout.splitlines():
            cid = cid.strip()
            if not cid:
                continue
            rm_cmd = ["docker", "rm", "-f", cid]
            try:
                self._run_optional(rm_cmd, cwd=cwd, timeout=_DOCKER_INFO_TIMEOUT)
            except Exception as exc:  # noqa: BLE001
                _LOG.warning("docker rm -f %s failed: %s", cid, exc)

    def _ensure_docker(self) -> None:
        """Verify the Docker daemon responds to ``docker version``."""
        cmd = ["docker", "version", "--format", "{{.Server.Version}}"]
        _LOG.debug("Running command: %s", cmd)
        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=_DOCKER_INFO_TIMEOUT,
            )
        except FileNotFoundError as exc:
            raise DockerNotAvailableError("docker executable not found on PATH.") from exc
        except subprocess.TimeoutExpired as exc:
            raise DockerNotAvailableError("Docker daemon did not respond in time.") from exc
        except OSError as exc:
            raise DockerNotAvailableError("Unable to query Docker daemon.") from exc

        if completed.returncode != 0:
            detail = (completed.stderr or "").strip() or "unknown error"
            raise DockerNotAvailableError(f"Docker is not available: {detail}")

    def _cleanup_stale(self) -> None:
        """Remove any containers carrying the ShieldClaw run label."""
        list_cmd = ["docker", "ps", "-qa", "--filter", "label=shieldclaw.run"]
        _LOG.debug("Running command: %s", list_cmd)
        try:
            listed = subprocess.run(
                list_cmd,
                capture_output=True,
                text=True,
                timeout=_DOCKER_INFO_TIMEOUT,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
            raise SandboxStartError("Unable to list stale ShieldClaw containers.") from exc

        if listed.returncode != 0:
            raise SandboxStartError(
                f"docker ps filter failed: {(listed.stderr or '').strip() or 'no stderr'}"
            )

        ids = [line.strip() for line in listed.stdout.splitlines() if line.strip()]
        if not ids:
            return
        rm_cmd = ["docker", "rm", "-f", *ids]
        _LOG.debug("Running command: %s", rm_cmd)
        try:
            removed = subprocess.run(
                rm_cmd,
                capture_output=True,
                text=True,
                timeout=_DOCKER_INFO_TIMEOUT,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
            raise SandboxStartError("Unable to remove stale ShieldClaw containers.") from exc

        if removed.returncode != 0:
            detail = (removed.stderr or "").strip() or "docker rm failed"
            raise SandboxStartError(f"Stale container cleanup failed: {detail}")

    def _compose_command_prefix(self, compose_file: Path, override: Path, project: str) -> list[str]:
        """Build the shared ``docker compose`` prefix including optional label overrides."""
        if override.is_file():
            return [
                "docker",
                "compose",
                "-f",
                str(compose_file),
                "-f",
                str(override),
                "-p",
                project,
            ]
        return ["docker", "compose", "-f", str(compose_file), "-p", project]

    def _discover_service_names(self, compose_file: Path, cwd: Path) -> list[str]:
        """List declared compose service names via ``docker compose config --services``."""
        cmd = ["docker", "compose", "-f", str(compose_file), "config", "--services"]
        completed = self._run_required(
            cmd,
            cwd=cwd,
            timeout=_DOCKER_INFO_TIMEOUT,
            error_cls=SandboxStartError,
            error_prefix="docker compose config --services failed",
        )
        services = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
        if not services:
            raise SandboxStartError("docker compose config returned no services.")
        return services

    def _write_label_override(self, compose_file: Path, result_id: str, cwd: Path) -> Path:
        """Emit a temporary compose override that applies ``shieldclaw.run`` labels."""
        services = self._discover_service_names(compose_file, cwd)
        quoted = result_id.replace("\\", "\\\\").replace('"', '\\"')
        lines = ["services:"]
        for service in services:
            lines.append(f"  {service}:")
            lines.append("    labels:")
            lines.append(f'      shieldclaw.run: "{quoted}"')
        override = label_override_path(compose_file, result_id)
        try:
            override.write_text("\n".join(lines) + "\n", encoding="utf-8")
        except OSError as exc:
            raise SandboxStartError(f"Unable to write compose label override {override}.") from exc
        return override

    def _wait_for_compose_ready(
        self,
        compose_file: Path,
        override: Path,
        project: str,
        cwd: Path,
    ) -> None:
        """Poll ``docker compose ps`` until every service is up or timeout hits."""
        deadline = time.monotonic() + self._start_wait
        ps_cmd = self._compose_command_prefix(compose_file, override, project) + [
            "ps",
            "--format",
            "{{.State}}",
        ]
        while time.monotonic() < deadline:
            listed = self._run_required(
                ps_cmd,
                cwd=cwd,
                timeout=_DOCKER_INFO_TIMEOUT,
                error_cls=SandboxStartError,
                error_prefix="docker compose ps failed while waiting for startup",
            )
            states = [s.strip().lower() for s in listed.stdout.splitlines() if s.strip()]
            if not states:
                time.sleep(self._poll_interval)
                continue
            if all(self._state_is_up(s) for s in states):
                return
            time.sleep(self._poll_interval)
        raise SandboxStartError(
            f"Timed out after {self._start_wait} seconds waiting for compose services to start."
        )

    def _run_required(
        self,
        cmd: list[str],
        *,
        cwd: Path,
        timeout: float,
        error_cls: type[SandboxStartError] | type[DetonationError],
        error_prefix: str,
    ) -> subprocess.CompletedProcess[str]:
        """Execute a command that must succeed, wrapping failures in ``error_cls``."""
        _LOG.debug("Running command: %s", cmd)
        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(cwd),
            )
        except FileNotFoundError as exc:
            raise error_cls("docker executable not found on PATH.") from exc
        except subprocess.TimeoutExpired as exc:
            raise error_cls(f"Command timed out after {timeout} seconds: {' '.join(cmd)}") from exc
        except OSError as exc:
            raise error_cls(f"Unable to execute command: {' '.join(cmd)}") from exc

        if completed.returncode != 0:
            detail = (completed.stderr or "").strip() or (completed.stdout or "").strip() or "no output"
            raise error_cls(f"{error_prefix} (exit {completed.returncode}): {detail}")
        return completed

    def _run_optional(self, cmd: list[str], *, cwd: Path, timeout: float) -> subprocess.CompletedProcess[str]:
        """Execute a command for teardown paths; failures are handled by callers."""
        _LOG.debug("Running command: %s", cmd)
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(cwd),
        )

    def _run_capture(self, cmd: list[str], *, cwd: Path, timeout: float) -> subprocess.CompletedProcess[str]:
        """Run a command and return the completed process without enforcing success."""
        _LOG.debug("Running command: %s", cmd)
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(cwd),
        )

    @staticmethod
    def _state_is_up(state: str) -> bool:
        """Return True when ``docker compose ps`` reports a service as healthy."""
        if "exited" in state or "dead" in state:
            return False
        return "running" in state or state.startswith("up") or "healthy" in state

    @staticmethod
    def _looks_like_docker_client_error(stderr: str | None) -> bool:
        """Heuristic to distinguish Docker client failures from script exits."""
        if not stderr:
            return False
        lowered = stderr.lower()
        needles = (
            "docker:",
            "cannot connect",
            "error response from daemon",
            "no such container",
            "unable to find image",
            "pull access denied",
            "invalid reference",
        )
        return any(token in lowered for token in needles)

    def _force_remove_container(self, name: str) -> None:
        """Best-effort kill/remove for a timed-out attacker container."""
        kill_cmd = ["docker", "kill", name]
        _LOG.debug("Running command: %s", kill_cmd)
        try:
            subprocess.run(
                kill_cmd,
                capture_output=True,
                text=True,
                timeout=_DOCKER_INFO_TIMEOUT,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
            _LOG.warning("docker kill %s failed: %s", name, exc)
        rm_cmd = ["docker", "rm", "-f", name]
        _LOG.debug("Running command: %s", rm_cmd)
        try:
            subprocess.run(
                rm_cmd,
                capture_output=True,
                text=True,
                timeout=_DOCKER_INFO_TIMEOUT,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
            _LOG.warning("docker rm -f %s failed: %s", name, exc)
