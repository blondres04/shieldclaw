"""Manage compose-backed targets and locked-down attacker containers for detonation.

Compose services receive ``shieldclaw.run`` labels via a generated override file so
engines that lack ``docker update --label-add`` (common on Windows Desktop) stay
compatible while still meeting labeling requirements.
"""

from __future__ import annotations

import hashlib
import logging
import os
import subprocess
import time
import uuid
from collections.abc import Sequence
from pathlib import Path

from shieldclaw.exceptions import DetonationError, DockerNotAvailableError, SandboxStartError
from shieldclaw.models import (
    DetonationObserver,
    DetonationOutcome,
    ExploitPayload,
    ObserverEvidence,
)

_LOG = logging.getLogger(__name__)

_DOCKER_INFO_TIMEOUT = 15.0
_COMPOSE_UP_TIMEOUT = 120.0
_START_POLL_INTERVAL = 2.0
_START_WAIT_SECONDS = 120.0

# Default tag for the pre-built attacker image.  Override via
# SHIELDCLAW_ATTACKER_IMAGE to pin a different version or registry.
_DETONATE_IMAGE_DEFAULT = "ghcr.io/blondres04/shieldclaw-attacker:0.1"


def _detonate_image() -> str:
    """Return the attacker image tag, consulting ``SHIELDCLAW_ATTACKER_IMAGE``."""
    return os.environ.get("SHIELDCLAW_ATTACKER_IMAGE", _DETONATE_IMAGE_DEFAULT)


def _compose_start_timeout() -> float:
    """Return the compose startup wait timeout from ``SHIELDCLAW_COMPOSE_START_TIMEOUT``.

    Falls back to ``_START_WAIT_SECONDS`` when the variable is unset or invalid.
    """
    raw = os.environ.get("SHIELDCLAW_COMPOSE_START_TIMEOUT", "")
    if raw:
        try:
            return float(raw)
        except ValueError:
            _LOG.warning(
                "SHIELDCLAW_COMPOSE_START_TIMEOUT=%r is not a valid float; using default %s s",
                raw,
                _START_WAIT_SECONDS,
            )
    return _START_WAIT_SECONDS


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
        start_wait_seconds: float | None = None,
        start_poll_interval: float = _START_POLL_INTERVAL,
        post_up_grace_seconds: float = 2.0,
    ) -> None:
        """Create an orchestrator with configurable startup polling.

        Args:
            start_wait_seconds: Maximum time to wait for compose services after ``up``.
                When ``None`` (the default), the value is read from the
                ``SHIELDCLAW_COMPOSE_START_TIMEOUT`` environment variable, falling back
                to ``120`` seconds when the variable is unset.
            start_poll_interval: Sleep interval between readiness probes.
            post_up_grace_seconds: Extra sleep after healthcheck gating completes.
                Reduced from 10 s to 2 s now that readiness is healthcheck-gated.
        """
        self._start_wait = (
            _compose_start_timeout() if start_wait_seconds is None else start_wait_seconds
        )
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
        compose_file = Path(compose_path).expanduser().resolve()
        if not compose_file.is_file():
            raise SandboxStartError(f"Compose file not found: {compose_file}")
        self._ensure_docker()
        self._probe_attacker_image()
        self._cleanup_stale(result_id)
        project = compose_project_name(result_id)
        cwd = compose_file.parent
        services = self._discover_service_names(compose_file, cwd)
        override = self._write_label_override(compose_file, result_id, services)
        up_cmd = self._compose_command_prefix(compose_file, override, project) + ["up", "-d"]
        self._run_required(
            up_cmd,
            cwd=cwd,
            timeout=_COMPOSE_UP_TIMEOUT,
            error_cls=SandboxStartError,
            error_prefix="docker compose up failed",
        )
        self._wait_for_compose_ready(project, cwd, services)
        if self._post_up_grace > 0:
            time.sleep(self._post_up_grace)

    def get_target_container_id(self, compose_path: str, result_id: str) -> str | None:
        """Resolve the primary target container ID for observer use.

        Queries ``docker compose ps --format json`` and returns the ID of the
        first non-database service (heuristic: skip services whose name contains
        ``db``, ``postgres``, ``mysql``, or ``redis``).

        Args:
            compose_path: Path to the compose file used for the stack.
            result_id: Run identifier used to scope the compose project.

        Returns:
            Docker container ID string, or ``None`` when not resolvable.
        """
        compose_file = Path(compose_path).expanduser().resolve()
        if not compose_file.is_file():
            return None
        project = compose_project_name(result_id)
        override = label_override_path(compose_file, result_id)
        cwd = compose_file.parent
        cmd = self._compose_command_prefix(compose_file, override, project) + [
            "ps",
            "--format",
            "json",
        ]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=_DOCKER_INFO_TIMEOUT,
                cwd=str(cwd),
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return None

        if result.returncode != 0:
            return None

        import json

        _db_keywords = ("db", "postgres", "mysql", "redis", "mongo")
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, list):
                containers = obj
            else:
                containers = [obj]
            for c in containers:
                if not isinstance(c, dict):
                    continue
                name = str(c.get("Name", c.get("Service", ""))).lower()
                if any(kw in name for kw in _db_keywords):
                    continue
                cid = c.get("ID") or c.get("Id")
                if cid:
                    return str(cid)
        return None

    def detonate(
        self,
        payload: ExploitPayload,
        network_name: str,
        result_id: str,
        timeout: int = 15,
        observers: Sequence[DetonationObserver] = (),
        target_container_id: str | None = None,
    ) -> DetonationOutcome:
        """Run exploit code inside a hardened, ephemeral Python container.

        Args:
            payload: Generated exploit metadata including ``raw_code``.
            network_name: Docker network shared with the vulnerable stack.
            result_id: Label value for ``shieldclaw.run``.
            timeout: Seconds to wait for the container to exit.
            observers: Optional observers called before and after detonation.
            target_container_id: Docker ID of the target (victim) container,
                passed to observers for side-effect inspection.

        Returns:
            ``DetonationOutcome`` containing the exit code and all observer evidence.

        Raises:
            DockerNotAvailableError: When Docker cannot be contacted.
            DetonationError: When the attacker container cannot be created or started.
        """
        self._ensure_docker()

        # Call before_detonate for all observers.
        before_states = [
            obs.before_detonate(target_container_id, network_name) for obs in observers
        ]

        container_name = f"shieldclaw-att-{uuid.uuid4().hex[:20]}"
        # The pre-built image's ENTRYPOINT already handles stdin exec; no
        # bootstrap script or pip install is needed.
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
            _detonate_image(),
        ]
        _LOG.debug("Running command: %s", cmd)
        exit_code: int
        stdout_text: str = ""
        stderr_text: str = ""

        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=float(timeout),
                input=payload.raw_code,
            )
            stdout_text = completed.stdout or ""
            stderr_text = completed.stderr or ""
        except subprocess.TimeoutExpired:
            _LOG.warning(
                "Detonation timed out after %s seconds; killing %s", timeout, container_name
            )
            self._force_remove_container(container_name)
            exit_code = 124
            evidence = tuple(
                obs.after_detonate(bs, exit_code, "", "", target_container_id)
                for obs, bs in zip(observers, before_states, strict=True)
            )
            return DetonationOutcome(exit_code=exit_code, evidence=evidence)
        except FileNotFoundError as exc:
            raise DetonationError("docker executable not found on PATH.") from exc
        except OSError as exc:
            raise DetonationError("Unable to execute docker run for detonation.") from exc

        if completed.returncode != 0 and self._looks_like_docker_client_error(stderr_text):
            detail = stderr_text.strip() or "docker run failed without stderr."
            raise DetonationError(f"Failed to start attacker container: {detail}")

        if completed.returncode != 0 and self._looks_like_docker_client_error(stdout_text):
            detail = stdout_text.strip()
            raise DetonationError(f"Failed to start attacker container: {detail}")

        if completed.returncode != 0:
            _LOG.info(
                "Exploit container exited %s; stdout=%r stderr=%r",
                completed.returncode,
                stdout_text[:4000],
                stderr_text[:4000],
            )

        exit_code = int(completed.returncode)

        # Call after_detonate for all observers.
        evidence_list: list[ObserverEvidence] = []
        for obs, bs in zip(observers, before_states, strict=True):
            try:
                ev = obs.after_detonate(
                    bs, exit_code, stdout_text, stderr_text, target_container_id
                )
                evidence_list.append(ev)
            except Exception as exc:  # noqa: BLE001
                _LOG.warning("Observer %s failed: %s", obs.name, exc)

        return DetonationOutcome(exit_code=exit_code, evidence=tuple(evidence_list))

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

    def _probe_attacker_image(self) -> None:
        """Verify the pre-built attacker image is present in the local Docker daemon.

        Raises:
            SandboxStartError: When the image is not found, with a clear message
                pointing to ``scripts/build_attacker_image.sh``.
        """
        image = _detonate_image()
        cmd = ["docker", "image", "inspect", "--format", "{{.Id}}", image]
        _LOG.debug("Running command: %s", cmd)
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=_DOCKER_INFO_TIMEOUT,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
            raise SandboxStartError(f"Unable to inspect attacker image {image!r}.") from exc

        if result.returncode != 0:
            raise SandboxStartError(
                f"Attacker image {image!r} not found in local Docker daemon.  "
                "Build it first:\n"
                "  cd shield-claw && bash scripts/build_attacker_image.sh\n"
                "Or set SHIELDCLAW_ATTACKER_IMAGE to an existing image tag."
            )
        _LOG.debug("Attacker image %s found (id prefix %s)", image, result.stdout.strip()[:12])

    def _cleanup_stale(self, result_id: str) -> None:
        """Remove any containers labeled with this run's ``shieldclaw.run`` value.

        Scoping to ``result_id`` ensures concurrent ShieldClaw runs do not
        destroy each other's containers.

        Args:
            result_id: The run identifier whose containers should be removed.
        """
        list_cmd = ["docker", "ps", "-qa", "--filter", f"label=shieldclaw.run={result_id}"]
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

    def _compose_command_prefix(
        self, compose_file: Path, override: Path, project: str
    ) -> list[str]:
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

    def _write_label_override(
        self, compose_file: Path, result_id: str, services: list[str]
    ) -> Path:
        """Emit a temporary compose override that applies ``shieldclaw.run`` labels.

        Args:
            compose_file: Path to the primary compose file (used to derive the
                override path via ``label_override_path``).
            result_id: Value written as ``shieldclaw.run`` on every service.
            services: Pre-discovered service names from ``_discover_service_names``.
        """
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

    def _is_service_healthy(self, service_name: str, project: str, cwd: Path) -> bool:
        """Return True when a service is running and its healthcheck is passing or absent.

        Docker Compose ≥ 2 names containers ``<project>-<service>-1``; legacy
        versions use ``<project>_<service>_1``.  Both conventions are probed.

        Args:
            service_name: Compose service name as returned by ``docker compose config``.
            project: Compose project name (derived from ``result_id``).
            cwd: Working directory for the ``docker inspect`` subprocess call.

        Returns:
            ``True`` when the container is ``running`` and health is ``healthy``
            or ``<no value>`` (no healthcheck configured).  ``False`` otherwise.
        """
        for sep in ("-", "_"):
            container = f"{project}{sep}{service_name}{sep}1"
            cmd = [
                "docker",
                "inspect",
                "--format",
                "{{.State.Health.Status}}\t{{.State.Status}}",
                container,
            ]
            _LOG.debug("Running command: %s", cmd)
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=_DOCKER_INFO_TIMEOUT,
                    cwd=str(cwd),
                )
            except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
                return False
            if result.returncode != 0:
                continue  # Container not found under this naming form; try the other.
            output = result.stdout.strip()
            if not output:
                continue
            health, _, status = output.partition("\t")
            if status.strip() != "running":
                return False
            # "<no value>" means no healthcheck is configured — treat as passing.
            return health.strip() in ("healthy", "<no value>", "")
        return False

    def _wait_for_compose_ready(
        self,
        project: str,
        cwd: Path,
        services: list[str],
    ) -> None:
        """Poll ``docker inspect`` until every service is running and healthcheck-passing.

        Args:
            project: Compose project name used to derive container names.
            cwd: Working directory for subprocess calls.
            services: Service names to probe; all must pass before returning.

        Raises:
            SandboxStartError: When the deadline expires before all services are ready.
        """
        deadline = time.monotonic() + self._start_wait
        while time.monotonic() < deadline:
            if all(self._is_service_healthy(svc, project, cwd) for svc in services):
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
            detail = (
                (completed.stderr or "").strip() or (completed.stdout or "").strip() or "no output"
            )
            raise error_cls(f"{error_prefix} (exit {completed.returncode}): {detail}")
        return completed

    def _run_optional(
        self, cmd: list[str], *, cwd: Path, timeout: float
    ) -> subprocess.CompletedProcess[str]:
        """Execute a command for teardown paths; failures are handled by callers."""
        _LOG.debug("Running command: %s", cmd)
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(cwd),
        )

    def _run_capture(
        self, cmd: list[str], *, cwd: Path, timeout: float
    ) -> subprocess.CompletedProcess[str]:
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
