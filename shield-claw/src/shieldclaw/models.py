"""Core dataclasses representing scan results, context, payloads, and sandbox state."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from uuid import UUID


class ContainerStatus(Enum):
    """Allowed lifecycle values for a sandbox attacker container."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    STOPPED = "STOPPED"
    FAILED = "FAILED"


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Outcome metadata for a completed or failed scan pipeline run.

    Args:
        result_id: Unique identifier for this scan result record.
        exit_code: Process exit code from the scan runner, if applicable.
        is_vulnerable: Whether the scan classified the change as exploitable.
        pipeline_error: Human-readable error when the pipeline failed.
        duration_seconds: Wall-clock duration of the scan in seconds.
    """

    result_id: UUID
    exit_code: int | None = None
    is_vulnerable: bool | None = None
    pipeline_error: str | None = None
    duration_seconds: float | None = None


@dataclass(frozen=True, slots=True)
class ScanContext:
    """Immutable inputs gathered before analysis and sandbox execution.

    Args:
        target_dir: Filesystem path to the repository under test.
        git_diff_content: Unified diff text describing proposed changes.
        docker_compose_content: Compose file content used to model services.
        timestamp: When the context snapshot was captured.
    """

    target_dir: str
    git_diff_content: str
    docker_compose_content: str
    timestamp: datetime


@dataclass(frozen=True, slots=True)
class ExploitPayload:
    """Executable exploit artifact produced for validation in isolation.

    Args:
        payload_id: Unique identifier for this payload instance.
        raw_code: Source or script body intended for execution.
        target_dns: Hostname or DNS name the payload expects to reach.
        execution_command: Shell or runtime command used to run the payload.
        language: Programming or scripting language label for the payload.
    """

    payload_id: UUID
    raw_code: str
    target_dns: str
    execution_command: str
    language: str


@dataclass(frozen=True, slots=True)
class ContainerState:
    """Runtime view of the attacker sandbox container.

    Args:
        status: Current lifecycle state of the container.
        attacker_container_id: Docker (or runtime) identifier when assigned.
        startup_logs: Captured stdout/stderr from container startup.
    """

    status: ContainerStatus
    attacker_container_id: str | None = None
    startup_logs: str | None = None
