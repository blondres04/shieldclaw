"""Shared pytest fixtures providing sample model instances for unit tests."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest

from shieldclaw.models import (
    ContainerState,
    ContainerStatus,
    ExploitPayload,
    ScanContext,
    ScanResult,
)


@pytest.fixture
def sample_scan_result_id() -> UUID:
    """Returns a fixed UUID used for deterministic ScanResult fixtures."""

    return UUID("aaaaaaaa-bbbb-4ccc-dddd-eeeeeeeeeeee")


@pytest.fixture
def sample_payload_id() -> UUID:
    """Returns a fixed UUID used for deterministic ExploitPayload fixtures."""

    return UUID("11111111-2222-4333-8444-555555555555")


@pytest.fixture
def sample_scan_result(sample_scan_result_id: UUID) -> ScanResult:
    """Builds a ScanResult with typical success fields populated."""

    return ScanResult(
        result_id=sample_scan_result_id,
        exit_code=0,
        is_vulnerable=False,
        pipeline_error=None,
        duration_seconds=12.5,
    )


@pytest.fixture
def sample_scan_context() -> ScanContext:
    """Builds a ScanContext with placeholder diff and compose content."""

    return ScanContext(
        target_dir="/tmp/shieldclaw-target",
        git_diff_content="diff --git a/app.py b/app.py\n+print('x')\n",
        docker_compose_content="services:\n  web:\n    image: nginx\n",
        timestamp=datetime(2026, 4, 13, 12, 0, tzinfo=UTC),
    )


@pytest.fixture
def sample_exploit_payload(sample_payload_id: UUID) -> ExploitPayload:
    """Builds an ExploitPayload describing a trivial proof-of-concept."""

    return ExploitPayload(
        payload_id=sample_payload_id,
        raw_code="print('poc')",
        target_dns="victim.test",
        execution_command="python3 payload.py",
        language="python",
    )


@pytest.fixture
def sample_container_state() -> ContainerState:
    """Builds a ContainerState representing a healthy running sandbox."""

    return ContainerState(
        status=ContainerStatus.RUNNING,
        attacker_container_id="abc123def456",
        startup_logs="container started\n",
    )
