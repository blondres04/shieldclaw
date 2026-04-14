"""Smoke tests ensuring model dataclasses construct and retain expected fields."""

from __future__ import annotations

from shieldclaw.models import (
    ContainerState,
    ContainerStatus,
    ExploitPayload,
    ScanContext,
    ScanResult,
)


def test_scan_result_fixture(sample_scan_result: ScanResult) -> None:
    """ScanResult fixture should hydrate with identifiers and metrics."""

    assert sample_scan_result.exit_code == 0
    assert sample_scan_result.is_vulnerable is False


def test_scan_context_fixture(sample_scan_context: ScanContext) -> None:
    """ScanContext fixture should preserve required textual inputs."""

    assert "diff --git" in sample_scan_context.git_diff_content
    assert "services:" in sample_scan_context.docker_compose_content


def test_exploit_payload_fixture(sample_exploit_payload: ExploitPayload) -> None:
    """ExploitPayload fixture should wire execution metadata."""

    assert sample_exploit_payload.language == "python"


def test_container_state_fixture(sample_container_state: ContainerState) -> None:
    """ContainerState fixture should report a running lifecycle."""

    assert sample_container_state.status is ContainerStatus.RUNNING
