"""Tier-2 observer: captures ``docker diff`` output on the target container.

Records which paths were added (A), modified (C), or deleted (D) during
the detonation window, after filtering out noise paths such as ``/tmp``,
``/var/log``, ``/proc``, and ``/sys``.
"""

from __future__ import annotations

import json
import logging
import subprocess
from datetime import UTC, datetime
from typing import Any

from shieldclaw.models import DetonationObserver, ObserverEvidence

_LOG = logging.getLogger(__name__)

_NOISE_PREFIXES: tuple[str, ...] = (
    "/tmp/",
    "/var/log/",
    "/var/tmp/",
    "/proc/",
    "/sys/",
    "/dev/",
    "/run/",
)
_DOCKER_TIMEOUT = 15.0


def _is_noise(path: str) -> bool:
    return any(path.startswith(p) for p in _NOISE_PREFIXES)


class DockerDiffObserver(DetonationObserver):
    """Tier-2 observer: ``docker diff`` on the target container after detonation.

    The ``before_detonate`` method is a no-op; the diff inherently shows
    all changes since the container started, which covers the detonation
    window without a baseline snapshot.
    """

    name = "docker_diff"
    tier = 2

    def before_detonate(self, target_container_id: str | None, network_name: str) -> None:
        return None

    def after_detonate(
        self,
        before_state: Any,
        exit_code: int,
        stdout: str,
        stderr: str,
        target_container_id: str | None,
    ) -> ObserverEvidence:
        if target_container_id is None:
            return ObserverEvidence(
                observer_name=self.name,
                tier=self.tier,
                captured_at=datetime.now(tz=UTC),
                summary="target container not available; observer skipped",
                payload_json=json.dumps({"skipped": True}),
            )

        added: list[str] = []
        modified: list[str] = []
        deleted: list[str] = []

        try:
            result = subprocess.run(
                ["docker", "diff", target_container_id],
                capture_output=True,
                text=True,
                timeout=_DOCKER_TIMEOUT,
            )
            for line in result.stdout.splitlines():
                line = line.strip()
                if len(line) < 3:
                    continue
                prefix, path = line[0], line[2:]
                if _is_noise(path):
                    continue
                if prefix == "A":
                    added.append(path)
                elif prefix == "C":
                    modified.append(path)
                elif prefix == "D":
                    deleted.append(path)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            _LOG.warning("docker diff failed for %s: %s", target_container_id, exc)
            return ObserverEvidence(
                observer_name=self.name,
                tier=self.tier,
                captured_at=datetime.now(tz=UTC),
                summary=f"docker diff error: {exc}",
                payload_json=json.dumps({"error": str(exc)}),
            )

        has_changes = bool(added or modified or deleted)
        summary = f"diff: {len(added)} added, {len(modified)} modified, {len(deleted)} deleted" + (
            " (non-trivial side-effects detected)" if has_changes else " (no side-effects)"
        )
        return ObserverEvidence(
            observer_name=self.name,
            tier=self.tier,
            captured_at=datetime.now(tz=UTC),
            summary=summary,
            payload_json=json.dumps({"added": added, "modified": modified, "deleted": deleted}),
        )
