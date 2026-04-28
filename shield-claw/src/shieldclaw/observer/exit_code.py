"""Tier-1 exit-code observer: wraps exit_code/stdout/stderr into ObserverEvidence."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from shieldclaw.models import DetonationObserver, ObserverEvidence


class ExitCodeObserver(DetonationObserver):
    """Tier-1 observer: records the exit code, stdout, and stderr triple.

    No system calls are made.  This observer is always registered and
    provides the baseline signal for verdict synthesis.
    """

    name = "exit_code"
    tier = 1

    def before_detonate(self, target_container_id: str | None, network_name: str) -> None:
        """No-op; no pre-detonation state needed."""
        return None

    def after_detonate(
        self,
        before_state: Any,
        exit_code: int,
        stdout: str,
        stderr: str,
        target_container_id: str | None,
    ) -> ObserverEvidence:
        """Capture exit code and output streams."""
        success = exit_code == 0
        payload = {
            "exit_code": exit_code,
            "stdout": stdout[:4000],
            "stderr": stderr[:4000],
        }
        summary = f"exit_code={exit_code}  {'EXPLOIT SUCCEEDED' if success else 'exploit failed'}"
        return ObserverEvidence(
            observer_name=self.name,
            tier=self.tier,
            captured_at=datetime.now(tz=UTC),
            summary=summary,
            payload_json=json.dumps(payload),
        )
