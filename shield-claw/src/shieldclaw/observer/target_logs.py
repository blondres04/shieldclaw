"""Tier-2 observer: captures ``docker logs`` from the target container.

``before_detonate`` records the current timestamp as a high-water mark.
``after_detonate`` retrieves only the logs produced *after* that mark,
limiting the capture to the last 100 lines.
"""

from __future__ import annotations

import json
import logging
import subprocess
from datetime import UTC, datetime
from typing import Any

from shieldclaw.models import DetonationObserver, ObserverEvidence

_LOG = logging.getLogger(__name__)
_DOCKER_TIMEOUT = 15.0
_MAX_LOG_LINES = 100


class TargetLogObserver(DetonationObserver):
    """Tier-2 observer: ``docker logs --since <timestamp>`` on the target."""

    name = "target_logs"
    tier = 2

    def before_detonate(self, target_container_id: str | None, network_name: str) -> str:
        """Record UTC timestamp as the high-water mark.

        Returns:
            ISO-8601 timestamp string used as the ``--since`` argument.
        """
        return datetime.now(tz=UTC).isoformat()

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

        since = before_state if isinstance(before_state, str) else "1ns"
        log_lines: list[str] = []

        try:
            result = subprocess.run(
                ["docker", "logs", "--since", since, target_container_id],
                capture_output=True,
                text=True,
                timeout=_DOCKER_TIMEOUT,
            )
            combined = (result.stdout + result.stderr).splitlines()
            log_lines = combined[-_MAX_LOG_LINES:]
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            _LOG.warning("docker logs failed for %s: %s", target_container_id, exc)
            return ObserverEvidence(
                observer_name=self.name,
                tier=self.tier,
                captured_at=datetime.now(tz=UTC),
                summary=f"docker logs error: {exc}",
                payload_json=json.dumps({"error": str(exc)}),
            )

        # Heuristic: look for HTTP 200 responses and error keywords.
        log_text = "\n".join(log_lines)
        has_200 = " 200 " in log_text or '"status": 200' in log_text
        has_error = any(
            kw in log_text.lower() for kw in ("error", "exception", "traceback", "sqlalchemy")
        )

        summary = (
            f"captured {len(log_lines)} log lines since detonation"
            + (" (200 response detected)" if has_200 else "")
            + (" (server error detected)" if has_error else "")
        )
        return ObserverEvidence(
            observer_name=self.name,
            tier=self.tier,
            captured_at=datetime.now(tz=UTC),
            summary=summary,
            payload_json=json.dumps(
                {"lines": log_lines, "has_200": has_200, "has_error": has_error}
            ),
        )
