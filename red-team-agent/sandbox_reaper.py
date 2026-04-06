"""
Reap orphaned Shield Claw sandbox resources when the agent process dies
before normal container cleanup (no finally block runs).

Run manually or on a schedule, e.g. cron every five minutes.
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime, timezone

import docker
import docker.errors

logger = logging.getLogger(__name__)

SANDBOX_LABEL_FILTER = "shieldclaw-sandbox=true"
MAX_RUNNING_AGE_SEC = 10 * 60
SHIELDCLAW_NETWORK_PREFIX = "shieldclaw"


def _parse_started_at(started_at: str) -> datetime | None:
    if not started_at or started_at.startswith("0001-01-01"):
        return None
    normalized = started_at.replace("Z", "+00:00")
    return datetime.fromisoformat(normalized)


def reap_stale_sandboxes(client: docker.DockerClient) -> None:
    containers = client.containers.list(
        all=True,
        filters={"label": SANDBOX_LABEL_FILTER},
    )
    now = datetime.now(timezone.utc)
    for container in containers:
        state = container.attrs.get("State") or {}
        if not state.get("Running"):
            continue
        started = _parse_started_at(state.get("StartedAt") or "")
        if started is None:
            continue
        age_sec = (now - started.astimezone(timezone.utc)).total_seconds()
        if age_sec <= MAX_RUNNING_AGE_SEC:
            continue
        cid_short = container.short_id
        try:
            logger.info(
                "Reaping stale sandbox container %s (%s), running %.0fs",
                cid_short,
                container.name or "(no name)",
                age_sec,
            )
            container.kill()
            container.remove()
            logger.info("Killed and removed %s", cid_short)
        except docker.errors.APIError as exc:
            logger.warning("Could not reap %s: %s", cid_short, exc)


def prune_dangling_shieldclaw_networks(client: docker.DockerClient) -> None:
    for network in client.networks.list():
        name = network.name
        if not name.lower().startswith(SHIELDCLAW_NETWORK_PREFIX):
            continue
        try:
            network.reload()
        except docker.errors.NotFound:
            continue
        containers = (network.attrs or {}).get("Containers") or {}
        if containers:
            continue
        try:
            logger.info("Removing dangling network %r", name)
            network.remove()
            logger.info("Removed network %r", name)
        except docker.errors.APIError as exc:
            logger.warning("Could not remove network %r: %s", name, exc)


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        stream=sys.stdout,
    )
    try:
        client = docker.from_env()
        client.ping()
    except docker.errors.DockerException as exc:
        logger.error("Docker unavailable: %s", exc)
        return 1

    reap_stale_sandboxes(client)
    prune_dangling_shieldclaw_networks(client)
    logger.info("Sandbox reaper finished")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
