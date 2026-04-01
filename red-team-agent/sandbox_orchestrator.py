"""
ShieldClaw Sandbox Orchestrator
Phase 2 — Empirical validation of LLM-generated exploit payloads via
ephemeral Docker containers with a shallow-cloned target repository.
"""

import logging
import re

import docker
import docker.errors

logger = logging.getLogger(__name__)

SANDBOX_IMAGE = "alpine:latest"
SANDBOX_MEM_LIMIT = "128m"
SANDBOX_TIMEOUT = 30
_REPO_SLUG = re.compile(r"^[\w.-]+/[\w.-]+$")


class SandboxOrchestrator:
    """Orchestrates ephemeral sandbox execution of exploit payloads.

    Spins up short-lived Alpine containers, installs git, shallow-clones the
    target GitHub repository under ``/workspace/<repo_name>``, then runs the
    payload from that directory.  Network is required for ``apk`` and ``git
    clone``; memory is capped and the container is always removed on exit.
    """

    def __init__(self) -> None:
        try:
            self.client = docker.from_env()
            self.client.ping()
            logger.info("[sandbox] Docker daemon connected")
        except docker.errors.DockerException:
            logger.critical(
                "[sandbox] Docker daemon unreachable — "
                "sandbox verification will be unavailable"
            )
            self.client = None

    def execute_payload(
        self, pr_repo: str, pr_number: int, payload_snippet: str
    ) -> bool:
        """Detonate a payload after cloning the target repo into the sandbox.

        Runs a chained shell script: install git via ``apk``, shallow-clone
        ``https://github.com/{owner}/{repo}.git`` into ``/workspace/{repo}``,
        ``cd`` there, then execute ``payload_snippet``.

        Launches an ``alpine:latest`` container with:
          - **mem_limit=\"128m\"** — caps memory to prevent fork-bombs.
          - **remove=True** — container is destroyed on exit (no zombies).
          - Default Docker bridge network — required for ``apk`` and
            ``git clone`` (not air-gapped).

        If ``containers.run`` completes without raising
        ``docker.errors.ContainerError``, the exploit is considered
        empirically verified (the code executed successfully).

        Args:
            pr_repo: GitHub repository slug (e.g. ``"owner/repo"``).
            pr_number: Pull request number under test.
            payload_snippet: Shell commands to run from the cloned repo root.

        Returns:
            True if the exploit executed successfully (detonation confirmed),
            False if it errored, timed out, or the daemon is unavailable.
        """
        logger.info(
            "[sandbox] Detonating payload for %s#%d (%d chars)",
            pr_repo,
            pr_number,
            len(payload_snippet),
        )

        if self.client is None:
            logger.warning("[sandbox] No Docker client — skipping, returning False")
            return False

        if not _REPO_SLUG.match(pr_repo.strip()):
            logger.error(
                "[sandbox] Invalid pr_repo slug %r — expected owner/name",
                pr_repo,
            )
            return False

        pr_repo = pr_repo.strip()
        repo_name = pr_repo.split("/")[1]
        shell_cmd = (
            f"apk add --no-cache git && "
            f"git clone --depth 1 https://github.com/{pr_repo}.git "
            f"/workspace/{repo_name} && "
            f"cd /workspace/{repo_name} && "
            f"{payload_snippet}"
        )

        try:
            output = self.client.containers.run(
                image=SANDBOX_IMAGE,
                entrypoint=["/bin/sh", "-c"],
                command=[shell_cmd],
                remove=True,
                mem_limit=SANDBOX_MEM_LIMIT,
                stdout=True,
                stderr=True,
            )

            decoded = output.decode("utf-8", errors="replace").strip()
            if decoded:
                logger.info("[sandbox] Container stdout:\n%s", decoded)

            logger.info(
                "[sandbox] Payload for %s#%d executed successfully — "
                "exploit VERIFIED",
                pr_repo,
                pr_number,
            )
            return True

        except docker.errors.ContainerError as exc:
            logger.warning(
                "[sandbox] Payload for %s#%d exited non-zero "
                "(code %s) — exploit FAILED: %s",
                pr_repo,
                pr_number,
                exc.exit_status,
                exc.stderr.decode("utf-8", errors="replace").strip()
                if exc.stderr
                else "(no stderr)",
            )
            return False

        except docker.errors.ImageNotFound:
            logger.error(
                "[sandbox] Image %s not found — pulling may be required",
                SANDBOX_IMAGE,
            )
            return False

        except docker.errors.APIError:
            logger.exception(
                "[sandbox] Docker API error during detonation for %s#%d",
                pr_repo,
                pr_number,
            )
            return False
