"""End-to-end pipeline coordinating context, LLM, Docker, and reporting stages."""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Final

from shieldclaw.context.aggregator import ContextAggregator
from shieldclaw.exceptions import SandboxStartError, ShieldClawError
from shieldclaw.intelligence.anthropic_provider import AnthropicProvider
from shieldclaw.intelligence.base import LLMProvider
from shieldclaw.intelligence.ollama import OllamaProvider
from shieldclaw.intelligence.openai_provider import OpenAIProvider
from shieldclaw.models import ExploitPayload, ScanContext, ScanResult
from shieldclaw.reporting.builder import ReportBuilder
from shieldclaw.sandbox.docker_orchestrator import DockerOrchestrator, compose_default_network

_LOG = logging.getLogger(__name__)

_COMPOSE_CANDIDATES: Final[tuple[str, ...]] = ("docker-compose.yml", "docker-compose.yaml")

_STATE_INIT: Final = "INIT"
_STATE_CONTEXT_AGGREGATED: Final = "CONTEXT_AGGREGATED"
_STATE_PAYLOAD_GENERATED: Final = "PAYLOAD_GENERATED"
_STATE_SANDBOX_RUNNING: Final = "SANDBOX_RUNNING"
_STATE_DETONATION_COMPLETE: Final = "DETONATION_COMPLETE"
_STATE_TEARDOWN_COMPLETE: Final = "TEARDOWN_COMPLETE"
_STATE_FAILED: Final = "FAILED"


def _resolve_compose_path(target_dir: str) -> str | None:
    """Locate a compose file beside the repository root, mirroring aggregator rules."""
    root = Path(target_dir).expanduser().resolve()
    for name in _COMPOSE_CANDIDATES:
        candidate = root / name
        if candidate.is_file():
            return str(candidate.resolve())
    return None


def default_provider_factory(provider_name: str) -> LLMProvider:
    """Construct the default ``LLMProvider`` implementation for a CLI name.

    Args:
        provider_name: One of ``ollama``, ``openai``, or ``anthropic`` (case-insensitive).

    Returns:
        A concrete provider instance.

    Raises:
        ValueError: When ``provider_name`` is not recognized.
    """
    match provider_name.lower():
        case "ollama":
            return OllamaProvider()
        case "openai":
            return OpenAIProvider()
        case "anthropic":
            return AnthropicProvider()
        case _:
            raise ValueError(f"Unknown LLM provider: {provider_name!r}")


class Orchestrator:
    """Runs the ShieldClaw scan pipeline with deterministic cleanup and reporting."""

    def __init__(
        self,
        *,
        context_aggregator: ContextAggregator | None = None,
        docker_orchestrator: DockerOrchestrator | None = None,
        report_builder: ReportBuilder | None = None,
        provider_factory: Callable[[str], LLMProvider] | None = None,
    ) -> None:
        """Wire pipeline collaborators (defaults use production implementations).

        Args:
            context_aggregator: Optional override for repository context loading.
            docker_orchestrator: Optional override for compose and detonation control.
            report_builder: Optional override for JSON emission.
            provider_factory: Callable mapping ``provider_name`` to an ``LLMProvider``.
        """
        self._aggregator = context_aggregator or ContextAggregator()
        self._docker = docker_orchestrator or DockerOrchestrator()
        self._reports = report_builder or ReportBuilder()
        self._provider_factory = provider_factory or default_provider_factory

    def run(
        self,
        target_dir: str,
        diff_path: str | None,
        provider_name: str,
        timeout: int,
        output_path: str | None,
    ) -> ScanResult:
        """Execute the scan pipeline and always emit a structured report.

        Args:
            target_dir: Repository root passed to the context aggregator.
            diff_path: Optional patch path; ``None`` triggers ``git diff HEAD~1``.
            provider_name: ``ollama``, ``openai``, or ``anthropic``.
            timeout: Detonation timeout forwarded to ``DockerOrchestrator.detonate``.
            output_path: Optional filesystem sink for JSON; ``None`` prints to stdout.

        Returns:
            The final ``ScanResult`` including duration and any captured error text.

        Raises:
            ValueError: When ``provider_name`` is unknown (not a ``ShieldClawError``).
            BaseException: Any non-``ShieldClawError`` failure propagates after ``finally``.
        """
        result_id = uuid.uuid4()
        result_token = str(result_id)
        started = time.monotonic()
        state = _STATE_INIT

        ctx: ScanContext | None = None
        payload: ExploitPayload | None = None
        compose_path_str: str | None = None
        exit_code: int | None = None
        is_vulnerable: bool | None = None
        pipeline_error: str | None = None

        final_result: ScanResult | None = None

        try:
            provider = self._provider_factory(provider_name)
            while state not in (_STATE_TEARDOWN_COMPLETE, _STATE_FAILED):
                match state:
                    case "INIT":
                        ctx = self._aggregator.aggregate(target_dir, diff_path)
                        compose_path_str = _resolve_compose_path(target_dir)
                        state = _STATE_CONTEXT_AGGREGATED
                    case "CONTEXT_AGGREGATED":
                        assert ctx is not None
                        payload = provider.generate_exploit(ctx)
                        state = _STATE_PAYLOAD_GENERATED
                    case "PAYLOAD_GENERATED":
                        if compose_path_str is None:
                            raise SandboxStartError(
                                "docker compose file missing after successful aggregation."
                            )
                        assert payload is not None
                        self._docker.start_sandbox(compose_path_str, result_token)
                        state = _STATE_SANDBOX_RUNNING
                    case "SANDBOX_RUNNING":
                        assert payload is not None
                        network = compose_default_network(result_token)
                        exit_code = self._docker.detonate(
                            payload,
                            network_name=network,
                            result_id=result_token,
                            timeout=timeout,
                        )
                        is_vulnerable = exit_code == 0
                        state = _STATE_DETONATION_COMPLETE
                    case "DETONATION_COMPLETE":
                        state = _STATE_TEARDOWN_COMPLETE
                    case _:
                        raise RuntimeError(f"Invalid pipeline state: {state!r}")
        except ShieldClawError as exc:
            pipeline_error = exc.message
            _LOG.error("Pipeline halted: %s", exc.message, exc_info=True)
            state = _STATE_FAILED
        finally:
            teardown_compose = compose_path_str or str(
                Path(target_dir).expanduser().resolve() / "docker-compose.yml"
            )
            self._docker.teardown(teardown_compose, result_token)
            duration_seconds = time.monotonic() - started
            final_result = ScanResult(
                result_id=result_id,
                exit_code=exit_code,
                is_vulnerable=is_vulnerable,
                pipeline_error=pipeline_error,
                duration_seconds=duration_seconds,
                exploit_payload=payload,
                container_state=None,
            )
            self._reports.write(self._reports.build(final_result), output_path)
        assert final_result is not None
        return final_result
