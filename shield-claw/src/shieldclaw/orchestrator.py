"""
File:        src/shieldclaw/orchestrator.py
Purpose:     Pipeline state machine for both the v0.1 legacy (diff) path and the
             v0.2 SAST path (ingest → triage → score → persist), with resumability.
Public API:
  - default_provider_factory(provider_name: str) -> LLMProvider
  - Orchestrator (class)
    - run(*, target_dir, semgrep_output, diff_path, provider_name, timeout,
          output_path, resume_scan_id) -> ScanResult
Depends On:
  - shieldclaw.context.aggregator
  - shieldclaw.exceptions
  - shieldclaw.ingest.semgrep
  - shieldclaw.intelligence.base
  - shieldclaw.intelligence.ollama
  - shieldclaw.models
  - shieldclaw.persistence.store
  - shieldclaw.reporting.builder
  - shieldclaw.sandbox.docker_orchestrator
  - shieldclaw.scoring.exploitability
  - shieldclaw.triage.classifier
Used By:
  - src/shieldclaw/__main__.py
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Final, Literal, cast

from shieldclaw.context.aggregator import ContextAggregator
from shieldclaw.exceptions import SandboxStartError, ShieldClawError
from shieldclaw.intelligence.base import LLMProvider
from shieldclaw.intelligence.ollama import OllamaProvider
from shieldclaw.models import ExploitPayload, Finding, ScanContext, ScanResult, TriageVerdict
from shieldclaw.reporting.builder import ReportBuilder
from shieldclaw.sandbox.docker_orchestrator import DockerOrchestrator, compose_default_network

_LOG = logging.getLogger(__name__)

_COMPOSE_CANDIDATES: Final[tuple[str, ...]] = ("docker-compose.yml", "docker-compose.yaml")

# Legacy state constants (diff/detonation path).
_STATE_INIT: Final = "INIT"
_STATE_CONTEXT_AGGREGATED: Final = "CONTEXT_AGGREGATED"
_STATE_PAYLOAD_GENERATED: Final = "PAYLOAD_GENERATED"
_STATE_SANDBOX_RUNNING: Final = "SANDBOX_RUNNING"
_STATE_DETONATION_COMPLETE: Final = "DETONATION_COMPLETE"
_STATE_TEARDOWN_COMPLETE: Final = "TEARDOWN_COMPLETE"
_STATE_FAILED: Final = "FAILED"


def _resolve_compose_path(target_dir: str) -> str | None:
    root = Path(target_dir).expanduser().resolve()
    for name in _COMPOSE_CANDIDATES:
        candidate = root / name
        if candidate.is_file():
            return str(candidate.resolve())
    return None


def _read_compose_yaml(target_dir: str) -> str:
    """Return raw compose YAML from target_dir, or empty string if absent."""
    for name in _COMPOSE_CANDIDATES:
        p = Path(target_dir).expanduser().resolve() / name
        if p.is_file():
            return p.read_text(encoding="utf-8")
    return ""


def _extract_source_lines(target_dir: str, finding: Finding) -> str:
    """Return an annotated excerpt of the source file surrounding the finding.

    Lines between ``start_line - 5`` and ``end_line + 5`` are returned,
    clamped to the file's actual bounds.  Lines within the finding range are
    prefixed with ``>>>`` for clarity.
    """
    source_path = Path(target_dir).expanduser().resolve() / finding.path
    if not source_path.is_file():
        return f"# Source file not found: {finding.path}"
    try:
        lines = source_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return f"# Could not read: {finding.path}"
    total = len(lines)
    start_idx = max(0, finding.start_line - 6)
    end_idx = min(total, finding.end_line + 5)
    excerpt: list[str] = []
    for i, line in enumerate(lines[start_idx:end_idx], start=start_idx + 1):
        marker = ">>>" if finding.start_line <= i <= finding.end_line else "   "
        excerpt.append(f"{i:4d} {marker} {line}")
    return "\n".join(excerpt)


def _finding_from_row(row: object) -> Finding:
    """Reconstruct a ``Finding`` from a ``FindingRow`` returned by ``ScanStore``."""
    from shieldclaw.persistence.store import FindingRow

    assert isinstance(row, FindingRow)
    cwe_list: list[str] = json.loads(row.cwe)
    metavars: dict[str, str] = json.loads(row.metavars_json)
    raw_extra = row.raw_extra_json
    # Extract message from raw_extra (stored as JSON-serialised Semgrep extra).
    try:
        extra_obj = json.loads(raw_extra)
        message = str(extra_obj.get("message", "")) if isinstance(extra_obj, dict) else ""
    except (json.JSONDecodeError, AttributeError):
        message = ""
    severity = cast(Literal["INFO", "WARNING", "ERROR"], row.severity)
    return Finding(
        finding_id=uuid.UUID(row.finding_id),
        rule_id=row.rule_id,
        severity=severity,
        path=row.path,
        start_line=row.start_line,
        end_line=row.end_line,
        message=message,
        cwe=tuple(cwe_list),
        metavars=metavars,
        raw_extra=raw_extra,
    )


def default_provider_factory(provider_name: str) -> LLMProvider:
    """Construct the default ``LLMProvider`` for a CLI name.

    Only ``ollama`` is available until Phase 4 implements hosted providers.
    """
    match provider_name.lower():
        case "ollama":
            return OllamaProvider()
        case _:
            raise ValueError(f"Unknown LLM provider: {provider_name!r}")


class Orchestrator:
    """Runs the ShieldClaw pipeline in either SAST or legacy diff mode."""

    def __init__(
        self,
        *,
        context_aggregator: ContextAggregator | None = None,
        docker_orchestrator: DockerOrchestrator | None = None,
        report_builder: ReportBuilder | None = None,
        provider_factory: Callable[[str], LLMProvider] | None = None,
    ) -> None:
        self._aggregator = context_aggregator or ContextAggregator()
        self._docker = docker_orchestrator or DockerOrchestrator()
        self._reports = report_builder or ReportBuilder()
        self._provider_factory = provider_factory or default_provider_factory

    def run(
        self,
        target_dir: str | None = None,
        diff_path: str | None = None,
        provider_name: str = "ollama",
        timeout: int = 15,
        output_path: str | None = None,
        *,
        # keyword-only extras (Phase 2+)
        semgrep_output: str | None = None,
        resume_scan_id: str | None = None,
        # allow old positional callers to pass target_dir positionally
        _target_dir: str | None = None,
    ) -> ScanResult:
        """Execute the scan pipeline.

        Accepts both the legacy positional call signature
        ``run(target_dir, diff_path, provider_name, timeout, output_path)``
        and the new keyword-only form
        ``run(target_dir=..., semgrep_output=..., resume_scan_id=...)``.

        When ``semgrep_output`` is provided the SAST flow runs (ingest →
        triage → score → persist).  Otherwise the legacy diff/detonation
        path is used.

        Args:
            target_dir: Repository root.
            diff_path: Unified diff patch; ``None`` uses ``git diff HEAD~1``.
            provider_name: LLM backend name.
            timeout: Detonation timeout in seconds.
            output_path: JSON sink; ``None`` prints to stdout.
            semgrep_output: Path to Semgrep --json report (SAST mode).
            resume_scan_id: Existing scan UUID to resume.

        Returns:
            ``ScanResult`` containing run metadata.
        """
        resolved_target = target_dir or _target_dir
        if resolved_target is None:
            raise ValueError("target_dir is required")

        if semgrep_output is not None:
            return self._run_sast(
                target_dir=resolved_target,
                semgrep_output=semgrep_output,
                provider_name=provider_name,
                output_path=output_path,
                resume_scan_id=resume_scan_id,
            )
        return self._run_legacy(
            target_dir=resolved_target,
            diff_path=diff_path,
            provider_name=provider_name,
            timeout=timeout,
            output_path=output_path,
        )

    # ------------------------------------------------------------------
    # SAST path (Phase 2)
    # ------------------------------------------------------------------

    def _run_sast(
        self,
        *,
        target_dir: str,
        semgrep_output: str,
        provider_name: str,
        output_path: str | None,
        resume_scan_id: str | None,
    ) -> ScanResult:
        """Ingest → triage → score with SQLite persistence and resumability."""
        from shieldclaw.ingest.semgrep import parse_semgrep_json
        from shieldclaw.persistence.store import ScanStore
        from shieldclaw.scoring.exploitability import ExploitabilityScorer
        from shieldclaw.triage.classifier import classify

        result_id = uuid.uuid4()
        started = time.monotonic()
        pipeline_error: str | None = None
        final_result: ScanResult | None = None
        scan_id: str | None = None

        resolved_target = str(Path(target_dir).expanduser().resolve())

        try:
            provider = self._provider_factory(provider_name)
            scorer = ExploitabilityScorer(provider, model_name=provider_name)
            store = ScanStore(resolved_target)

            if resume_scan_id is not None:
                scan_row = store.load_scan(resume_scan_id)
                if scan_row is None:
                    raise ShieldClawError(f"resume_scan_id {resume_scan_id!r} not found in store")
                scan_id = resume_scan_id
                _LOG.info("Resuming scan %s (state=%s)", scan_id, scan_row.state)
            else:
                scan_id = str(uuid.uuid4())
                store.create_scan(scan_id, resolved_target, semgrep_output)
                _LOG.info("Starting new scan %s", scan_id)

                # Ingest
                store.update_scan_state(scan_id, "INGESTING")
                raw_findings = parse_semgrep_json(Path(semgrep_output))
                store.record_findings(scan_id, raw_findings)
                store.update_scan_state(scan_id, "INGESTED")
                _LOG.info("Ingested %d findings", len(raw_findings))

                # Triage
                store.update_scan_state(scan_id, "TRIAGING")
                for f in raw_findings:
                    tf = classify(f)
                    store.set_triage(str(f.finding_id), tf.verdict.value, tf.reason)
                    store.update_finding_state(str(f.finding_id), "TRIAGED")
                store.update_scan_state(scan_id, "TRIAGED")
                _LOG.info("Triage complete for %d findings", len(raw_findings))

            # Score — pick up any findings still in TRIAGED state.
            store.update_scan_state(scan_id, "SCORING")
            compose_yaml = _read_compose_yaml(resolved_target)
            pending = store.get_pending_findings(scan_id, "TRIAGED")
            _LOG.info("Scoring %d pending findings", len(pending))

            for row in pending:
                if row.triage_verdict == TriageVerdict.DYNAMICALLY_VERIFIABLE.value:
                    finding = _finding_from_row(row)
                    excerpt = _extract_source_lines(resolved_target, finding)
                    score = scorer.score(finding, excerpt, compose_yaml)
                    store.record_score(str(finding.finding_id), score)
                    _LOG.debug(
                        "Scored %s: %.2f (%s)", row.finding_id, score.score, score.attack_surface
                    )
                store.update_finding_state(row.finding_id, "SCORED")

            store.update_scan_state(scan_id, "COMPLETE")
            _LOG.info("Scan %s complete", scan_id)

        except ShieldClawError as exc:
            pipeline_error = exc.message
            _LOG.error("SAST pipeline halted: %s", exc.message, exc_info=True)
            if scan_id is not None:
                try:
                    from shieldclaw.persistence.store import ScanStore as _Store

                    _Store(resolved_target).update_scan_state(scan_id, "FAILED")
                except Exception:  # noqa: BLE001
                    pass
        finally:
            duration = time.monotonic() - started
            final_result = ScanResult(
                result_id=result_id,
                pipeline_error=pipeline_error,
                duration_seconds=duration,
            )
            self._reports.write(self._reports.build(final_result), output_path)

        assert final_result is not None
        return final_result

    # ------------------------------------------------------------------
    # Legacy diff/detonation path (v0.1 behaviour, preserved unchanged)
    # ------------------------------------------------------------------

    def _run_legacy(
        self,
        *,
        target_dir: str,
        diff_path: str | None,
        provider_name: str,
        timeout: int,
        output_path: str | None,
    ) -> ScanResult:
        """Execute the original v0.1 pipeline (context → exploit → detonate)."""
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
