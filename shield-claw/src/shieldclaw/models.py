"""
File:        src/shieldclaw/models.py
Purpose:     Shared immutable dataclasses representing scan inputs, exploit payloads,
             container state, scan results, and SAST findings with triage verdicts.
Public API:
  - ContainerStatus (Enum: PENDING, RUNNING, STOPPED, FAILED)
  - ExploitPayload (frozen dataclass: payload_id, raw_code, target_dns, execution_command, language)
  - ContainerState (frozen dataclass: status, attacker_container_id, startup_logs)
  - ScanResult (frozen dataclass: result_id, exit_code, is_vulnerable, pipeline_error,
                duration_seconds, exploit_payload, container_state)
  - ScanContext (frozen dataclass: target_dir, git_diff_content, docker_compose_content, timestamp)
  - Finding (frozen dataclass: finding_id, rule_id, severity, path, start_line, end_line,
             message, cwe, metavars, raw_extra)
  - TriageVerdict (Enum: DYNAMICALLY_VERIFIABLE, STATIC_ONLY, OUT_OF_SCOPE)
  - TriagedFinding (frozen dataclass: finding, verdict, reason)
  - ObserverWarning (frozen dataclass: observer_name, message)
  - SASTFindingReport (frozen dataclass: per-finding SAST JSON report entry)
Depends On:
  - stdlib only (dataclasses, datetime, enum, typing, uuid)
Used By:
  - src/shieldclaw/orchestrator.py
  - src/shieldclaw/context/aggregator.py
  - src/shieldclaw/intelligence/base.py
  - src/shieldclaw/intelligence/ollama.py
  - src/shieldclaw/intelligence/parser.py
  - src/shieldclaw/intelligence/prompts.py
  - src/shieldclaw/sandbox/docker_orchestrator.py
  - src/shieldclaw/reporting/builder.py
  - src/shieldclaw/ingest/semgrep.py
  - src/shieldclaw/triage/classifier.py
Use Cases:
  - SCAN-001 (Run Vulnerability Scan)
  - SCAN-002 (Ingest and Triage SAST Findings)
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Literal
from uuid import UUID

# ---------------------------------------------------------------------------
# Sentinel value re-used across scoring and persistence layers.
# ---------------------------------------------------------------------------
_ATTACK_SURFACE = Literal["NETWORK", "FILE", "ENV", "OTHER"]
MVP_SUPPORTED_CWES: frozenset[str] = frozenset({"CWE-89"})


def normalize_cwe_id(raw_cwe: str) -> str:
    """Return a normalized ``CWE-<number>`` key from Semgrep metadata text."""
    return raw_cwe.split(":", 1)[0].strip().upper()


def has_mvp_supported_cwe(cwes: tuple[str, ...]) -> bool:
    """Return True when a finding belongs to the default SQLi-only MVP lane."""
    return any(normalize_cwe_id(cwe) in MVP_SUPPORTED_CWES for cwe in cwes)


class ContainerStatus(Enum):
    """Allowed lifecycle values for a sandbox attacker container."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    STOPPED = "STOPPED"
    FAILED = "FAILED"


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


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Outcome metadata for a completed or failed scan pipeline run.

    Args:
        result_id: Unique identifier for this scan result record.
        exit_code: Process exit code from the scan runner, if applicable.
        is_vulnerable: Whether the scan classified the change as exploitable.
        pipeline_error: Human-readable error when the pipeline failed.
        duration_seconds: Wall-clock duration of the scan in seconds.
        exploit_payload: Generated exploit metadata when the LLM stage succeeded.
        container_state: Sandbox container snapshot after execution when available.
    """

    result_id: UUID
    exit_code: int | None = None
    is_vulnerable: bool | None = None
    pipeline_error: str | None = None
    duration_seconds: float | None = None
    exploit_payload: ExploitPayload | None = None
    container_state: ContainerState | None = None
    scan_id: UUID | None = None
    findings: tuple[SASTFindingReport, ...] | None = None


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
class Finding:
    """A single SAST finding produced by ingesting a Semgrep JSON report.

    All fields are immutable.  ``metavars`` is a plain ``dict`` — callers must
    not mutate it; a future phase will convert it to a ``MappingProxyType``.

    Args:
        finding_id: Deterministic UUID derived from rule_id + path + line numbers
            via ``uuid.uuid5(NAMESPACE_URL, ...)``.
        rule_id: Fully-qualified Semgrep check identifier (e.g. ``python.flask.sqli``).
        severity: One of ``"INFO"``, ``"WARNING"``, or ``"ERROR"`` (normalised from
            Semgrep's ``extra.severity`` field).
        path: File path relative to the scanned repository root.
        start_line: 1-based line number where the finding starts.
        end_line: 1-based line number where the finding ends.
        message: Human-readable description from ``extra.message``.
        cwe: Tuple of CWE identifiers (e.g. ``("CWE-89",)``); empty when absent.
        metavars: Flattened map of metavariable name → ``abstract_content`` string.
        raw_extra: JSON-serialised original ``extra`` field, retained for debugging.
    """

    finding_id: UUID
    rule_id: str
    severity: Literal["INFO", "WARNING", "ERROR"]
    path: str
    start_line: int
    end_line: int
    message: str
    cwe: tuple[str, ...]
    metavars: dict[str, str]
    raw_extra: str


class TriageVerdict(Enum):
    """Classification of a SAST finding by whether it can be dynamically verified."""

    DYNAMICALLY_VERIFIABLE = "DYNAMICALLY_VERIFIABLE"
    STATIC_ONLY = "STATIC_ONLY"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"


class FindingState(Enum):
    """Persisted lifecycle states for a SAST finding within the pipeline."""

    INGESTED = "INGESTED"
    TRIAGED = "TRIAGED"
    SCORED = "SCORED"
    DEFERRED = "DEFERRED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    POC_GENERATED = "POC_GENERATED"
    VERDICTED = "VERDICTED"
    REFUSED = "REFUSED"


@dataclass(frozen=True, slots=True)
class TriagedFinding:
    """A ``Finding`` annotated with a triage verdict and human-readable reason.

    Args:
        finding: The underlying SAST finding.
        verdict: Triage classification produced by the classifier.
        reason: Short explanation of why this verdict was assigned.
    """

    finding: Finding
    verdict: TriageVerdict
    reason: str


@dataclass(frozen=True, slots=True)
class ExploitabilityScore:
    """LLM-assigned exploitability assessment for a single SAST finding.

    Args:
        score: Normalised exploitability probability in the range [0.0, 1.0].
            Higher values indicate higher confidence that the finding is
            exploitable in the described environment.
        attack_surface: How the vulnerability would be reached.
            ``NETWORK`` — via HTTP/WebSocket/RPC.
            ``FILE`` — via a crafted file upload or local path.
            ``ENV`` — via an environment variable or configuration value.
            ``OTHER`` — any other attack vector.
        prerequisites: Ordered list of preconditions an attacker must satisfy
            before exploitation is possible (e.g. "authenticated user").
        reasoning: One-sentence rationale for the assigned score.
        model_name: Identifier of the LLM that produced this score.
        scored_at: UTC timestamp when the scoring call completed.
    """

    score: float
    attack_surface: Literal["NETWORK", "FILE", "ENV", "OTHER"]
    prerequisites: tuple[str, ...]
    reasoning: str
    model_name: str
    scored_at: datetime


@dataclass(frozen=True, slots=True)
class ScoredFinding:
    """A ``TriagedFinding`` paired with an optional exploitability score.

    ``score`` is ``None`` for ``STATIC_ONLY`` and ``OUT_OF_SCOPE`` findings
    because calling the LLM for unverifiable findings wastes tokens.

    Args:
        triaged: The triaged finding this score is associated with.
        score: LLM-assigned score, or ``None`` when not applicable.
    """

    triaged: TriagedFinding
    score: ExploitabilityScore | None


# ---------------------------------------------------------------------------
# Final report payloads
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ObserverWarning:
    """Non-fatal observer failure captured during detonation.

    Args:
        observer_name: Name of the observer that failed.
        message: Human-readable failure detail from the observer exception.
    """

    observer_name: str
    message: str


@dataclass(frozen=True, slots=True)
class SASTFindingReport:
    """Serialized per-finding outcome included in the extended SAST JSON report.

    Args:
        finding_id: Stable identifier for the SAST finding.
        rule_id: Semgrep rule identifier.
        severity: Normalized Semgrep severity string.
        path: Repository-relative file path.
        start_line: First affected line in the source file.
        end_line: Last affected line in the source file.
        cwe: Tuple of associated CWE identifiers.
        state: Latest persisted pipeline state for this finding.
        triage_verdict: Optional triage classification string.
        triage_reason: Optional human-readable triage explanation.
        verdict: Optional final verdict string.
        verdict_confidence: Optional verdict confidence.
        verdict_summary: Optional final verdict summary.
        observer_warnings: Non-fatal observer failures captured during detonation.
    """

    finding_id: UUID
    rule_id: str
    severity: Literal["INFO", "WARNING", "ERROR"]
    path: str
    start_line: int
    end_line: int
    cwe: tuple[str, ...]
    state: str
    triage_verdict: str | None = None
    triage_reason: str | None = None
    verdict: str | None = None
    verdict_confidence: float | None = None
    verdict_summary: str | None = None
    observer_warnings: tuple[ObserverWarning, ...] = ()


# ---------------------------------------------------------------------------
# Observer protocol (interface defined here so both sandbox/ and observer/
# can import it from the shared leaf module without cross-feature imports).
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ObserverEvidence:
    """A single piece of evidence collected by a ``DetonationObserver``.

    Args:
        observer_name: Unique identifier for the observer that produced this.
        tier: 1 for exit-code observers, 2 for side-effect observers.
        captured_at: UTC timestamp when the evidence was captured.
        summary: One-line human-readable description.
        payload_json: Observer-specific structured data (JSON string).
    """

    observer_name: str
    tier: int
    captured_at: datetime
    summary: str
    payload_json: str


class DetonationObserver(ABC):
    """Abstract base for observers that run around a detonation.

    Implementations are passed to ``DockerOrchestrator.detonate()`` and
    called once before and once after the attacker container exits.

    ``before_state`` is opaque per-observer context: whatever ``before_detonate``
    returns is passed verbatim to ``after_detonate``.
    """

    name: str
    tier: int

    @abstractmethod
    def before_detonate(self, target_container_id: str | None, network_name: str) -> Any:
        """Snapshot or prepare state before the attacker container starts.

        Args:
            target_container_id: Docker ID of the target (victim) container,
                or ``None`` when not resolvable.
            network_name: Compose network the attacker will join.

        Returns:
            Opaque state value passed to ``after_detonate``.
        """
        ...

    @abstractmethod
    def after_detonate(
        self,
        before_state: Any,
        exit_code: int,
        stdout: str,
        stderr: str,
        target_container_id: str | None,
    ) -> ObserverEvidence:
        """Collect and return evidence after the attacker container exits.

        Args:
            before_state: Value returned by ``before_detonate``.
            exit_code: Process exit code of the attacker container.
            stdout: Captured stdout from the attacker run.
            stderr: Captured stderr from the attacker run.
            target_container_id: Docker ID of the target container, or ``None``.

        Returns:
            ``ObserverEvidence`` summarising what this observer observed.
        """
        ...


@dataclass(frozen=True, slots=True)
class DetonationOutcome:
    """Result returned by ``DockerOrchestrator.detonate()``.

    Args:
        exit_code: Process exit code from the exploit container (124 = timeout).
        evidence: Tuple of evidence collected by all registered observers.
        observer_warnings: Non-fatal observer failures captured during teardown.
    """

    exit_code: int
    evidence: tuple[ObserverEvidence, ...]
    observer_warnings: tuple[ObserverWarning, ...] = ()


# ---------------------------------------------------------------------------
# Verdict (synthesised from observer evidence)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Verdict:
    """Synthesised verdict for a single detonated finding.

    Args:
        verdict: ``"TRUE_POSITIVE"``, ``"FALSE_POSITIVE"``, or ``"INCONCLUSIVE"``.
        confidence: Confidence in the verdict in ``[0.0, 1.0]``.
        evidence_summary: Human-readable explanation of the synthesis decision.
    """

    verdict: Literal["TRUE_POSITIVE", "FALSE_POSITIVE", "INCONCLUSIVE"]
    confidence: float
    evidence_summary: str
