"""Pure-logic approval gate for SAST findings.

This module contains no database imports — the orchestrator and ``__main__.py``
are responsible for reading/writing approval records.  ``gate.py`` provides
only formatting, environment-variable checks, and helper functions.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from shieldclaw.models import ExploitabilityScore, Finding, TriagedFinding

_AUTO_APPROVE_ENV = "SHIELDCLAW_AUTO_APPROVE"


def is_auto_approve_enabled() -> bool:
    """Return ``True`` when ``SHIELDCLAW_AUTO_APPROVE=1`` is set in the environment."""
    return os.environ.get(_AUTO_APPROVE_ENV, "").strip() == "1"


def get_current_user() -> str:
    """Return the current OS username with a safe fallback."""
    try:
        return os.getlogin()
    except (OSError, AttributeError):
        return (
            os.environ.get("USER")
            or os.environ.get("USERNAME")
            or os.environ.get("LOGNAME")
            or "unknown"
        )


@dataclass(frozen=True)
class ApprovalContext:
    """All information needed by a reviewer to approve or reject a finding.

    Args:
        finding: The SAST finding under review.
        triaged: Triage result with verdict and reason.
        score: LLM-assigned exploitability score, or ``None`` if unavailable.
        source_excerpt: Annotated source lines around the finding.
        compose_yaml: Docker Compose YAML for the target application.
        poc_code: Generated proof-of-concept script, or ``None`` if not yet created.
    """

    finding: Finding
    triaged: TriagedFinding
    score: ExploitabilityScore | None
    source_excerpt: str
    compose_yaml: str
    poc_code: str | None = None


def format_approval_context(ctx: ApprovalContext) -> str:
    """Render all approval-relevant information as a human-readable string.

    Args:
        ctx: Full approval context for a single finding.

    Returns:
        Multi-line string suitable for printing to a terminal.
    """
    score_line = "(not scored)"
    blast_line = ""
    if ctx.score is not None:
        score_line = (
            f"{ctx.score.score:.2f}  surface={ctx.score.attack_surface}  "
            f"model={ctx.score.model_name}"
        )
        prereqs = ", ".join(ctx.score.prerequisites) or "none"
        blast_line = (
            f"\n  Blast radius  : attack_surface={ctx.score.attack_surface}; "
            "will issue HTTP requests to compose-internal target only"
            f"\n  Prerequisites : {prereqs}"
            f"\n  Reasoning     : {ctx.score.reasoning}"
        )

    poc_section = (
        f"\n--- Generated PoC ---\n{ctx.poc_code}\n---------------------"
        if ctx.poc_code
        else "\n  (PoC not yet generated)"
    )

    return (
        f"\n{'=' * 72}\n"
        f"APPROVAL REQUIRED\n"
        f"{'=' * 72}\n"
        f"  Rule        : {ctx.finding.rule_id}\n"
        f"  Location    : {ctx.finding.path}:{ctx.finding.start_line}–{ctx.finding.end_line}\n"
        f"  Severity    : {ctx.finding.severity}\n"
        f"  CWE         : {', '.join(ctx.finding.cwe) or '—'}\n"
        f"  Message     : {ctx.finding.message}\n"
        f"  Verdict     : {ctx.triaged.verdict.value}  ({ctx.triaged.reason})\n"
        f"  Score       : {score_line}"
        f"{blast_line}\n"
        f"\n--- Source excerpt ---\n{ctx.source_excerpt}\n---------------------"
        f"{poc_section}\n"
        f"{'=' * 72}\n"
    )
