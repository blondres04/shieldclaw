"""Deterministic verdict synthesis from detonation observer evidence.

Synthesis rules (evaluated top-to-bottom; first match wins)
-----------------------------------------------------------

1. **TRUE_POSITIVE** (high confidence, 0.95):
   exit_code == 0 AND at least one Tier-2 observer reports a non-trivial
   side-effect.  For ``docker_diff``: the diff is non-empty after filtering.
   For ``target_logs``: at least one HTTP 200 response OR a stack trace is
   detected in the captured log window.

2. **INCONCLUSIVE** (medium confidence, 0.50):
   exit_code == 0 but NO Tier-2 observer corroborates a side-effect.
   This is the spoofed-stdout case: the exploit script exited cleanly but we
   cannot confirm the target was actually affected.  Flag for human review.

3. **FALSE_POSITIVE** (timeout, confidence 0.85):
   exit_code == 124 (detonation timed out).  Either the exploit never
   triggered or the target was unreachable within the time window.

4. **FALSE_POSITIVE** (non-zero, confidence 0.80):
   exit_code != 0 and not 124.  The exploit script itself reported failure.

5. **INCONCLUSIVE** (no evidence, confidence 0.10):
   Fallback when no observers are registered.

Public API
----------
- ``synthesize(evidence) -> Verdict``
"""

from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from typing import Literal

from shieldclaw.models import ObserverEvidence, Verdict

_LOG = logging.getLogger(__name__)


def _has_tier2_corroboration(evidence: Sequence[ObserverEvidence]) -> bool:
    """Return True when at least one Tier-2 observer reports a side-effect."""
    for ev in evidence:
        if ev.tier < 2:
            continue
        # docker_diff: non-empty added/modified/deleted lists
        if ev.observer_name == "docker_diff":
            try:
                payload = json.loads(ev.payload_json)
                if payload.get("skipped") or payload.get("error"):
                    continue
                if payload.get("added") or payload.get("modified") or payload.get("deleted"):
                    return True
            except (json.JSONDecodeError, AttributeError):
                pass
        # target_logs: HTTP 200 or server error in logs
        if ev.observer_name == "target_logs":
            try:
                payload = json.loads(ev.payload_json)
                if payload.get("skipped") or payload.get("error"):
                    continue
                if payload.get("has_200") or payload.get("has_error"):
                    return True
            except (json.JSONDecodeError, AttributeError):
                pass
    return False


def _get_exit_code(evidence: Sequence[ObserverEvidence]) -> int | None:
    """Extract exit_code from the Tier-1 ExitCodeObserver evidence."""
    for ev in evidence:
        if ev.observer_name == "exit_code":
            try:
                payload = json.loads(ev.payload_json)
                return int(payload["exit_code"])
            except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                pass
    return None


def synthesize(evidence: Sequence[ObserverEvidence]) -> Verdict:
    """Synthesise a verdict from all available observer evidence.

    Args:
        evidence: Collection of ``ObserverEvidence`` objects produced by
            the observers registered for the detonation.

    Returns:
        A deterministic ``Verdict`` describing the detonation outcome.
    """
    if not evidence:
        return Verdict(
            verdict="INCONCLUSIVE",
            confidence=0.10,
            evidence_summary="No observers registered; cannot determine outcome.",
        )

    exit_code = _get_exit_code(evidence)
    tier2_corroborated = _has_tier2_corroboration(evidence)

    # Collect a summary of all evidence.
    summaries = [f"{ev.observer_name}(tier{ev.tier}): {ev.summary}" for ev in evidence]
    evidence_text = " | ".join(summaries)

    verdict_str: Literal["TRUE_POSITIVE", "FALSE_POSITIVE", "INCONCLUSIVE"]

    if exit_code is None:
        # No exit-code observer; fall back to tier-2 only.
        if tier2_corroborated:
            verdict_str = "TRUE_POSITIVE"
            confidence = 0.70
            rationale = "Tier-2 observer reports side-effect (no exit code available)."
        else:
            verdict_str = "INCONCLUSIVE"
            confidence = 0.20
            rationale = "No exit code and no Tier-2 corroboration."
    elif exit_code == 0 and tier2_corroborated:
        # Rule 1: clear true positive.
        verdict_str = "TRUE_POSITIVE"
        confidence = 0.95
        rationale = "exit_code=0 and Tier-2 observer reports non-trivial side-effect."
    elif exit_code == 0:
        # Rule 2: spoofed-stdout / no corroboration.
        verdict_str = "INCONCLUSIVE"
        confidence = 0.50
        rationale = (
            "exit_code=0 but no Tier-2 observer corroborates a side-effect.  "
            "Script may have falsely reported success.  Flag for human review."
        )
    elif exit_code == 124:
        # Rule 3: timeout.
        verdict_str = "FALSE_POSITIVE"
        confidence = 0.85
        rationale = "Detonation timed out (exit_code=124).  Target may be unreachable."
    else:
        # Rule 4: explicit failure.
        verdict_str = "FALSE_POSITIVE"
        confidence = 0.80
        rationale = f"Exploit script exited with non-zero code {exit_code}."

    _LOG.debug(
        "Verdict synthesis: %s (confidence=%.2f)  evidence=%s",
        verdict_str,
        confidence,
        evidence_text,
    )

    return Verdict(
        verdict=verdict_str,
        confidence=confidence,
        evidence_summary=f"{rationale} Evidence: {evidence_text}",
    )
