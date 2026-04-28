"""Unit tests for the deterministic verdict synthesizer."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from shieldclaw.models import ObserverEvidence, Verdict
from shieldclaw.verdict.synthesizer import synthesize


def _exit_ev(exit_code: int, stdout: str = "", stderr: str = "") -> ObserverEvidence:
    return ObserverEvidence(
        observer_name="exit_code",
        tier=1,
        captured_at=datetime(2026, 1, 1, tzinfo=UTC),
        summary=f"exit_code={exit_code}",
        payload_json=json.dumps({"exit_code": exit_code, "stdout": stdout, "stderr": stderr}),
    )


def _diff_ev(
    added: list[str],
    modified: list[str] | None = None,
    deleted: list[str] | None = None,
) -> ObserverEvidence:
    m = modified or []
    d = deleted or []
    return ObserverEvidence(
        observer_name="docker_diff",
        tier=2,
        captured_at=datetime(2026, 1, 1, tzinfo=UTC),
        summary="diff evidence",
        payload_json=json.dumps({"added": added, "modified": m, "deleted": d}),
    )


def _log_ev(has_200: bool = False, has_error: bool = False) -> ObserverEvidence:
    return ObserverEvidence(
        observer_name="target_logs",
        tier=2,
        captured_at=datetime(2026, 1, 1, tzinfo=UTC),
        summary="log evidence",
        payload_json=json.dumps({"lines": [], "has_200": has_200, "has_error": has_error}),
    )


class TestSynthesize:
    def test_no_evidence_is_inconclusive(self) -> None:
        v = synthesize([])
        assert v.verdict == "INCONCLUSIVE"
        assert v.confidence < 0.3

    def test_true_positive_exit0_with_diff(self) -> None:
        v = synthesize([_exit_ev(0), _diff_ev(["/app/hacked"])])
        assert v.verdict == "TRUE_POSITIVE"
        assert v.confidence >= 0.90

    def test_true_positive_exit0_with_200_log(self) -> None:
        v = synthesize([_exit_ev(0), _log_ev(has_200=True)])
        assert v.verdict == "TRUE_POSITIVE"

    def test_true_positive_exit0_with_error_log(self) -> None:
        v = synthesize([_exit_ev(0), _log_ev(has_error=True)])
        assert v.verdict == "TRUE_POSITIVE"

    def test_inconclusive_exit0_no_tier2_corroboration(self) -> None:
        v = synthesize([_exit_ev(0), _diff_ev([], [], [])])
        assert v.verdict == "INCONCLUSIVE"
        assert 0.4 <= v.confidence <= 0.6

    def test_false_positive_timeout(self) -> None:
        v = synthesize([_exit_ev(124)])
        assert v.verdict == "FALSE_POSITIVE"
        assert v.confidence >= 0.80

    def test_false_positive_nonzero(self) -> None:
        v = synthesize([_exit_ev(1)])
        assert v.verdict == "FALSE_POSITIVE"

    def test_false_positive_exit2(self) -> None:
        v = synthesize([_exit_ev(2)])
        assert v.verdict == "FALSE_POSITIVE"

    def test_returns_verdict_dataclass(self) -> None:
        v = synthesize([_exit_ev(0)])
        assert isinstance(v, Verdict)
        assert v.verdict in ("TRUE_POSITIVE", "FALSE_POSITIVE", "INCONCLUSIVE")
        assert 0.0 <= v.confidence <= 1.0
        assert v.evidence_summary

    def test_skipped_diff_does_not_corroborate(self) -> None:
        skipped = ObserverEvidence(
            observer_name="docker_diff",
            tier=2,
            captured_at=datetime(2026, 1, 1, tzinfo=UTC),
            summary="skipped",
            payload_json=json.dumps({"skipped": True}),
        )
        v = synthesize([_exit_ev(0), skipped])
        assert v.verdict == "INCONCLUSIVE"

    def test_evidence_text_in_summary(self) -> None:
        v = synthesize([_exit_ev(0), _diff_ev(["/new"])])
        assert "exit_code" in v.evidence_summary
        assert "docker_diff" in v.evidence_summary
