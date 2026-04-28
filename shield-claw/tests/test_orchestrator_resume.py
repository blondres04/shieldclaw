"""Resumability test: a mid-run interrupt must not cause findings to be re-scored.

Test scenario
-------------
1. A ``CountingProvider`` is given to the orchestrator; it tracks how many
   times ``complete()`` is called and raises ``KeyboardInterrupt`` after
   the third call.
2. The SAST pipeline is run against a 5-finding fixture (all
   DYNAMICALLY_VERIFIABLE).  A ``KeyboardInterrupt`` fires mid-scoring
   (after findings 1, 2, 3 are scored).
3. The interrupted scan's ``scan_id`` is retrieved from the store.
4. A second orchestrator with a normal (always-succeeding) provider resumes
   with ``resume_scan_id=scan_id``.
5. Only 2 additional ``complete()`` calls happen (findings 4 and 5).
6. After the resume all 5 findings are in ``SCORED`` state.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shieldclaw.exceptions import LLMConnectionError
from shieldclaw.intelligence.base import LLMProvider
from shieldclaw.models import ExploitPayload, ScanContext
from shieldclaw.orchestrator import Orchestrator
from shieldclaw.persistence.store import ScanStore

_5DV_FIXTURE = Path(__file__).parent / "fixtures" / "semgrep_5dv.json"

_SCORE_JSON = json.dumps(
    {
        "score": 0.85,
        "attack_surface": "NETWORK",
        "prerequisites": [],
        "reasoning": "Direct user input to SQL query.",
    }
)


class CountingProvider(LLMProvider):
    """Provider that records complete() calls and interrupts after a threshold."""

    def __init__(self, interrupt_after: int = 3) -> None:
        self.complete_calls = 0
        self.interrupt_after = interrupt_after

    def generate_exploit(self, context: ScanContext) -> ExploitPayload:
        raise LLMConnectionError("CountingProvider is for scoring only")

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        self.complete_calls += 1
        if self.complete_calls > self.interrupt_after:
            raise KeyboardInterrupt(f"Simulated interrupt after {self.interrupt_after} completions")
        return _SCORE_JSON


class NormalProvider(LLMProvider):
    """Provider that always succeeds and records call count."""

    def __init__(self) -> None:
        self.complete_calls = 0

    def generate_exploit(self, context: ScanContext) -> ExploitPayload:
        raise LLMConnectionError("NormalProvider is for scoring only")

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        self.complete_calls += 1
        return _SCORE_JSON


@pytest.fixture
def repo_dir(tmp_path: Path) -> Path:
    """Minimal repo with a compose file so orchestrator target validation passes."""
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  web:\n    image: nginx:alpine\n",
        encoding="utf-8",
    )
    return tmp_path


def test_resume_skips_already_scored_findings(repo_dir: Path) -> None:
    """Mid-run interrupt followed by resume must call complete() only for unseen findings."""
    counting_provider = CountingProvider(interrupt_after=3)

    orch1 = Orchestrator(provider_factory=lambda _: counting_provider)

    # First run — expect KeyboardInterrupt after finding 3 is scored.
    with pytest.raises(KeyboardInterrupt):
        orch1.run(
            target_dir=str(repo_dir),
            semgrep_output=str(_5DV_FIXTURE),
        )

    # The interrupt fires on the 4th call (after incrementing the counter but
    # before the response is used), so the counter reaches 4 even though only
    # 3 findings were actually scored successfully.
    assert counting_provider.complete_calls == 4, (
        f"Expected 4 complete() attempts before interrupt; got {counting_provider.complete_calls}"
    )

    # Retrieve the interrupted scan's ID from the store.
    store = ScanStore(str(repo_dir))
    latest = store.get_latest_scan(str(repo_dir))
    assert latest is not None, "No scan record found after interrupted run"
    scan_id = latest.scan_id

    # Confirm 3 findings are SCORED and 2 are still TRIAGED.
    counts_before = store.count_findings_by_state(scan_id)
    assert counts_before.get("SCORED", 0) == 3, f"Expected 3 SCORED; got {counts_before}"
    assert counts_before.get("TRIAGED", 0) == 2, f"Expected 2 TRIAGED; got {counts_before}"

    # Second run — resume.
    normal_provider = NormalProvider()
    orch2 = Orchestrator(provider_factory=lambda _: normal_provider)

    orch2.run(
        target_dir=str(repo_dir),
        semgrep_output=str(_5DV_FIXTURE),
        resume_scan_id=scan_id,
    )

    # Only 2 additional complete() calls (findings 4 and 5).
    assert normal_provider.complete_calls == 2, (
        f"Expected 2 complete() calls during resume; got {normal_provider.complete_calls}"
    )

    # All 5 findings should now be SCORED.
    counts_after = store.count_findings_by_state(scan_id)
    assert counts_after.get("SCORED", 0) == 5, f"Expected 5 SCORED after resume; got {counts_after}"
    assert counts_after.get("TRIAGED", 0) == 0, (
        f"Expected 0 TRIAGED after resume; got {counts_after}"
    )

    # Scan state should be COMPLETE.
    final_scan = store.load_scan(scan_id)
    assert final_scan is not None
    assert final_scan.state == "COMPLETE", f"Expected COMPLETE; got {final_scan.state}"


def test_scores_are_persisted_correctly(repo_dir: Path) -> None:
    """Scores written during the interrupted run must match the expected values."""
    counting_provider = CountingProvider(interrupt_after=5)  # no interrupt this time

    orch = Orchestrator(provider_factory=lambda _: counting_provider)
    orch.run(
        target_dir=str(repo_dir),
        semgrep_output=str(_5DV_FIXTURE),
    )

    store = ScanStore(str(repo_dir))
    latest = store.get_latest_scan(str(repo_dir))
    assert latest is not None
    scan_id = latest.scan_id
    counts = store.count_findings_by_state(scan_id)
    assert counts.get("SCORED", 0) == 5

    # Verify all 5 complete() calls happened.
    assert counting_provider.complete_calls == 5


def test_resume_with_unknown_scan_id_fails(repo_dir: Path) -> None:
    """Resuming a non-existent scan_id must raise ShieldClawError."""

    orch = Orchestrator()
    result = orch.run(
        target_dir=str(repo_dir),
        semgrep_output=str(_5DV_FIXTURE),
        resume_scan_id="00000000-0000-0000-0000-000000000000",
        provider_name="ollama",
    )
    # The orchestrator catches ShieldClawError and stores it in pipeline_error.
    assert result.pipeline_error is not None
    assert "not found" in result.pipeline_error.lower()


def test_fresh_run_without_resume_creates_new_scan(repo_dir: Path) -> None:
    """Two sequential fresh runs must create two distinct scan records."""
    provider = NormalProvider()
    orch = Orchestrator(provider_factory=lambda _: provider)

    orch.run(target_dir=str(repo_dir), semgrep_output=str(_5DV_FIXTURE))
    orch.run(target_dir=str(repo_dir), semgrep_output=str(_5DV_FIXTURE))

    store = ScanStore(str(repo_dir))
    scans = store.list_scans(str(repo_dir))
    assert len(scans) == 2, f"Expected 2 scans; found {len(scans)}"
    assert scans[0].scan_id != scans[1].scan_id


def test_out_of_scope_findings_are_not_scored(tmp_path: Path) -> None:
    """OUT_OF_SCOPE findings must not generate complete() calls."""
    # Create a fixture with only OUT_OF_SCOPE findings.
    oos_fixture = tmp_path / "oos.json"
    oos_fixture.write_text(
        json.dumps(
            {
                "results": [
                    {
                        "check_id": "dockerfile.security.rule",
                        "path": "Dockerfile",
                        "start": {"line": 1, "col": 1},
                        "end": {"line": 1, "col": 10},
                        "extra": {
                            "severity": "WARNING",
                            "message": "dockerfile rule",
                            "metadata": {},
                            "metavars": {},
                        },
                    }
                ],
                "errors": [],
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "docker-compose.yml").write_text("services:\n  web:\n    image: nginx\n")

    provider = NormalProvider()
    orch = Orchestrator(provider_factory=lambda _: provider)
    orch.run(target_dir=str(tmp_path), semgrep_output=str(oos_fixture))

    assert provider.complete_calls == 0, (
        f"OUT_OF_SCOPE finding triggered {provider.complete_calls} complete() call(s)"
    )
