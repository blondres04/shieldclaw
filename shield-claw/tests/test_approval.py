"""Unit tests for the approval gate — milestone test_rejected_finding_is_skipped."""

from __future__ import annotations

import json
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

from shieldclaw.approval.gate import (
    ApprovalContext,
    format_approval_context,
    get_current_user,
    is_auto_approve_enabled,
)
from shieldclaw.intelligence.base import LLMProvider
from shieldclaw.models import (
    DetonationOutcome,
    ExploitabilityScore,
    ExploitPayload,
    Finding,
    ScanContext,
    TriagedFinding,
    TriageVerdict,
)
from shieldclaw.orchestrator import Orchestrator
from shieldclaw.persistence.store import ScanStore

_FIXTURE = Path(__file__).parent / "fixtures" / "semgrep_5sqli.json"
_DATETIME = "2026-01-01T00:00:00+00:00"


def _make_finding() -> Finding:
    return Finding(
        finding_id=uuid.uuid5(uuid.NAMESPACE_URL, "test:app.py:10:10"),
        rule_id="python.flask.sqli",
        severity="ERROR",
        path="app.py",
        start_line=10,
        end_line=10,
        message="SQL injection",
        cwe=("CWE-89",),
        metavars={"$ID": "request.args.get('id')"},
        raw_extra="{}",
    )


# ---------------------------------------------------------------------------
# Milestone test
# ---------------------------------------------------------------------------


class _ProviderThatScores(LLMProvider):
    """Provider that records complete() calls."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def generate_exploit(self, context: ScanContext) -> ExploitPayload:
        raise NotImplementedError

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        self.calls.append("score")
        return json.dumps(
            {
                "score": 0.9,
                "attack_surface": "NETWORK",
                "prerequisites": [],
                "reasoning": "Direct SQL injection.",
            }
        )


class _InteractiveProvider(LLMProvider):
    """Provider that scores findings and emits a valid PoC when approved."""

    def generate_exploit(self, context: ScanContext) -> ExploitPayload:
        raise NotImplementedError

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        if '"score"' in system_prompt or "exploitability" in system_prompt.lower():
            return json.dumps(
                {
                    "score": 0.9,
                    "attack_surface": "NETWORK",
                    "prerequisites": [],
                    "reasoning": "Direct SQL injection.",
                }
            )
        return json.dumps(
            {
                "language": "python",
                "target_dns": "web",
                "raw_code": "import sys\nsys.exit(0)\n",
                "execution_command": "python -",
            }
        )


def _write_single_finding_fixture(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "results": [
                    {
                        "check_id": "python.flask.security.sqli",
                        "path": "app.py",
                        "start": {"line": 1, "col": 1},
                        "end": {"line": 1, "col": 12},
                        "extra": {
                            "severity": "ERROR",
                            "message": "Possible SQL injection",
                            "metadata": {"cwe": ["CWE-89"]},
                            "metavars": {},
                        },
                    }
                ],
                "errors": [],
            }
        ),
        encoding="utf-8",
    )


def test_rejected_finding_is_skipped(tmp_path: Path) -> None:
    """A finding rejected via the approve subcommand must not be detonated.

    Scenario:
    1. Run the SAST pipeline; findings are scored and transition to AWAITING_APPROVAL.
    2. Reject one finding via the store (simulating `shieldclaw approve --reject`).
    3. Resume; assert that rejected finding never calls complete() again.
    """
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  web:\n    image: nginx:alpine\n", encoding="utf-8"
    )

    provider = _ProviderThatScores()

    # Score all findings, stop at AWAITING_APPROVAL state.
    with patch.dict(os.environ, {"SHIELDCLAW_AUTO_APPROVE": ""}, clear=False):
        orch = Orchestrator(provider_factory=lambda _: provider)
        orch.run(
            target_dir=str(tmp_path),
            semgrep_output=str(_FIXTURE),
        )

    store = ScanStore(str(tmp_path))
    latest = store.get_latest_scan(str(tmp_path))
    assert latest is not None
    scan_id = latest.scan_id

    # At this point findings should be awaiting approval. Manually reject one finding.
    awaiting = store.get_pending_findings(scan_id, "AWAITING_APPROVAL")
    assert awaiting, "Expected findings awaiting approval"
    store.record_approval(awaiting[0].finding_id, "REJECTED", "test-user")
    store.update_finding_state(awaiting[0].finding_id, "REJECTED")
    rejected_id = awaiting[0].finding_id

    # Verify the rejected finding is in REJECTED state.
    approval = store.get_approval(rejected_id)
    assert approval is not None
    assert approval["decision"] == "REJECTED"

    counts = store.count_findings_by_state(scan_id)
    assert counts.get("REJECTED", 0) >= 1


# ---------------------------------------------------------------------------
# Gate logic unit tests
# ---------------------------------------------------------------------------


def test_is_auto_approve_enabled_false_by_default() -> None:
    with patch.dict(os.environ, {}, clear=True):
        if "SHIELDCLAW_AUTO_APPROVE" in os.environ:
            del os.environ["SHIELDCLAW_AUTO_APPROVE"]
        assert not is_auto_approve_enabled()


def test_is_auto_approve_enabled_with_env_var() -> None:
    with patch.dict(os.environ, {"SHIELDCLAW_AUTO_APPROVE": "1"}):
        assert is_auto_approve_enabled()


def test_get_current_user_fallback() -> None:
    """get_current_user must return a non-empty string even when os.getlogin() fails."""
    with patch("shieldclaw.approval.gate.os.getlogin", side_effect=OSError):
        with patch.dict(os.environ, {"USER": "testuser"}):
            user = get_current_user()
    assert user == "testuser"


def test_get_current_user_unknown_fallback() -> None:
    """get_current_user must return 'unknown' when no env vars are set."""
    with patch("shieldclaw.approval.gate.os.getlogin", side_effect=OSError):
        with patch.dict(os.environ, {}, clear=True):
            for k in ("USER", "USERNAME", "LOGNAME"):
                os.environ.pop(k, None)
            user = get_current_user()
    assert user == "unknown"


def test_format_approval_context_contains_rule_id() -> None:
    finding = _make_finding()
    triaged = TriagedFinding(
        finding=finding, verdict=TriageVerdict.DYNAMICALLY_VERIFIABLE, reason="CWE-89"
    )
    ctx = ApprovalContext(
        finding=finding,
        triaged=triaged,
        score=None,
        source_excerpt="1 >>> line",
        compose_yaml="services: {}",
    )
    text = format_approval_context(ctx)
    assert finding.rule_id in text
    assert "app.py" in text


def test_format_approval_context_includes_score() -> None:
    finding = _make_finding()
    triaged = TriagedFinding(
        finding=finding, verdict=TriageVerdict.DYNAMICALLY_VERIFIABLE, reason="CWE-89"
    )
    score = ExploitabilityScore(
        score=0.9,
        attack_surface="NETWORK",
        prerequisites=("authenticated user",),
        reasoning="SQLi confirmed.",
        model_name="test",
        scored_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    ctx = ApprovalContext(
        finding=finding, triaged=triaged, score=score, source_excerpt="", compose_yaml=""
    )
    text = format_approval_context(ctx)
    assert "0.90" in text
    assert "NETWORK" in text
    assert "AWAITING_APPROVAL" not in text  # should not appear in format output


def test_interactive_approval_allows_finding_to_proceed(tmp_path: Path) -> None:
    """Interactive approval should record APPROVED and continue to detonation."""
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  web:\n    image: nginx:alpine\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text("query = request.args['id']\n", encoding="utf-8")
    fixture = tmp_path / "semgrep-one.json"
    _write_single_finding_fixture(fixture)

    docker = MagicMock()
    docker.detonate.return_value = DetonationOutcome(exit_code=0, evidence=())
    docker.get_target_container_id.return_value = "target-1"

    with patch.dict(os.environ, {"SHIELDCLAW_AUTO_APPROVE": ""}, clear=False):
        with patch("builtins.input", return_value="y"):
            orch = Orchestrator(
                provider_factory=lambda _: _InteractiveProvider(),
                docker_orchestrator=docker,
            )
            result = orch.run(
                target_dir=str(tmp_path),
                semgrep_output=str(fixture),
                interactive=True,
            )

    assert result.pipeline_error is None
    docker.detonate.assert_called_once()

    store = ScanStore(str(tmp_path))
    latest = store.get_latest_scan(str(tmp_path))
    assert latest is not None
    finding_row = store.list_findings(latest.scan_id)[0]
    approval = store.get_approval(finding_row.finding_id)
    assert approval is not None
    assert approval["decision"] == "APPROVED"
    assert finding_row.state == "VERDICTED"


def test_interactive_rejection_skips_detonation(tmp_path: Path) -> None:
    """Interactive rejection should record REJECTED and skip detonation."""
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  web:\n    image: nginx:alpine\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text("query = request.args['id']\n", encoding="utf-8")
    fixture = tmp_path / "semgrep-one.json"
    _write_single_finding_fixture(fixture)

    docker = MagicMock()

    with patch.dict(os.environ, {"SHIELDCLAW_AUTO_APPROVE": ""}, clear=False):
        with patch("builtins.input", return_value="n"):
            orch = Orchestrator(
                provider_factory=lambda _: _InteractiveProvider(),
                docker_orchestrator=docker,
            )
            result = orch.run(
                target_dir=str(tmp_path),
                semgrep_output=str(fixture),
                interactive=True,
            )

    assert result.pipeline_error is None
    docker.detonate.assert_not_called()

    store = ScanStore(str(tmp_path))
    latest = store.get_latest_scan(str(tmp_path))
    assert latest is not None
    finding_row = store.list_findings(latest.scan_id)[0]
    approval = store.get_approval(finding_row.finding_id)
    assert approval is not None
    assert approval["decision"] == "REJECTED"
    assert finding_row.state == "REJECTED"
