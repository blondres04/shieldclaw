"""Resumability test: a mid-run interrupt must not cause findings to be re-scored.

Test scenario
-------------
1. A ``CountingProvider`` is given to the orchestrator; it tracks how many
   times ``complete()`` is called and raises ``KeyboardInterrupt`` after
   the third call.
2. The SAST pipeline is run against a 5-finding SQLi fixture (all default
   MVP-supported).  A ``KeyboardInterrupt`` fires mid-scoring
   (after findings 1, 2, 3 are scored).
3. The interrupted scan's ``scan_id`` is retrieved from the store.
4. A second orchestrator with a normal (always-succeeding) provider resumes
   with ``resume_scan_id=scan_id``.
5. Only 2 additional ``complete()`` calls happen (findings 4 and 5).
6. After the resume all 5 findings are in ``AWAITING_APPROVAL`` state.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shieldclaw.exceptions import LLMConnectionError
from shieldclaw.intelligence.base import LLMProvider
from shieldclaw.models import DetonationOutcome, ExploitPayload, ScanContext
from shieldclaw.orchestrator import Orchestrator
from shieldclaw.persistence.store import ScanStore
from shieldclaw.sandbox.docker_orchestrator import DockerOrchestrator

_5SQLI_FIXTURE = Path(__file__).parent / "fixtures" / "semgrep_5sqli.json"
_MIXED_CWE_FIXTURE = Path(__file__).parent / "fixtures" / "semgrep_5dv.json"

_SCORE_JSON = json.dumps(
    {
        "score": 0.85,
        "attack_surface": "NETWORK",
        "prerequisites": [],
        "reasoning": "Direct user input to SQL query.",
    }
)

_INVALID_TARGET_POC_JSON = json.dumps(
    {
        "language": "python",
        "target_dns": "admin",
        "raw_code": "import sys\nsys.exit(0)\n",
        "execution_command": "python -",
    }
)

_VALID_TARGET_POC_JSON = json.dumps(
    {
        "language": "python",
        "target_dns": "web",
        "raw_code": "import sys\nsys.exit(0)\n",
        "execution_command": "python -",
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


class InvalidTargetDnsProvider(LLMProvider):
    """Provider that scores normally but emits a PoC for a missing compose service."""

    def __init__(self) -> None:
        self.complete_calls = 0

    def generate_exploit(self, context: ScanContext) -> ExploitPayload:
        raise LLMConnectionError("InvalidTargetDnsProvider is for SAST PoC generation only")

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        self.complete_calls += 1
        if '"score"' in system_prompt or "exploitability" in system_prompt.lower():
            return _SCORE_JSON
        return _INVALID_TARGET_POC_JSON


class ValidTargetDnsProvider(LLMProvider):
    """Provider that scores normally and emits a PoC for a valid compose service."""

    def __init__(self) -> None:
        self.complete_calls = 0

    def generate_exploit(self, context: ScanContext) -> ExploitPayload:
        raise LLMConnectionError("ValidTargetDnsProvider is for SAST PoC generation only")

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        self.complete_calls += 1
        if '"score"' in system_prompt or "exploitability" in system_prompt.lower():
            return _SCORE_JSON
        return _VALID_TARGET_POC_JSON


class RefusalThenSuccessProvider(LLMProvider):
    """Provider that refuses PoC generation for one finding and succeeds for another."""

    def __init__(self) -> None:
        self.complete_calls = 0

    def generate_exploit(self, context: ScanContext) -> ExploitPayload:
        raise LLMConnectionError("RefusalThenSuccessProvider is for SAST PoC generation only")

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        self.complete_calls += 1
        if '"score"' in system_prompt or "exploitability" in system_prompt.lower():
            return _SCORE_JSON
        if "refused.py" in user_prompt:
            return "Sorry, I cannot help generate exploit code."
        return _VALID_TARGET_POC_JSON


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
            semgrep_output=str(_5SQLI_FIXTURE),
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

    # Confirm 3 findings are awaiting approval and 2 are still TRIAGED.
    counts_before = store.count_findings_by_state(scan_id)
    assert counts_before.get("AWAITING_APPROVAL", 0) == 3, (
        f"Expected 3 AWAITING_APPROVAL; got {counts_before}"
    )
    assert counts_before.get("TRIAGED", 0) == 2, f"Expected 2 TRIAGED; got {counts_before}"

    # Second run — resume.
    normal_provider = NormalProvider()
    orch2 = Orchestrator(provider_factory=lambda _: normal_provider)

    orch2.run(
        target_dir=str(repo_dir),
        semgrep_output=str(_5SQLI_FIXTURE),
        resume_scan_id=scan_id,
    )

    # Only 2 additional complete() calls (findings 4 and 5).
    assert normal_provider.complete_calls == 2, (
        f"Expected 2 complete() calls during resume; got {normal_provider.complete_calls}"
    )

    # All 5 findings should now await approval.
    counts_after = store.count_findings_by_state(scan_id)
    assert counts_after.get("AWAITING_APPROVAL", 0) == 5, (
        f"Expected 5 AWAITING_APPROVAL after resume; got {counts_after}"
    )
    assert counts_after.get("TRIAGED", 0) == 0, (
        f"Expected 0 TRIAGED after resume; got {counts_after}"
    )

    # Scan state should make the next operator action explicit.
    final_scan = store.load_scan(scan_id)
    assert final_scan is not None
    assert final_scan.state == "AWAITING_APPROVAL", (
        f"Expected AWAITING_APPROVAL; got {final_scan.state}"
    )


def test_scores_are_persisted_correctly(repo_dir: Path) -> None:
    """Scores written during the interrupted run must match the expected values."""
    counting_provider = CountingProvider(interrupt_after=5)  # no interrupt this time

    orch = Orchestrator(provider_factory=lambda _: counting_provider)
    orch.run(
        target_dir=str(repo_dir),
        semgrep_output=str(_5SQLI_FIXTURE),
    )

    store = ScanStore(str(repo_dir))
    latest = store.get_latest_scan(str(repo_dir))
    assert latest is not None
    scan_id = latest.scan_id
    counts = store.count_findings_by_state(scan_id)
    assert counts.get("AWAITING_APPROVAL", 0) == 5

    # Verify all 5 complete() calls happened.
    assert counting_provider.complete_calls == 5


def test_default_mvp_scores_only_sqli_findings(repo_dir: Path) -> None:
    """Default MVP path must not score or approve non-CWE-89 findings."""
    provider = NormalProvider()
    orch = Orchestrator(provider_factory=lambda _: provider)

    orch.run(target_dir=str(repo_dir), semgrep_output=str(_MIXED_CWE_FIXTURE))

    store = ScanStore(str(repo_dir))
    latest = store.get_latest_scan(str(repo_dir))
    assert latest is not None
    counts = store.count_findings_by_state(latest.scan_id)

    assert provider.complete_calls == 2
    assert counts.get("AWAITING_APPROVAL", 0) == 2
    assert counts.get("DEFERRED", 0) == 3
    assert counts.get("APPROVED", 0) == 0
    assert counts.get("POC_GENERATED", 0) == 0


def test_resume_with_unknown_scan_id_fails(repo_dir: Path) -> None:
    """Resuming a non-existent scan_id must raise ShieldClawError."""

    orch = Orchestrator()
    result = orch.run(
        target_dir=str(repo_dir),
        semgrep_output=str(_5SQLI_FIXTURE),
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

    orch.run(target_dir=str(repo_dir), semgrep_output=str(_5SQLI_FIXTURE))
    orch.run(target_dir=str(repo_dir), semgrep_output=str(_5SQLI_FIXTURE))

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


def test_invalid_target_dns_records_inconclusive_and_skips_detonation(repo_dir: Path) -> None:
    """A PoC targeting a missing compose service must be marked INCONCLUSIVE without detonation."""
    from unittest.mock import MagicMock

    from shieldclaw.orchestrator import Orchestrator
    from shieldclaw.persistence.store import ScanStore

    semgrep_fixture = repo_dir / "semgrep-invalid-target.json"
    semgrep_fixture.write_text(
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
    (repo_dir / "app.py").write_text("query = request.args['id']\n", encoding="utf-8")

    provider = InvalidTargetDnsProvider()
    docker = MagicMock(spec=DockerOrchestrator)

    with pytest.MonkeyPatch().context() as m:
        m.setenv("SHIELDCLAW_AUTO_APPROVE", "1")
        orch = Orchestrator(provider_factory=lambda _: provider, docker_orchestrator=docker)
        result = orch.run(target_dir=str(repo_dir), semgrep_output=str(semgrep_fixture))

    assert result.pipeline_error is None
    docker.detonate.assert_not_called()

    store = ScanStore(str(repo_dir))
    latest = store.get_latest_scan(str(repo_dir))
    assert latest is not None

    counts = store.count_findings_by_state(latest.scan_id)
    assert counts.get("VERDICTED", 0) == 1

    from shieldclaw.ingest.semgrep import parse_semgrep_json

    finding = parse_semgrep_json(semgrep_fixture)[0]
    verdict = store.get_verdict(str(finding.finding_id))
    assert verdict is not None
    assert verdict["verdict"] == "INCONCLUSIVE"
    assert "target_dns" in str(verdict["summary"])
    assert "admin" in str(verdict["summary"])
    assert "web" in str(verdict["summary"])


def test_sast_run_threads_configured_timeout_to_detonate(repo_dir: Path) -> None:
    """The SAST pipeline must pass the CLI-configured timeout through to detonate()."""
    from unittest.mock import MagicMock

    from shieldclaw.orchestrator import Orchestrator

    semgrep_fixture = repo_dir / "semgrep-timeout.json"
    semgrep_fixture.write_text(
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
    (repo_dir / "app.py").write_text("query = request.args['id']\n", encoding="utf-8")

    provider = ValidTargetDnsProvider()
    docker = MagicMock(spec=DockerOrchestrator)
    docker.detonate.return_value = DetonationOutcome(exit_code=0, evidence=())

    with pytest.MonkeyPatch().context() as m:
        m.setenv("SHIELDCLAW_AUTO_APPROVE", "1")
        orch = Orchestrator(provider_factory=lambda _: provider, docker_orchestrator=docker)
        result = orch.run(target_dir=str(repo_dir), semgrep_output=str(semgrep_fixture), timeout=7)

    assert result.pipeline_error is None
    docker.detonate.assert_called_once()
    assert docker.detonate.call_args.kwargs["timeout"] == 7


def test_resume_marks_poc_generated_findings_inconclusive_without_redetonating(
    repo_dir: Path,
) -> None:
    """Interrupted detonations should be verdicted INCONCLUSIVE on resume."""
    from unittest.mock import MagicMock

    from shieldclaw.ingest.semgrep import parse_semgrep_json
    from shieldclaw.orchestrator import Orchestrator

    semgrep_fixture = repo_dir / "semgrep-poc-generated.json"
    semgrep_fixture.write_text(
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
    (repo_dir / "app.py").write_text("query = request.args['id']\n", encoding="utf-8")

    store = ScanStore(str(repo_dir))
    scan_id = "11111111-2222-4333-8444-555555555555"
    store.create_scan(scan_id, str(repo_dir), str(semgrep_fixture))
    findings = parse_semgrep_json(semgrep_fixture)
    finding = findings[0]
    store.record_findings(scan_id, findings)
    store.set_triage(str(finding.finding_id), "DYNAMICALLY_VERIFIABLE", "seeded for resume")
    store.record_approval(
        str(finding.finding_id),
        "APPROVED",
        "tester",
        note="seeded for resume",
        auto=True,
    )
    store.record_poc(
        "aaaaaaaa-bbbb-4ccc-dddd-eeeeeeeeeeee",
        str(finding.finding_id),
        "import sys\nsys.exit(0)\n",
        "web",
        "python -",
        "python",
        "test-model",
    )
    store.update_finding_state(str(finding.finding_id), "POC_GENERATED")
    store.update_scan_state(scan_id, "DETONATING")

    docker = MagicMock(spec=DockerOrchestrator)
    orch = Orchestrator(provider_factory=lambda _: NormalProvider(), docker_orchestrator=docker)

    result = orch.run(
        target_dir=str(repo_dir),
        semgrep_output=str(semgrep_fixture),
        resume_scan_id=scan_id,
    )

    assert result.pipeline_error is None
    docker.detonate.assert_not_called()

    verdict = store.get_verdict(str(finding.finding_id))
    assert verdict is not None
    assert verdict["verdict"] == "INCONCLUSIVE"
    assert "Detonation interrupted" in str(verdict["summary"])

    counts = store.count_findings_by_state(scan_id)
    assert counts.get("VERDICTED", 0) == 1
    assert counts.get("POC_GENERATED", 0) == 0


def test_refused_poc_is_reported_and_does_not_block_other_findings(repo_dir: Path) -> None:
    """A twice-refused PoC should become REFUSED in the report while other findings continue."""
    from unittest.mock import MagicMock

    semgrep_fixture = repo_dir / "semgrep-refused.json"
    semgrep_fixture.write_text(
        json.dumps(
            {
                "results": [
                    {
                        "check_id": "python.flask.security.sqli",
                        "path": "refused.py",
                        "start": {"line": 1, "col": 1},
                        "end": {"line": 1, "col": 12},
                        "extra": {
                            "severity": "ERROR",
                            "message": "Possible SQL injection",
                            "metadata": {"cwe": ["CWE-89"]},
                            "metavars": {},
                        },
                    },
                    {
                        "check_id": "python.flask.security.sqli",
                        "path": "ok.py",
                        "start": {"line": 1, "col": 1},
                        "end": {"line": 1, "col": 12},
                        "extra": {
                            "severity": "ERROR",
                            "message": "Possible SQL injection",
                            "metadata": {"cwe": ["CWE-89"]},
                            "metavars": {},
                        },
                    },
                ],
                "errors": [],
            }
        ),
        encoding="utf-8",
    )
    (repo_dir / "refused.py").write_text("query = request.args['id']\n", encoding="utf-8")
    (repo_dir / "ok.py").write_text("query = request.args['id']\n", encoding="utf-8")

    provider = RefusalThenSuccessProvider()
    docker = MagicMock(spec=DockerOrchestrator)
    docker.detonate.return_value = DetonationOutcome(exit_code=0, evidence=())
    output_path = repo_dir / "report.json"

    with pytest.MonkeyPatch().context() as m:
        m.setenv("SHIELDCLAW_AUTO_APPROVE", "1")
        orch = Orchestrator(provider_factory=lambda _: provider, docker_orchestrator=docker)
        result = orch.run(
            target_dir=str(repo_dir),
            semgrep_output=str(semgrep_fixture),
            output_path=str(output_path),
        )

    assert result.pipeline_error is None
    docker.detonate.assert_called_once()

    store = ScanStore(str(repo_dir))
    latest = store.get_latest_scan(str(repo_dir))
    assert latest is not None

    findings_by_path = {row.path: row for row in store.list_findings(latest.scan_id)}
    assert findings_by_path["refused.py"].state == "REFUSED"
    assert findings_by_path["ok.py"].state == "VERDICTED"

    refused_verdict = store.get_verdict(findings_by_path["refused.py"].finding_id)
    assert refused_verdict is not None
    assert refused_verdict["verdict"] == "REFUSED"
    assert refused_verdict["summary"] == "LLM refused to generate PoC after retry"

    report_data = json.loads(output_path.read_text(encoding="utf-8"))
    report_findings = {item["path"]: item for item in report_data["findings"]}
    assert report_findings["refused.py"]["state"] == "REFUSED"
    assert report_findings["refused.py"]["verdict"] == "REFUSED"
    assert (
        report_findings["refused.py"]["verdict_summary"]
        == "LLM refused to generate PoC after retry"
    )
    assert report_findings["ok.py"]["state"] == "VERDICTED"
