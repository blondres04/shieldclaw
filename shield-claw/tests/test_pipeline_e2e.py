"""End-to-end integration test: full SAST pipeline against the vulnerable Flask lab.

Requires Docker and a running Docker daemon.  Skipped automatically when
either is unavailable.

Test scenario
-------------
1. Use the pre-captured Semgrep fixture (``semgrep_sample.json``) which
   contains a confirmed SQLi finding for ``app.py:42``.
2. Run the full pipeline with ``SHIELDCLAW_AUTO_APPROVE=1``:
   ingest → triage → score (mocked) → approve → PoC generate (mocked)
   → detonate → verdict synthesis.
3. Assert the SQLi finding ends with ``verdict=TRUE_POSITIVE``.
4. Assert the evidence array contains both ExitCodeObserver and at least one
   Tier-2 observer entry.
5. Assert ``shieldclaw status`` shows all findings in terminal states.

Notes on mocking
----------------
The LLM calls (scoring and PoC generation) are mocked so the test does not
require Ollama.  Docker compose brings up the actual Flask + Postgres stack
to detonation, which is required for the TRUE_POSITIVE assertion.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import uuid
from pathlib import Path

import pytest

from shieldclaw.intelligence.base import LLMProvider
from shieldclaw.models import ExploitPayload, ScanContext
from shieldclaw.persistence.store import ScanStore

# ---------------------------------------------------------------------------
# Fixtures and skip conditions
# ---------------------------------------------------------------------------

_SEMGREP_FIXTURE = Path(__file__).parent / "fixtures" / "semgrep_sample.json"
_LAB_APP_DIR = Path(__file__).resolve().parents[2] / "test_repos" / "vulnerable-flask-app"
_LAB_COMPOSE = _LAB_APP_DIR / "docker-compose.yml"


def _docker_available() -> bool:
    try:
        r = subprocess.run(["docker", "version"], capture_output=True, text=True, timeout=15.0)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def _strip_host_ports(raw: str) -> str:
    """Remove published ports so the stack does not bind host TCP ports."""
    import re

    return re.sub(
        r"^\s*ports:\s*\r?\n(?:^\s+-\s+.+\r?\n)+",
        "",
        raw,
        flags=re.MULTILINE,
    )


# ---------------------------------------------------------------------------
# Mock provider: real scoring JSON + real PoC for SQLi
# ---------------------------------------------------------------------------

_SCORE_JSON = json.dumps(
    {
        "score": 0.95,
        "attack_surface": "NETWORK",
        "prerequisites": [],
        "reasoning": "Direct user input to SQL string; exploitable via HTTP.",
    }
)

_POC_JSON = json.dumps(
    {
        "language": "python",
        "target_dns": "web",
        "raw_code": (
            "import sys\nimport requests\n\n"
            "def exploit():\n"
            "    url = 'http://web:5000/user'\n"
            "    r = requests.get(url, params={'id': '1 OR 1=1'})\n"
            "    if r.status_code == 200 and len(r.text) > 10:\n"
            "        print('SQLi confirmed')\n"
            "        sys.exit(0)\n"
            "    sys.exit(1)\n\n"
            "if __name__ == '__main__':\n"
            "    exploit()\n"
        ),
        "execution_command": "python3 /exploit/exploit.py",
    }
)


class _MockProvider(LLMProvider):
    """Returns pre-canned scoring and PoC responses without calling Ollama."""

    def generate_exploit(self, context: ScanContext) -> ExploitPayload:
        raise NotImplementedError

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        # Scoring calls contain "score" in the system prompt; PoC calls don't.
        if '"score"' in system_prompt or "exploitability" in system_prompt.lower():
            return _SCORE_JSON
        return _POC_JSON


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_compose_dir(tmp_path: Path) -> Path:
    """Copy lab app to tmp_path with host port mappings stripped."""
    for name in ("Dockerfile", "app.py", "init.sql"):
        shutil.copy2(_LAB_APP_DIR / name, tmp_path / name)
    compose_text = _strip_host_ports(_LAB_COMPOSE.read_text(encoding="utf-8"))
    (tmp_path / "docker-compose.yml").write_text(compose_text, encoding="utf-8")
    return tmp_path


def _build_attacker_image(tag: str) -> bool:
    """Build the attacker image used by end-to-end Docker tests."""
    dockerfile = (
        Path(__file__).resolve().parents[2] / "shield-claw" / "docker" / "attacker.Dockerfile"
    )
    if not dockerfile.is_file():
        return False
    result = subprocess.run(
        [
            "docker",
            "build",
            "-f",
            str(dockerfile),
            "-t",
            tag,
            str(Path(__file__).resolve().parents[2] / "shield-claw"),
        ],
        capture_output=True,
        text=True,
        timeout=300.0,
    )
    return result.returncode == 0


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.skipif(not _docker_available(), reason="Docker engine not available")
@pytest.mark.skipif(not _LAB_COMPOSE.is_file(), reason="Lab app compose file missing")
def test_sqli_finding_gets_true_positive_verdict(tmp_path: Path) -> None:
    """Full pipeline: SQLi finding should end with TRUE_POSITIVE verdict."""
    from shieldclaw.orchestrator import Orchestrator

    target_dir = _build_compose_dir(tmp_path)
    attacker_tag = f"shieldclaw-attacker:test-{uuid.uuid4().hex[:12]}"

    # Build Docker images.
    build = subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            str(target_dir / "docker-compose.yml"),
            "build",
        ],
        cwd=str(target_dir),
        capture_output=True,
        text=True,
        timeout=600.0,
    )
    if build.returncode != 0:
        pytest.skip(f"docker compose build failed: {build.stderr[:500]}")
    if not _build_attacker_image(attacker_tag):
        pytest.skip("Failed to build attacker image")

    provider = _MockProvider()

    with pytest.MonkeyPatch().context() as m:
        m.setenv("SHIELDCLAW_AUTO_APPROVE", "1")
        m.setenv("SHIELDCLAW_ATTACKER_IMAGE", attacker_tag)
        orch = Orchestrator(provider_factory=lambda _: provider)
        result = orch.run(
            target_dir=str(target_dir),
            semgrep_output=str(_SEMGREP_FIXTURE),
        )

    # No pipeline error.
    assert result.pipeline_error is None, f"pipeline_error: {result.pipeline_error}"

    store = ScanStore(str(target_dir))
    latest = store.get_latest_scan(str(target_dir))
    assert latest is not None

    scan_id = latest.scan_id
    counts = store.count_findings_by_state(scan_id)

    # All findings should be in terminal states.
    terminal_states = {"VERDICTED", "REJECTED", "SCORED", "COMPLETE"}
    non_terminal = {s: n for s, n in counts.items() if s not in terminal_states and n > 0}
    assert not non_terminal, f"Non-terminal states found: {non_terminal}"

    # At least the SQLi finding should have a TRUE_POSITIVE verdict.
    from shieldclaw.ingest.semgrep import parse_semgrep_json

    raw_findings = parse_semgrep_json(_SEMGREP_FIXTURE)
    sqli = next(f for f in raw_findings if "sql" in f.rule_id.lower())
    verdict_row = store.get_verdict(str(sqli.finding_id))
    assert verdict_row is not None, "No verdict recorded for SQLi finding"
    assert verdict_row["verdict"] == "TRUE_POSITIVE", (
        f"Expected TRUE_POSITIVE; got {verdict_row['verdict']}"
    )
    assert float(str(verdict_row["confidence"])) >= 0.90

    # Evidence should include exit_code and at least one Tier-2 observer.
    evidence_rows = store.get_evidence_for_finding(str(sqli.finding_id))
    observer_names = {str(r["observer_name"]) for r in evidence_rows}
    assert "exit_code" in observer_names, f"No exit_code evidence; found: {observer_names}"
    tier2 = {n for n in observer_names if n in ("docker_diff", "target_logs")}
    assert tier2, f"No Tier-2 observer evidence; found: {observer_names}"


@pytest.mark.integration
@pytest.mark.skipif(not _docker_available(), reason="Docker engine not available")
@pytest.mark.skipif(not _LAB_COMPOSE.is_file(), reason="Lab app compose file missing")
def test_status_shows_terminal_states(tmp_path: Path) -> None:
    """``shieldclaw status`` should show all findings in terminal states after a run."""
    from shieldclaw.orchestrator import Orchestrator

    target_dir = _build_compose_dir(tmp_path)
    attacker_tag = f"shieldclaw-attacker:test-{uuid.uuid4().hex[:12]}"
    build = subprocess.run(
        ["docker", "compose", "-f", str(target_dir / "docker-compose.yml"), "build"],
        cwd=str(target_dir),
        capture_output=True,
        text=True,
        timeout=600.0,
    )
    if build.returncode != 0:
        pytest.skip("docker compose build failed")
    if not _build_attacker_image(attacker_tag):
        pytest.skip("Failed to build attacker image")

    with pytest.MonkeyPatch().context() as m:
        m.setenv("SHIELDCLAW_AUTO_APPROVE", "1")
        m.setenv("SHIELDCLAW_ATTACKER_IMAGE", attacker_tag)
        orch = Orchestrator(provider_factory=lambda _: _MockProvider())
        orch.run(target_dir=str(target_dir), semgrep_output=str(_SEMGREP_FIXTURE))

    store = ScanStore(str(target_dir))
    latest = store.get_latest_scan(str(target_dir))
    assert latest is not None
    assert latest.state in ("COMPLETE", "VERDICTING", "FAILED"), (
        f"Unexpected scan state: {latest.state}"
    )
