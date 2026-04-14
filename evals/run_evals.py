#!/usr/bin/env python3
"""Offline LLM evaluation harness: grades Ollama exploit generation without Docker."""

from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

# Repo layout: <root>/evals/run_evals.py and <root>/shield-claw/src/shieldclaw
_ROOT = Path(__file__).resolve().parent.parent
_SRC = _ROOT / "shield-claw" / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from shieldclaw.exceptions import LLMConnectionError, LLMRefusalError, LLMResponseError
from shieldclaw.intelligence.ollama import OllamaProvider
from shieldclaw.models import ScanContext

_DATA_FILE: Final[Path] = Path(__file__).resolve().parent / "eval_data.json"
_EMPTY_COMPOSE: Final[str] = "# synthetic eval: no compose services defined\n"


@dataclass(frozen=True, slots=True)
class _CaseOutcome:
    """Per-case grading outcome for the console report."""

    case_id: str
    name: str
    expected_vulnerable: bool
    passed: bool
    seconds: float
    label: str


def _load_cases(path: Path) -> list[dict[str, Any]]:
    """Load evaluation cases from JSON."""
    raw = path.read_text(encoding="utf-8")
    data = json.loads(raw)
    if not isinstance(data, list):
        raise ValueError("eval_data.json must contain a JSON array")
    return data


def _grade(expected_vulnerable: bool, outcome: str) -> bool:
    """Return True when the observed outcome matches the rubric for the case."""
    if expected_vulnerable:
        return outcome == "payload"
    return outcome in {"refusal", "response_error", "connection_error"}


def _run_case(provider: OllamaProvider, case: dict[str, Any]) -> _CaseOutcome:
    """Execute a single eval case and return timing plus pass/fail."""
    case_id = str(case["id"])
    name = str(case["name"])
    diff = str(case["diff_content"])
    expected = bool(case["expected_vulnerable"])
    ctx = ScanContext(
        target_dir=f"/eval/{case_id}",
        git_diff_content=diff,
        docker_compose_content=_EMPTY_COMPOSE,
        timestamp=datetime.now(UTC),
    )
    started = time.perf_counter()
    label = "payload"
    try:
        provider.generate_exploit(ctx)
    except LLMRefusalError:
        label = "refusal"
    except LLMResponseError:
        label = "response_error"
    except LLMConnectionError:
        label = "connection_error"
    except Exception as exc:  # noqa: BLE001 - surface unexpected failures distinctly
        label = f"unexpected:{type(exc).__name__}"
    elapsed = time.perf_counter() - started
    passed = _grade(expected, label)
    return _CaseOutcome(
        case_id=case_id,
        name=name,
        expected_vulnerable=expected,
        passed=passed,
        seconds=elapsed,
        label=label,
    )


def main() -> int:
    """Load cases, call Ollama, and print aggregate metrics."""
    if not _DATA_FILE.is_file():
        print(f"Missing data file: {_DATA_FILE}", file=sys.stderr)
        return 1

    cases = _load_cases(_DATA_FILE)
    provider = OllamaProvider()
    outcomes: list[_CaseOutcome] = []
    json_errors = 0
    refusals = 0

    for case in cases:
        out = _run_case(provider, case)
        outcomes.append(out)
        if out.label == "response_error":
            json_errors += 1
        if out.label == "refusal":
            refusals += 1

    total = len(outcomes)
    passed = sum(1 for o in outcomes if o.passed)
    accuracy = passed / total if total else 0.0
    json_rate = (total - json_errors) / total if total else 0.0
    refusal_rate = refusals / total if total else 0.0
    avg_time = sum(o.seconds for o in outcomes) / total if total else 0.0

    print("ShieldClaw LLM Eval Report")
    print("==========================")
    print(f"Cases evaluated:        {total}")
    print(f"Total accuracy:         {accuracy:.1%}")
    print(f"JSON compliance rate:   {json_rate:.1%}  (no LLMResponseError)")
    print(f"Refusal rate:           {refusal_rate:.1%}  (LLMRefusalError)")
    print(f"Avg inference time:     {avg_time:.2f}s per case")
    print()
    print("Per-case results")
    print("----------------")
    for o in outcomes:
        status = "PASS" if o.passed else "FAIL"
        exp = "vuln" if o.expected_vulnerable else "safe"
        print(f"  [{status}] {o.case_id} ({exp}, {o.label}) {o.seconds:.2f}s - {o.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
