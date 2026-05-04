"""Unit tests for retry-once PoC generation behavior."""

from __future__ import annotations

import json
import uuid

import pytest

from shieldclaw.exceptions import LLMConnectionError, LLMRefusalError
from shieldclaw.intelligence.base import LLMProvider
from shieldclaw.intelligence.poc_generator import PocGenerator
from shieldclaw.models import ExploitPayload, Finding, ScanContext

_VALID_POC_JSON = json.dumps(
    {
        "language": "python",
        "target_dns": "web",
        "raw_code": "import sys\nimport requests\nsys.exit(0)\n",
        "execution_command": "python3 /exploit/exploit.py",
    }
)


def _sample_finding() -> Finding:
    return Finding(
        finding_id=uuid.UUID("11111111-2222-4333-8444-555555555555"),
        rule_id="python.flask.security.sqli",
        severity="ERROR",
        path="app.py",
        start_line=10,
        end_line=10,
        message="Possible SQL injection",
        cwe=("CWE-89",),
        metavars={"$QUERY": "SELECT * FROM users"},
        raw_extra='{"message": "Possible SQL injection"}',
    )


class SequencedProvider(LLMProvider):
    """Provider stub that returns a fixed sequence of complete() responses."""

    def __init__(self, responses: list[str]) -> None:
        self._responses = list(responses)
        self.prompts: list[tuple[str, str]] = []

    def generate_exploit(self, context: ScanContext) -> ExploitPayload:
        raise LLMConnectionError("SequencedProvider only supports complete()")

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        self.prompts.append((system_prompt, user_prompt))
        if not self._responses:
            raise AssertionError("Unexpected extra complete() call")
        return self._responses.pop(0)


def test_generate_retries_once_after_refusal_then_succeeds() -> None:
    """A first refusal should trigger one authorized-context retry that can succeed."""
    provider = SequencedProvider(
        [
            "Sorry, I cannot help generate exploit code.",
            _VALID_POC_JSON,
        ]
    )

    payload = PocGenerator(provider, model_name="test-model").generate(
        _sample_finding(),
        "10 >>> cursor.execute(query)\n",
        "services:\n  web:\n    image: nginx:alpine\n",
    )

    assert payload.target_dns == "web"
    assert len(provider.prompts) == 2
    assert provider.prompts[0][1] != provider.prompts[1][1]
    assert "authorized security testing" in provider.prompts[1][1]


def test_generate_raises_refusal_after_second_refusal() -> None:
    """Two refusals should surface as a terminal LLMRefusalError after one retry."""
    provider = SequencedProvider(
        [
            "Sorry, I cannot help generate exploit code.",
            "I cannot assist with that request.",
        ]
    )

    with pytest.raises(LLMRefusalError, match="after retry"):
        PocGenerator(provider, model_name="test-model").generate(
            _sample_finding(),
            "10 >>> cursor.execute(query)\n",
            "services:\n  web:\n    image: nginx:alpine\n",
        )

    assert len(provider.prompts) == 2
