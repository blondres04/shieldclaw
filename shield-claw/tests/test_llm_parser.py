"""Unit tests for ``parse_llm_response`` covering JSON, markdown, and refusals."""

from __future__ import annotations

import json

import pytest

from shieldclaw.exceptions import LLMRefusalError, LLMResponseError
from shieldclaw.intelligence.parser import parse_llm_response

_VALID_PAYLOAD = {
    "language": "python",
    "target_dns": "web",
    "raw_code": "import sys\nsys.exit(0)\n",
    "execution_command": "python3 /exploit/exploit.py",
}


def test_parse_valid_json_plain() -> None:
    """Bare JSON objects should deserialize into exploit payloads."""
    raw = json.dumps(_VALID_PAYLOAD)
    payload = parse_llm_response(raw)
    assert payload.language == "python"
    assert payload.target_dns == "web"
    assert "sys.exit" in payload.raw_code
    assert payload.execution_command == "python3 /exploit/exploit.py"


def test_parse_normalizes_host_port_target_dns() -> None:
    """Models sometimes emit ``service:port``; keep only the Compose service name."""
    data = {**_VALID_PAYLOAD, "target_dns": "web:5000"}
    raw = json.dumps(data)
    payload = parse_llm_response(raw)
    assert payload.target_dns == "web"


def test_parse_json_wrapped_in_markdown_fence() -> None:
    """Markdown fences must be stripped before JSON parsing."""
    inner = json.dumps(_VALID_PAYLOAD)
    raw = f"```json\n{inner}\n```"
    payload = parse_llm_response(raw)
    assert payload.target_dns == "web"


def test_parse_json_with_surrounding_noise() -> None:
    """Leading or trailing prose should be ignored when braces delimit JSON."""
    inner = json.dumps(_VALID_PAYLOAD)
    raw = f"Thoughts first\n{inner}\ntrailing noise"
    payload = parse_llm_response(raw)
    assert payload.language == "python"


def test_refusal_plain_text() -> None:
    """Safety refusals without code markers must raise ``LLMRefusalError``."""
    raw = "I am sorry, but I cannot help with harmful requests."
    with pytest.raises(LLMRefusalError):
        parse_llm_response(raw)


def test_refusal_unethical_phrase() -> None:
    """The heuristic should catch unethical refusals lacking code markers."""
    raw = "That would be unethical and against my guidelines."
    with pytest.raises(LLMRefusalError):
        parse_llm_response(raw)


def test_non_refusal_when_code_markers_present() -> None:
    """Apologies embedded alongside JSON should not trigger refusals."""
    inner = json.dumps(_VALID_PAYLOAD)
    raw = f"I will comply.\n{inner}"
    payload = parse_llm_response(raw)
    assert payload.target_dns == "web"


def test_malformed_json_raises() -> None:
    """Invalid JSON must surface ``LLMResponseError``."""
    raw = "{this is not json"
    with pytest.raises(LLMResponseError):
        parse_llm_response(raw)


def test_missing_required_field_raises() -> None:
    """Omitting mandatory keys should raise a structured response error."""
    bad = dict(_VALID_PAYLOAD)
    del bad["raw_code"]
    raw = json.dumps(bad)
    with pytest.raises(LLMResponseError) as excinfo:
        parse_llm_response(raw)
    assert "raw_code" in str(excinfo.value).lower() or "missing" in str(excinfo.value).lower()


def test_non_string_field_raises() -> None:
    """Non-string JSON values for required fields are rejected."""
    bad = dict(_VALID_PAYLOAD)
    bad["language"] = ["python"]
    raw = json.dumps(bad)
    with pytest.raises(LLMResponseError):
        parse_llm_response(raw)
