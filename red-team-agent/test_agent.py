"""
Deterministic unit tests for the Red Team Agent's parsing and validation layer.
No live Ollama API calls — all LLM output is simulated.
"""

import json

import pytest
from pydantic import ValidationError

from agent import PRPayload, clean_and_parse_llm_output

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

VALID_PAYLOAD = {
    "prId": "PR-ABC12345",
    "threatCategory": "OWASP_A03 - Injection",
    "isPoisoned": True,
    "originalSnippet": 'String query = "SELECT * FROM users WHERE id = ?";',
    "poisonedSnippet": 'String query = "SELECT * FROM users WHERE id = " + userId;',
}


# ---------------------------------------------------------------------------
# Parsing tests
# ---------------------------------------------------------------------------

def test_clean_valid_json():
    """Perfect JSON string parses without modification."""
    raw = json.dumps(VALID_PAYLOAD)
    result = clean_and_parse_llm_output(raw)
    assert result == VALID_PAYLOAD


def test_clean_markdown_json():
    """JSON wrapped in ```json ... ``` fences is successfully extracted."""
    raw = "```json\n" + json.dumps(VALID_PAYLOAD, indent=2) + "\n```"
    result = clean_and_parse_llm_output(raw)
    assert result == VALID_PAYLOAD


def test_clean_conversational_json():
    """Conversational preamble before the JSON object is stripped away."""
    raw = "Here is your payload: \n" + json.dumps(VALID_PAYLOAD)
    result = clean_and_parse_llm_output(raw)
    assert result == VALID_PAYLOAD


def test_clean_raises_on_garbage():
    """Completely unparseable text raises JSONDecodeError."""
    with pytest.raises(json.JSONDecodeError):
        clean_and_parse_llm_output("This is not JSON at all")


# ---------------------------------------------------------------------------
# Pydantic validation tests
# ---------------------------------------------------------------------------

def test_pydantic_validation_failure():
    """Missing required 'threatCategory' key raises ValidationError."""
    incomplete = {
        "prId": "PR-DEADBEEF",
        "isPoisoned": True,
        "originalSnippet": "safe code",
        "poisonedSnippet": "dangerous code",
    }
    with pytest.raises(ValidationError) as exc_info:
        PRPayload(**incomplete)
    assert "threatCategory" in str(exc_info.value)


def test_pydantic_validation_success():
    """A complete, well-formed dict passes Pydantic validation."""
    payload = PRPayload(**VALID_PAYLOAD)
    assert payload.prId == VALID_PAYLOAD["prId"]
    assert payload.threatCategory == VALID_PAYLOAD["threatCategory"]
    assert payload.isPoisoned is True
