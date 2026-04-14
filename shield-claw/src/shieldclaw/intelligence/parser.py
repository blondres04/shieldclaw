"""Parse model output into structured exploit payloads with refusal detection.

Refusal detection follows the product heuristic (code signals plus refusal
phrases) while avoiding common English false positives such as the substring
``http`` inside ``harmful`` or the word ``requests`` in prose.
"""

from __future__ import annotations

import json
import re
import uuid
from typing import Any, Final

from shieldclaw.exceptions import LLMRefusalError, LLMResponseError
from shieldclaw.models import ExploitPayload

_URL_SCHEMES: Final[tuple[str, ...]] = ("http://", "https://")
_CODE_KEYWORD_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"\b(import|def|curl)\b",
    flags=re.IGNORECASE,
)
_REQUESTS_LIBRARY_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"\b(import\s+requests|from\s+requests|requests\.(get|post|put|delete|session|Request))\b",
    flags=re.IGNORECASE,
)
_REFUSAL_MARKERS: Final[tuple[str, ...]] = (
    "cannot",
    "sorry",
    "harmful",
    "unethical",
    "against my",
)

_REQUIRED_JSON_FIELDS: Final[tuple[str, ...]] = (
    "language",
    "target_dns",
    "raw_code",
    "execution_command",
)


def _contains_code_marker(raw: str) -> bool:
    """Return True when the response includes any configured code signal."""
    if "{" in raw:
        return True
    lower = raw.lower()
    if any(scheme in lower for scheme in _URL_SCHEMES):
        return True
    if _CODE_KEYWORD_PATTERN.search(raw):
        return True
    if _REQUESTS_LIBRARY_PATTERN.search(raw):
        return True
    return False


def _contains_refusal_marker(raw: str) -> bool:
    """Return True when the response text matches refusal heuristics."""
    lower = raw.lower()
    return any(marker in lower for marker in _REFUSAL_MARKERS)


def _is_refusal_response(raw: str) -> bool:
    """Classify plain-text refusals that lack code-like signals."""
    if _contains_code_marker(raw):
        return False
    return _contains_refusal_marker(raw)


def _strip_markdown_fences(raw: str) -> str:
    """Remove optional ``` / ```json fences and isolate JSON object text."""
    text = raw.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines:
            lines = lines[1:]
        while lines and lines[-1].strip() == "```":
            lines.pop()
        text = "\n".join(lines).strip()
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return text
    return text[start : end + 1]


def _normalize_compose_service_name(value: str) -> str:
    """Strip a trailing ``:port`` suffix when models confuse DNS with host:port pairs.

    Docker Compose DNS names are service identifiers (for example ``web``), not
    ``web:5000``. Numeric ports after the final colon are removed defensively.
    """
    stripped = value.strip()
    if ":" in stripped:
        host, _, maybe_port = stripped.rpartition(":")
        if maybe_port.isdigit() and host:
            return host
    return stripped


def _coerce_payload_fields(data: dict[str, Any]) -> dict[str, str]:
    """Validate JSON object shape and normalize all required string fields.

    Raises:
        LLMResponseError: When fields are missing or not strings.
    """
    missing = [name for name in _REQUIRED_JSON_FIELDS if name not in data]
    if missing:
        msg = f"Missing required JSON fields: {', '.join(sorted(missing))}"
        raise LLMResponseError(msg)
    out: dict[str, str] = {}
    for name in _REQUIRED_JSON_FIELDS:
        value = data[name]
        if not isinstance(value, str) or not value.strip():
            raise LLMResponseError(f"Field {name!r} must be a non-empty string.")
        out[name] = value.strip()
    return out


def parse_llm_response(raw: str) -> ExploitPayload:
    """Strip fences, parse JSON, validate fields, and enforce refusal rules.

    Args:
        raw: Untouched model output prior to structured parsing.

    Returns:
        Exploit payload with a freshly generated identifier.

    Raises:
        LLMRefusalError: When the output matches the configured refusal heuristic.
        LLMResponseError: When JSON is invalid or required fields are absent.
    """
    if _is_refusal_response(raw):
        raise LLMRefusalError("Model response classified as a safety refusal.")

    candidate = _strip_markdown_fences(raw)
    try:
        parsed: Any = json.loads(candidate)
    except json.JSONDecodeError as exc:
        raise LLMResponseError("Unable to parse JSON from model response.") from exc

    if not isinstance(parsed, dict):
        raise LLMResponseError("Model JSON must be an object at the top level.")

    fields = _coerce_payload_fields(parsed)
    fields["target_dns"] = _normalize_compose_service_name(fields["target_dns"])
    payload_id = uuid.uuid4()
    return ExploitPayload(
        payload_id=payload_id,
        language=fields["language"],
        target_dns=fields["target_dns"],
        raw_code=fields["raw_code"],
        execution_command=fields["execution_command"],
    )
