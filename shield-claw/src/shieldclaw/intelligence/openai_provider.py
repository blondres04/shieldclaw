"""OpenAI Chat Completions provider for exploit generation and scoring.

Uses ``gpt-4o-mini`` by default: lowest per-token cost while still producing
reliable JSON-structured outputs.  See ADR-003 for the model selection rationale.

Environment variables
---------------------
``OPENAI_API_KEY``  — required; bearer token for the OpenAI API.
``OPENAI_BASE_URL`` — optional; override for API-compatible endpoints.
``OPENAI_MODEL``    — optional; override model name (default ``gpt-4o-mini``).
"""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

from shieldclaw.exceptions import LLMConnectionError, LLMRefusalError, LLMResponseError
from shieldclaw.intelligence.base import LLMProvider
from shieldclaw.intelligence.parser import parse_llm_response
from shieldclaw.intelligence.prompts import SYSTEM_PROMPT, build_diff_prompt
from shieldclaw.models import ExploitPayload, ScanContext

_LOG = logging.getLogger(__name__)

_DEFAULT_BASE = "https://api.openai.com/v1"
_DEFAULT_MODEL = "gpt-4o-mini"
_TIMEOUT_SECONDS = 120.0

# Models that support OpenAI's structured-output response_format.
_JSON_OBJECT_MODELS: frozenset[str] = frozenset(
    {
        "gpt-4o",
        "gpt-4o-mini",
        "gpt-4-turbo",
        "gpt-4-turbo-preview",
        "gpt-3.5-turbo",
        "gpt-3.5-turbo-16k",
    }
)

# Refusal heuristics: phrases that indicate the model declined to answer.
_REFUSAL_PHRASES: tuple[str, ...] = (
    "i cannot",
    "i'm not able to",
    "i am not able to",
    "i won't",
    "i will not",
    "as an ai",
    "i'd rather not",
)


def _looks_like_refusal(text: str) -> bool:
    lower = text.lower()
    return any(phrase in lower for phrase in _REFUSAL_PHRASES)


class OpenAIProvider(LLMProvider):
    """OpenAI Chat Completions provider.

    Phase 4 replaces the v0.1 stub with a real implementation that uses the
    ``/v1/chat/completions`` endpoint, requests JSON output mode when the
    model supports it, and reuses the existing ``parse_llm_response`` parser.

    Args:
        api_key: Bearer token (defaults to ``OPENAI_API_KEY``).
        base_url: API root (defaults to the public OpenAI endpoint, or
            ``OPENAI_BASE_URL`` if set).
        model: Model name (defaults to ``OPENAI_MODEL`` or ``gpt-4o-mini``).
        timeout_seconds: HTTP read timeout.
    """

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        timeout_seconds: float = _TIMEOUT_SECONDS,
    ) -> None:
        self._api_key = api_key or os.environ.get("OPENAI_API_KEY") or ""
        resolved_base = base_url or os.environ.get("OPENAI_BASE_URL", _DEFAULT_BASE)
        self._base_url = resolved_base.rstrip("/")
        self._model = model or os.environ.get("OPENAI_MODEL", _DEFAULT_MODEL)
        self._timeout = timeout_seconds

    def _make_request(
        self,
        messages: list[dict[str, str]],
        *,
        require_json_object: bool = False,
    ) -> str:
        """POST to ``/chat/completions`` and return the assistant message content.

        Args:
            messages: OpenAI message list (system + user turns).
            require_json_object: When ``True`` and the model supports it, add
                ``response_format={"type": "json_object"}``.

        Returns:
            Raw assistant message text.

        Raises:
            LLMConnectionError: On transport-level failures.
            LLMResponseError: On malformed API responses.
        """
        if not self._api_key:
            raise LLMConnectionError(
                "OPENAI_API_KEY is not set.  Export it before running ShieldClaw."
            )

        body: dict[str, Any] = {
            "model": self._model,
            "messages": messages,
            "temperature": 0,
        }

        model_key = self._model.split(":")[0].lower()
        if require_json_object and any(k in model_key for k in _JSON_OBJECT_MODELS):
            body["response_format"] = {"type": "json_object"}

        url = f"{self._base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

        try:
            with httpx.Client(timeout=self._timeout) as client:
                response = client.post(url, json=body, headers=headers)
                response.raise_for_status()
                data = response.json()
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            raise LLMConnectionError(
                f"OpenAI API returned HTTP {status}: {exc.response.text[:200]}"
            ) from exc
        except httpx.HTTPError as exc:
            raise LLMConnectionError(f"Unable to reach the OpenAI API: {exc}") from exc
        except ValueError as exc:
            raise LLMResponseError("OpenAI returned non-JSON content.") from exc

        choices = data.get("choices")
        if not isinstance(choices, list) or not choices:
            raise LLMResponseError("OpenAI response missing 'choices' array.")

        message = choices[0].get("message", {})
        content = message.get("content")
        if not isinstance(content, str):
            raise LLMResponseError("OpenAI response missing string 'content' in choices[0].")

        finish_reason = choices[0].get("finish_reason", "")
        if finish_reason == "content_filter":
            raise LLMRefusalError("OpenAI content filter blocked the request.")

        _LOG.debug("OpenAI raw response (model=%s): %s", self._model, content[:400])
        return content

    def generate_exploit(self, context: ScanContext) -> ExploitPayload:
        """Generate an exploit payload from scan context using OpenAI.

        Args:
            context: Immutable diff and compose snapshot.

        Returns:
            Parsed ``ExploitPayload`` ready for sandbox detonation.

        Raises:
            LLMConnectionError: When the API is unreachable or returns HTTP errors.
            LLMRefusalError: When OpenAI refuses the request.
            LLMResponseError: When the response cannot be parsed into a payload.
        """
        messages: list[dict[str, str]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": build_diff_prompt(context)},
        ]
        raw = self._make_request(messages, require_json_object=True)

        if _looks_like_refusal(raw):
            raise LLMRefusalError("OpenAI response classified as a safety refusal.")

        return parse_llm_response(raw)

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        """Send a chat pair and return the raw assistant text.

        Args:
            system_prompt: System role instructions.
            user_prompt: User-turn content.

        Returns:
            Verbatim assistant message string.

        Raises:
            LLMConnectionError: When the API is unreachable.
            LLMResponseError: When the response is malformed.
        """
        messages: list[dict[str, str]] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]
        return self._make_request(messages, require_json_object=True)
