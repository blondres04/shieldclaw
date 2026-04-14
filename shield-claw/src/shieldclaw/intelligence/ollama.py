"""Ollama-backed LLM provider using the HTTP API with deterministic decoding."""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

from shieldclaw.exceptions import LLMConnectionError, LLMResponseError
from shieldclaw.intelligence.base import LLMProvider
from shieldclaw.intelligence.parser import parse_llm_response
from shieldclaw.intelligence.prompts import SYSTEM_PROMPT, build_user_prompt
from shieldclaw.models import ExploitPayload, ScanContext

_LOG = logging.getLogger(__name__)

_DEFAULT_BASE_URL = "http://localhost:11434"
_DEFAULT_MODEL = "gemma3:4b"
_TIMEOUT_SECONDS = 60.0


class OllamaProvider(LLMProvider):
    """Calls Ollama's chat endpoint and parses the assistant message into payloads."""

    def __init__(
        self,
        *,
        base_url: str | None = None,
        model: str | None = None,
        timeout_seconds: float = _TIMEOUT_SECONDS,
    ) -> None:
        """Configure HTTP client defaults for a local or remote Ollama daemon.

        Args:
            base_url: Root URL for Ollama (defaults to ``OLLAMA_BASE_URL`` or localhost).
            model: Model tag to request (defaults to ``OLLAMA_MODEL`` or ``gemma3:4b``).
            timeout_seconds: Socket read timeout for each request.
        """
        resolved_base = base_url or os.environ.get("OLLAMA_BASE_URL", _DEFAULT_BASE_URL)
        self._base_url = resolved_base.rstrip("/")
        self._model = model or os.environ.get("OLLAMA_MODEL", _DEFAULT_MODEL)
        self._timeout = timeout_seconds

    def generate_exploit(self, context: ScanContext) -> ExploitPayload:
        """Request an exploit script from Ollama and parse the assistant reply.

        Args:
            context: Immutable scan inputs forwarded to the prompt builder.

        Returns:
            Structured exploit metadata produced by ``parse_llm_response``.

        Raises:
            LLMConnectionError: When the HTTP transport or Ollama daemon fails.
            LLMRefusalError: Propagated from the parser when safety heuristics match.
            LLMResponseError: When the HTTP payload is malformed or parsing fails.
        """
        user_prompt = build_user_prompt(context)
        payload: dict[str, Any] = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            "stream": False,
            "options": {"temperature": 0},
        }
        url = f"{self._base_url}/api/chat"
        try:
            with httpx.Client(timeout=self._timeout) as client:
                response = client.post(url, json=payload)
                response.raise_for_status()
                body = response.json()
        except httpx.HTTPError as exc:
            raise LLMConnectionError("Unable to reach the Ollama HTTP API.") from exc
        except ValueError as exc:
            raise LLMResponseError("Ollama returned non-JSON content.") from exc

        raw = self._extract_assistant_text(body)
        _LOG.debug("Raw Ollama response: %s", raw)
        return parse_llm_response(raw)

    @staticmethod
    def _extract_assistant_text(body: dict[str, Any]) -> str:
        """Pull assistant text from an Ollama chat response envelope.

        Args:
            body: Parsed JSON object returned by ``/api/chat``.

        Returns:
            Assistant message content suitable for downstream parsing.

        Raises:
            LLMResponseError: When the expected keys are missing.
        """
        message = body.get("message")
        if not isinstance(message, dict):
            raise LLMResponseError("Ollama response missing 'message' object.")
        content = message.get("content")
        if not isinstance(content, str):
            raise LLMResponseError("Ollama response missing string 'content' field.")
        return content
