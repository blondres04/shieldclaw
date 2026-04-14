"""Placeholder Anthropic integration reserved for future Messages API support."""

from __future__ import annotations

import os

import httpx

from shieldclaw.exceptions import LLMConnectionError, LLMResponseError
from shieldclaw.intelligence.base import LLMProvider
from shieldclaw.models import ExploitPayload, ScanContext

_DEFAULT_BASE = "https://api.anthropic.com"
_TIMEOUT_SECONDS = 60.0


class AnthropicProvider(LLMProvider):
    """Stub provider that checks for an API key and declines exploit synthesis."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        timeout_seconds: float = _TIMEOUT_SECONDS,
    ) -> None:
        """Capture credentials for future Anthropic HTTP wiring.

        Args:
            api_key: ``x-api-key`` value (defaults to ``ANTHROPIC_API_KEY``).
            base_url: API host root for Anthropic-compatible deployments.
            timeout_seconds: Reserved timeout for forthcoming HTTP calls.
        """
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self._base_url = (base_url or _DEFAULT_BASE).rstrip("/")
        self._timeout = timeout_seconds

    def generate_exploit(self, _context: ScanContext) -> ExploitPayload:
        """Decline exploit generation while ensuring configuration exists.

        Args:
            _context: Unused in this stub; retained for interface compatibility.

        Returns:
            Never returns; always raises.

        Raises:
            LLMConnectionError: When no API key is configured.
            LLMResponseError: Always, because the Messages API path is not implemented.
        """
        if not self._api_key:
            raise LLMConnectionError("ANTHROPIC_API_KEY is not configured.")

        with httpx.Client(
            timeout=self._timeout,
            headers={
                "x-api-key": self._api_key,
                "anthropic-version": "2023-06-01",
            },
            base_url=self._base_url,
        ) as _client:
            _ = _client  # Future: POST /v1/messages with streamed completions.

        raise LLMResponseError(
            "AnthropicProvider.generate_exploit is not implemented; use OllamaProvider."
        )
