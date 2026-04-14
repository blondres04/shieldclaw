"""Placeholder OpenAI integration that validates HTTP connectivity only."""

from __future__ import annotations

import os

import httpx

from shieldclaw.exceptions import LLMConnectionError, LLMResponseError
from shieldclaw.intelligence.base import LLMProvider
from shieldclaw.models import ExploitPayload, ScanContext

_DEFAULT_BASE = "https://api.openai.com/v1"
_TIMEOUT_SECONDS = 60.0


class OpenAIProvider(LLMProvider):
    """Stub provider that exercises ``httpx`` but does not synthesize exploits."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        timeout_seconds: float = _TIMEOUT_SECONDS,
    ) -> None:
        """Capture credentials for future chat completion wiring.

        Args:
            api_key: Bearer token (defaults to ``OPENAI_API_KEY``).
            base_url: API root (defaults to the public OpenAI endpoint).
            timeout_seconds: Network timeout applied to stubbed HTTP calls.
        """
        self._api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self._base_url = (base_url or _DEFAULT_BASE).rstrip("/")
        self._timeout = timeout_seconds

    def generate_exploit(self, _context: ScanContext) -> ExploitPayload:
        """Reject exploit generation while optionally validating API reachability.

        Args:
            _context: Unused in this stub; retained for interface compatibility.

        Returns:
            Never returns; always raises.

        Raises:
            LLMConnectionError: When no API key is configured or the models probe fails.
            LLMResponseError: Always, because chat completions are not implemented.
        """
        if not self._api_key:
            raise LLMConnectionError("OPENAI_API_KEY is not configured.")

        models_url = f"{self._base_url}/models"
        try:
            with httpx.Client(timeout=self._timeout) as client:
                probe = client.get(
                    models_url,
                    headers={"Authorization": f"Bearer {self._api_key}"},
                )
                probe.raise_for_status()
        except httpx.HTTPError as exc:
            raise LLMConnectionError("Unable to reach the OpenAI HTTP API.") from exc

        raise LLMResponseError(
            "OpenAIProvider.generate_exploit is not implemented; use OllamaProvider."
        )
