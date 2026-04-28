"""Abstract provider contract for turning scan context into exploit payloads.

``LLMProvider`` exposes two abstract methods:

* ``generate_exploit`` — high-level exploit generation (original v0.1 API).
* ``complete`` — raw chat completion returning the assistant's text verbatim;
  used by the ``scoring`` package to send arbitrary structured prompts without
  going through the exploit-payload parsing layer.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from shieldclaw.models import ExploitPayload, ScanContext


class LLMProvider(ABC):
    """Strategy interface for LLM-backed exploit generation and raw completion."""

    @abstractmethod
    def generate_exploit(self, context: ScanContext) -> ExploitPayload:
        """Produce an exploit payload from immutable scan context.

        Args:
            context: Repository diff and compose metadata supplied to the model.

        Returns:
            Parsed exploit payload ready for sandbox execution.

        Raises:
            LLMConnectionError: When the remote model endpoint is unreachable.
            LLMRefusalError: When the model declines for policy reasons.
            LLMResponseError: When the model output cannot be parsed into a payload.
        """
        pass

    @abstractmethod
    def complete(self, system_prompt: str, user_prompt: str) -> str:
        """Send a chat message pair and return the raw assistant text.

        This lower-level method allows callers to control both the system and
        user prompts without going through the exploit-payload parsing layer.

        Args:
            system_prompt: Instructions placed in the system role.
            user_prompt: The user-turn content.

        Returns:
            Raw assistant response text (may contain markdown fences or JSON).

        Raises:
            LLMConnectionError: When the remote model endpoint is unreachable.
            LLMResponseError: When the HTTP payload is malformed.
        """
        pass
