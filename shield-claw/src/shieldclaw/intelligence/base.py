"""Abstract provider contract for turning scan context into exploit payloads."""

from __future__ import annotations

from abc import ABC, abstractmethod

from shieldclaw.models import ExploitPayload, ScanContext


class LLMProvider(ABC):
    """Strategy interface for LLM-backed exploit generation."""

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
