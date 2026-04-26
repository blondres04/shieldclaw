"""
File:        src/shieldclaw/exceptions.py
Purpose:     Typed exception hierarchy for all ShieldClaw pipeline and integration failures.
Public API:
  - ShieldClawError (base exception, carries .message: str)
  - AggregationError
  - LLMRefusalError
  - LLMResponseError
  - LLMConnectionError
  - DockerNotAvailableError
  - SandboxStartError
  - DetonationError
Depends On:
  - stdlib only
Used By:
  - src/shieldclaw/orchestrator.py
  - src/shieldclaw/context/aggregator.py
  - src/shieldclaw/intelligence/base.py
  - src/shieldclaw/intelligence/ollama.py
  - src/shieldclaw/intelligence/openai_provider.py
  - src/shieldclaw/intelligence/anthropic_provider.py
  - src/shieldclaw/intelligence/parser.py
  - src/shieldclaw/sandbox/docker_orchestrator.py
Use Cases:
  - SCAN-001 (Run Vulnerability Scan)
"""

from __future__ import annotations


class ShieldClawError(Exception):
    """Base error type for all ShieldClaw failures.

    Args:
        message: Human-readable explanation suitable for logs and operators.
    """

    def __init__(self, message: str) -> None:
        self.message: str = message
        super().__init__(message)


class AggregationError(ShieldClawError):
    """Raised when context or telemetry aggregation cannot be completed."""


class LLMRefusalError(ShieldClawError):
    """Raised when the model declines to answer for policy or safety reasons."""


class LLMResponseError(ShieldClawError):
    """Raised when the model response is malformed or cannot be parsed."""


class LLMConnectionError(ShieldClawError):
    """Raised when the HTTP client cannot reach the configured LLM endpoint."""


class DockerNotAvailableError(ShieldClawError):
    """Raised when the Docker engine or CLI is missing or unreachable."""


class SandboxStartError(ShieldClawError):
    """Raised when the attacker sandbox cannot be created or started."""


class DetonationError(ShieldClawError):
    """Raised when controlled execution of a payload fails unexpectedly."""
