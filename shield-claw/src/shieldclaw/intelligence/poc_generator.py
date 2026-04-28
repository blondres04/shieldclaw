"""Finding-aware proof-of-concept exploit generator.

``PocGenerator`` wraps an ``LLMProvider`` to produce a ``ExploitPayload``
tailored to a specific SAST ``Finding``, using source-code context and the
Docker Compose topology.

Unlike the legacy ``OllamaProvider.generate_exploit()`` which uses a diff-centric
prompt, ``PocGenerator`` uses the finding-centric prompt from ``prompts.py`` and
calls ``LLMProvider.complete()`` directly, feeding the raw text through the
existing ``parse_llm_response`` parser.
"""

from __future__ import annotations

import logging

from shieldclaw.exceptions import LLMResponseError
from shieldclaw.intelligence.base import LLMProvider
from shieldclaw.intelligence.parser import parse_llm_response
from shieldclaw.intelligence.prompts import FINDING_SYSTEM_PROMPT, build_finding_prompt
from shieldclaw.models import ExploitPayload, Finding

_LOG = logging.getLogger(__name__)


class PocGenerator:
    """Generate a ``ExploitPayload`` from a SAST ``Finding``.

    Args:
        provider: LLM provider; only ``complete()`` is used.
        model_name: Human-readable model identifier for logging.
    """

    def __init__(self, provider: LLMProvider, *, model_name: str = "unknown") -> None:
        self._provider = provider
        self._model_name = model_name

    def generate(
        self,
        finding: Finding,
        source_excerpt: str,
        compose_yaml: str,
    ) -> ExploitPayload:
        """Generate a proof-of-concept exploit for the given finding.

        Args:
            finding: SAST finding that describes the vulnerability.
            source_excerpt: Annotated source lines surrounding the finding.
            compose_yaml: Docker Compose YAML for the target application.

        Returns:
            A parsed ``ExploitPayload`` ready for sandbox detonation.

        Raises:
            LLMConnectionError: When the provider cannot be reached.
            LLMRefusalError: When the model refuses to generate the PoC.
            LLMResponseError: When the model output cannot be parsed.
        """
        user_prompt = build_finding_prompt(finding, source_excerpt, compose_yaml)
        _LOG.debug(
            "Generating PoC for finding %s (%s) via %s",
            finding.finding_id,
            finding.rule_id,
            self._model_name,
        )
        raw = self._provider.complete(FINDING_SYSTEM_PROMPT, user_prompt)
        _LOG.debug("Raw PoC response: %s", raw[:500])
        try:
            return parse_llm_response(raw)
        except LLMResponseError:
            _LOG.warning("Failed to parse PoC for finding %s; re-raising", finding.finding_id)
            raise
