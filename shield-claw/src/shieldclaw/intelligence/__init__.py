"""LLM clients and prompt orchestration for vulnerability reasoning."""

from __future__ import annotations

from shieldclaw.intelligence.base import LLMProvider
from shieldclaw.intelligence.ollama import OllamaProvider
from shieldclaw.intelligence.openai_provider import OpenAIProvider
from shieldclaw.intelligence.parser import parse_llm_response
from shieldclaw.intelligence.poc_generator import PocGenerator
from shieldclaw.intelligence.prompts import (
    FINDING_SYSTEM_PROMPT,
    SYSTEM_PROMPT,
    build_diff_prompt,
    build_finding_prompt,
    build_user_prompt,
)

__all__ = [
    "FINDING_SYSTEM_PROMPT",
    "LLMProvider",
    "OllamaProvider",
    "OpenAIProvider",
    "PocGenerator",
    "SYSTEM_PROMPT",
    "build_diff_prompt",
    "build_finding_prompt",
    "build_user_prompt",
    "parse_llm_response",
]
