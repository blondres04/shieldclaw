"""LLM clients and prompt orchestration for vulnerability reasoning."""

from __future__ import annotations

from shieldclaw.intelligence.base import LLMProvider
from shieldclaw.intelligence.ollama import OllamaProvider
from shieldclaw.intelligence.parser import parse_llm_response
from shieldclaw.intelligence.prompts import SYSTEM_PROMPT, build_user_prompt

__all__ = [
    "LLMProvider",
    "OllamaProvider",
    "SYSTEM_PROMPT",
    "build_user_prompt",
    "parse_llm_response",
]
