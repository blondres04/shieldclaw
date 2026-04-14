"""LLM clients and prompt orchestration for vulnerability reasoning."""

from __future__ import annotations

from shieldclaw.intelligence.anthropic_provider import AnthropicProvider
from shieldclaw.intelligence.base import LLMProvider
from shieldclaw.intelligence.ollama import OllamaProvider
from shieldclaw.intelligence.openai_provider import OpenAIProvider
from shieldclaw.intelligence.parser import parse_llm_response
from shieldclaw.intelligence.prompts import SYSTEM_PROMPT, build_user_prompt

__all__ = [
    "AnthropicProvider",
    "LLMProvider",
    "OllamaProvider",
    "OpenAIProvider",
    "SYSTEM_PROMPT",
    "build_user_prompt",
    "parse_llm_response",
]
