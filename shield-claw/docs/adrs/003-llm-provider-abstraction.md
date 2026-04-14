# ADR-003: LLM Provider Abstraction

## Status

Accepted (placeholder — formalize from Phase 6 §8)

## Context

Operators may run Ollama locally or use hosted APIs (OpenAI, Anthropic). Call sites should not depend on a single vendor SDK shape.

## Decision

Expose an `LLMProvider` protocol (or abstract base) in `intelligence/` with concrete providers per backend. Parsing and prompts stay co-located with intelligence code.

## Consequences

- New backends add a class and CLI wiring without changing sandbox or reporting.
- Provider code must not import `sandbox` or `reporting` (enforced by ADR-001 and fitness tests).
