# ADR-001: Feature Module Isolation

## Status

Accepted (placeholder — formalize from Phase 6 §8)

## Context

ShieldClaw splits pipeline responsibilities into `context/`, `intelligence/`, `sandbox/`, and `reporting/`. Cross-imports between these packages would blur boundaries and complicate testing and deployment.

## Decision

Feature modules communicate only through `shieldclaw.models` and `shieldclaw.exceptions`. Orchestration code outside those packages may import from any of them.

## Consequences

- Architectural fitness tests (see `tests/test_architecture.py`) enforce import rules without Docker or LLM calls.
- New shared types belong in `models.py` (or a future dedicated contracts module) rather than in cross-feature imports.
