# ADR-002: Pipeline Orchestration Placement

## Status

Accepted (placeholder — formalize from Phase 6 §8)

## Context

The scan pipeline coordinates context aggregation, LLM calls, sandbox execution, and reporting. A single orchestrator keeps ordering and error handling explicit.

## Decision

Keep orchestration in `orchestrator.py` at the `shieldclaw` package root (not inside a feature module). The CLI entrypoint dispatches to this orchestrator.

## Consequences

- `orchestrator.py` may import from all feature modules; feature modules must not import orchestrator.
- State-machine style flow remains the single source of truth for pipeline ordering.
