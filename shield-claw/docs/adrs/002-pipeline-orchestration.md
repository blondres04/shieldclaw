# ADR-002: Pipeline Orchestration Placement

## Status

Accepted — 2026-04-28

## Context

The scan pipeline coordinates up to seven sequential stages: ingest → triage →
score → approve → PoC generate → detonate → verdict. Each stage produces
immutable data consumed by the next. Errors at any stage must trigger
deterministic teardown and report emission.

The key questions are: where does the state machine live, and who is
responsible for wiring stage outputs to stage inputs?

## Decision

Keep all orchestration in `orchestrator.py` at the `shieldclaw` package root —
not inside any feature package. The CLI dispatches to `Orchestrator.run()`.

The orchestrator owns:
- The per-stage transition logic (state constants, error mapping).
- The `finally` block that always runs teardown and report emission.
- Cross-boundary imports (the only file permitted to import from all packages).
- Resumability: checking SQLite state and skipping already-completed stages.

Two internal execution paths exist:
- `_run_sast()` — the v0.2 SAST pipeline (Phases 1–6).
- `_run_legacy()` — the v0.1 diff-based detonation path, preserved for
  backwards compatibility until Phase 5 integrates it.

## Consequences

**Positive**
- The state machine is the single source of truth for pipeline ordering.
- Teardown and report emission are guaranteed regardless of which stage fails.
- Resumability (resume from `TRIAGED`, `SCORED`, `APPROVED`, etc.) is
  implemented in one place with no risk of a feature package silently
  resuming from stale state.

**Negative**
- `orchestrator.py` grows with each new phase. A future refactor may extract
  sub-orchestrators per tier (scoring tier, detonation tier) once the file
  exceeds ~600 lines.
- Testing the orchestrator requires mocking many collaborators simultaneously,
  making orchestrator tests heavier than feature-package unit tests.

## Alternatives Considered

- **Pipeline-inside-each-feature**: Each package owns its own "run" method.
  Rejected: teardown becomes fragile when stage N fails to call stage N+1's
  cleanup.
- **Separate orchestrator package**: A `pipeline/` package.  Rejected:
  `orchestrator.py` is explicitly allowed to cross boundaries; wrapping it
  in a new package would require that package to also be exempted, adding
  complexity with no benefit.
