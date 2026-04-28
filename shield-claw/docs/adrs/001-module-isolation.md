# ADR-001: Feature Module Isolation

## Status

Accepted — 2026-04-28

## Context

ShieldClaw's pipeline has grown from four stages (v0.1) to eleven feature
packages (v0.2): `context`, `ingest`, `intelligence`, `approval`, `observer`,
`persistence`, `reporting`, `sandbox`, `scoring`, `triage`, and `verdict`.

Without explicit boundaries, any feature package can import any other.
This makes the dependency graph opaque and turns unit tests into integration
tests — every test that touches `scoring` would transitively pull in `sandbox`,
`persistence`, and Docker clients.

The problem compounds at scale: a change to `persistence/store.py` could
silently break `scoring`, `triage`, and `observer` through transitive imports,
even though none of those packages should know about database layout.

## Decision

Feature packages communicate **only** through:
1. `shieldclaw.models` — immutable frozen dataclasses; the shared vocabulary.
2. `shieldclaw.exceptions` — the `ShieldClawError` hierarchy.
3. Direct injection — the orchestrator constructs concrete objects and passes
   them as arguments; feature packages never reach out for collaborators.

Only `orchestrator.py` and `__main__.py` may cross package boundaries.

A documented allowlist (`_CROSS_FEATURE_ALLOWLIST` in `test_architecture.py`)
covers one necessary exception: `scoring/` imports `intelligence.base`
(for the `LLMProvider` ABC) and `intelligence.parser` (for JSON fence
stripping). This is the only permitted cross-feature dependency.

The rule is enforced by static AST analysis in `tests/test_architecture.py`
on every test run and in the `arch-guard` pre-commit hook.

## Consequences

**Positive**
- Unit tests for any feature package run with zero Docker, zero LLM, and
  zero database setup.
- Developers can reason about a single package without loading the full call
  graph.
- The isolation test provides a continuous build-gate against regressions.

**Negative**
- New shared types must be added to `models.py`, which grows over time.
  A future `contracts.py` split may become necessary at ~20+ model types.
- The allowlist must be manually updated when a new cross-feature dependency
  is introduced (though this is intentional friction that prompts documentation).

## Alternatives Considered

- **Dependency injection framework**: Heavier, adds a runtime library, and
  makes the dependency graph implicit again (resolved at runtime).
- **Event bus / message queue**: Correct for distributed systems; unnecessary
  complexity for a single-process CLI tool.
- **No enforcement**: Status quo before v0.2. Rejected because CI feedback for
  isolation violations was zero — bugs propagated silently.
