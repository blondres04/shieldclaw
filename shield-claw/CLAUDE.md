# ShieldClaw

SAST vulnerability verification pipeline. Takes Semgrep findings, generates exploit code, detonates in isolated containers, produces verdicts.

## Pipeline

```
Semgrep JSON → INGEST → TRIAGE → SCORE → APPROVE → POC_GEN → DETONATE → VERDICT
```

All inter-stage state persists to SQLite. Each finding has a lifecycle state. Current states written by the orchestrator: `INGESTED → TRIAGED → SCORED → APPROVED → VERDICTED` (terminal). `REJECTED` is terminal when approval is denied. Note: `POC_GENERATED` and `DETONATED` are not yet written as intermediate states — this is a known gap.

## Commands

```bash
# Tests (primary feedback loop — run after every change)
python -m pytest tests/ -x -q

# Type check
python -m mypy --strict src/

# Lint
python -m ruff check src/

# Run pipeline
python -m shieldclaw run --target <dir> --semgrep-output <semgrep.json> --timeout <seconds>
```

## Invariants (never violate these)

- INCONCLUSIVE always means INCONCLUSIVE — LLM score never tips a verdict
- Multi-CWE conflict → STATIC_ONLY wins (conservative) — not yet enforced, tracked in #42
- Exploitability score is stored in SQLite but does NOT influence verdict
- Interrupted detonations → INCONCLUSIVE on resume — never re-detonate
- 1:1 finding-to-exploit cardinality — one exploit per finding
- Attacker containers must have: read-only FS, non-root UID. Planned: `internal: true` network (#38), seccomp (#39)

## Issue workflow

- Open issues: `issues/*.md`
- Completed issues: `issues/done/`
- Priority: Tier 1 (Security) → Tier 2 (Correctness) → Tier 3 (Capability)
- Each issue contains its own acceptance criteria and constraints
- Implementation method: TDD (write failing test first, then implement, then refactor)

## Git workflow

- Never commit directly to `main`
- Create a branch per issue: `git checkout -b issue-NNN-short-name`
- Commit format: `fix(issue-NNN): short description` or `feat(issue-NNN): short description`
- After implementation + all tests pass → branch is ready for review
- Merge to main only after review passes

## Architecture reference

- PRD: `docs/prd-sast-pipeline-v02.md` (read when you need implementation decisions or module context)
- Deep modules: `orchestrator.py`, `sandbox/docker_orchestrator.py`, `persistence/store.py`
- Legacy diff path: being retired — do not invest in it

## Out of scope (do not implement)

- LLM score influencing verdict
- Multi-variant exploit generation per finding
- Custom seccomp profiles (Docker default is sufficient)
- Legacy diff path improvements
- ScoredFinding dataclass in memory
- Agentic source context enrichment (requires multi-turn tool-use refactor)
