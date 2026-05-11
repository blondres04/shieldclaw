# ShieldClaw

SQLi-focused SAST validation pipeline. The default MVP path takes Semgrep
`CWE-89` findings, scores them, requires approval, generates one PoC, detonates
inside a constrained Docker attacker container, and produces evidence-backed
JSON/Markdown reports.

## Pipeline

```text
Semgrep JSON -> INGEST -> TRIAGE -> SCORE -> AWAITING_APPROVAL
  -> APPROVE or REJECT -> POC_GEN -> DETONATE -> VERDICT
```

All inter-stage state persists to SQLite. Current SQLi MVP finding states:
`INGESTED`, `TRIAGED`, `DEFERRED`, `AWAITING_APPROVAL`, `APPROVED`, `REJECTED`,
`POC_GENERATED`, `VERDICTED`, and `REFUSED`. Legacy `SCORED` rows remain
approval-compatible for resume.

## Commands

```bash
# Tests (primary feedback loop)
python -m pytest tests/ -x -q

# Type check
python -m mypy --strict src/

# Lint
python -m ruff check src/

# Run pipeline
python -m shieldclaw run --target <dir> --semgrep-output <semgrep.json> --timeout <seconds>
```

## Invariants

- Default MVP validation is `CWE-89` SQL injection only.
- Non-`CWE-89` findings remain visible but are not scored, approved, PoC-generated, or detonated by default.
- `INCONCLUSIVE` always means `INCONCLUSIVE`; LLM score never tips a verdict.
- Multi-CWE conflict resolves conservatively to `STATIC_ONLY`.
- Exploitability score is stored in SQLite but does not influence verdict.
- Interrupted detonations become `INCONCLUSIVE` on resume; never silently re-detonate.
- One approved finding generates at most one PoC.
- Attacker containers must use constrained runtime settings and internal networking.

## Issue Workflow

- Open implementation work lives in GitHub issues.
- Completed local issue notes live in `issues/done/` when present.
- Priority: security, correctness, then capability.
- Implementation method: write or update focused tests, implement, then refactor.

## Git Workflow

- Never commit directly to `main`.
- Create a branch per issue or issue cluster.
- Keep commits focused and do not stage `.codex/`.
- Commit format: `feat(scope): short description`, `fix(scope): short description`, `test(scope): short description`, `docs(scope): short description`, or `chore: short description`.

## Architecture Reference

- PRD: `docs/prd-sast-pipeline-v02.md`.
- Manual SQLi MVP gate: `docs/sqli-mvp-validation-checklist.md`.
- Deep modules: `orchestrator.py`, `sandbox/docker_orchestrator.py`, `persistence/store.py`.
- Legacy diff path is preserved but not the MVP investment path.

## Out of Scope

- Broad vulnerability-class support beyond `CWE-89`.
- `CWE-78` or `CWE-434` MVP implementation.
- SARIF release gating.
- Web UI.
- Patch generation or patch verification.
- LLM score influencing verdict.
- Multi-variant exploit generation per finding.
- Legacy diff path improvements.
