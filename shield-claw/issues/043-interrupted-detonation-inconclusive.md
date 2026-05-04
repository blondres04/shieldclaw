# Issue #43: Mark interrupted detonations INCONCLUSIVE on resume

- **Tier:** 2 (Correctness)
- **Blocked by:** None
- **afk:** true

## What to build

When the pipeline resumes after a crash mid-detonation, findings stuck in `POC_GENERATED` state should be marked INCONCLUSIVE rather than silently re-detonated. Re-detonation could cause side effects on the target (double writes, double command execution).

End-to-end: in `orchestrator.py` resume logic, detect findings in `POC_GENERATED` state, write an INCONCLUSIVE verdict with reason "Detonation interrupted — marked INCONCLUSIVE on resume", and advance the finding state to VERDICTED.

## Acceptance criteria

- [ ] On resume, findings in POC_GENERATED state → INCONCLUSIVE verdict (no re-detonation)
- [ ] Verdict reason clearly states this was an interrupted detonation
- [ ] Findings in other states (TRIAGED, SCORED, APPROVED) resume normally
- [ ] Unit test: mock SQLite with a finding in POC_GENERATED → assert INCONCLUSIVE written, assert detonate() NOT called

## Relevant modules

- `src/shieldclaw/orchestrator.py`
- `src/shieldclaw/persistence/store.py`
- `src/shieldclaw/verdict/synthesizer.py`
