# Issue #45: Retry once on LLM refusal and add REFUSED finding state

- **Tier:** 2 (Correctness)
- **Blocked by:** None
- **afk:** true

## What to build

When the LLM refuses to generate a PoC (detected by `intelligence/parser.py` refusal phrases), the pipeline currently raises an exception that can crash the scan. Instead:

1. Retry once with a rephrased prompt (adjust framing to emphasize authorized security testing context)
2. If the second attempt also refuses, mark the finding with a new terminal state REFUSED
3. REFUSED findings appear in the final report with a clear reason

End-to-end: add retry logic to `intelligence/poc_generator.py`, add REFUSED state to `models.py`, handle REFUSED in `orchestrator.py` (skip detonation, write to report), update `persistence/store.py` if needed.

## Acceptance criteria

- [ ] First LLM refusal triggers one retry with rephrased prompt
- [ ] Second refusal → finding state set to REFUSED (not exception)
- [ ] REFUSED is a terminal state — finding does not proceed to detonation
- [ ] REFUSED findings appear in JSON report with reason "LLM refused to generate PoC after retry"
- [ ] Scan continues processing remaining findings (no crash)
- [ ] Unit test: mock LLM that refuses twice → finding marked REFUSED
- [ ] Unit test: mock LLM that refuses once then succeeds → finding proceeds normally

## Relevant modules

- `src/shieldclaw/intelligence/poc_generator.py`
- `src/shieldclaw/intelligence/parser.py`
- `src/shieldclaw/models.py`
- `src/shieldclaw/orchestrator.py`
- `src/shieldclaw/persistence/store.py`
