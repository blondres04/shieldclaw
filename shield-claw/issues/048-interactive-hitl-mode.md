# Issue #48: Add interactive HITL approval mode (--interactive flag)

- **Tier:** 3 (Capability)
- **Blocked by:** None
- **afk:** true

## What to build

Add an `--interactive` CLI flag that makes the approval gate block in-process and prompt the user on stdin for each finding, rather than requiring a separate `shieldclaw approve` invocation.

Currently approval has two modes: auto (`SHIELDCLAW_AUTO_APPROVE=1`) and async (pipeline stops, manual `shieldclaw approve`, re-run). This adds a third: interactive (pipeline blocks, user approves/rejects per finding in terminal, pipeline continues).

End-to-end: add `--interactive` flag to `__main__.py`, extend `approval/gate.py` with a blocking stdin prompt, wire through `orchestrator.py` so the SAST pipeline pauses at the approval stage and waits for user input per finding.

## Acceptance criteria

- [ ] `--interactive` flag added to CLI argument parser
- [ ] With `--interactive`: pipeline displays finding summary and blocks on stdin (`y/n/s` for approve/reject/skip)
- [ ] Approved findings proceed to PoC generation; rejected findings are skipped
- [ ] Without `--interactive`: existing async behavior is unchanged
- [ ] `--interactive` and `SHIELDCLAW_AUTO_APPROVE=1` are mutually exclusive (error if both set)
- [ ] Unit test: mock stdin with approval input → finding proceeds
- [ ] Unit test: mock stdin with rejection → finding skipped

## Relevant modules

- `src/shieldclaw/__main__.py`
- `src/shieldclaw/approval/gate.py`
- `src/shieldclaw/orchestrator.py`
