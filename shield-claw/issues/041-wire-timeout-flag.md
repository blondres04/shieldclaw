# Issue #41: Wire --timeout CLI flag to detonate() call

- **Tier:** 2 (Correctness)
- **Blocked by:** None
- **afk:** true

## What to build

The `--timeout` CLI flag is parsed in `__main__.py` but the SAST pipeline hardcodes `timeout=30` in `orchestrator.py` line ~458. Thread the CLI timeout value through the orchestrator to the `detonate()` call so the flag actually controls the detonation window.

## Acceptance criteria

- [ ] `--timeout N` CLI argument controls the detonation timeout (not hardcoded to 30)
- [ ] Default timeout remains 30 seconds when `--timeout` is not specified
- [ ] Unit test: orchestrator passes the configured timeout value to `detonate()`

## Relevant modules

- `src/shieldclaw/__main__.py`
- `src/shieldclaw/orchestrator.py`
- `src/shieldclaw/sandbox/docker_orchestrator.py`
