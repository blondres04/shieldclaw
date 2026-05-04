# Issue #44: Surface observer failures in report output

- **Tier:** 2 (Correctness)
- **Blocked by:** None
- **afk:** true

## What to build

When a Tier-2 observer (DockerDiff, TargetLogs) fails during `after_detonate()`, the failure is currently caught and logged but not reflected in the output. Add an `observer_warnings` field to the detonation result and the final JSON report so reviewers know when a verdict was reached with degraded evidence.

Also consolidate `observer/base.py` (13-line re-export) into `observer/__init__.py` as a cleanup.

## Acceptance criteria

- [ ] Failed observer → warning entry added to `observer_warnings` list (observer name + error message)
- [ ] `observer_warnings` field appears in the JSON report per finding
- [ ] Successful observers do not produce warnings
- [ ] `observer/base.py` re-export consolidated into `observer/__init__.py`
- [ ] Unit test: mock observer that raises → assert warning in report output
- [ ] Unit test: all observers succeed → assert empty warnings list

## Relevant modules

- `src/shieldclaw/sandbox/docker_orchestrator.py`
- `src/shieldclaw/observer/base.py`
- `src/shieldclaw/observer/__init__.py`
- `src/shieldclaw/reporting/builder.py`
- `src/shieldclaw/models.py`
