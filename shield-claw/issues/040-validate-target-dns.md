# Issue #40: Validate PoC target_dns against compose service names before detonation

- **Tier:** 1 (Security)
- **Blocked by:** None
- **afk:** true

## What to build

Before detonating an exploit, cross-check the LLM-generated `ExploitPayload.target_dns` against the actual service names in the compose YAML. If `target_dns` doesn't match any service, skip detonation and mark the finding INCONCLUSIVE with a reason explaining the mismatch.

End-to-end: parse compose service names in the orchestrator (or sandbox module), validate before `detonate()`, handle the mismatch case, and write a unit test with a mismatched `target_dns`.

## Acceptance criteria

- [ ] Compose service names are extracted from the compose YAML before detonation
- [ ] `ExploitPayload.target_dns` is validated against the service name list
- [ ] Mismatched `target_dns` → finding marked INCONCLUSIVE with descriptive reason
- [ ] Detonation is skipped (no container launched) on mismatch
- [ ] Unit test: ExploitPayload with invalid target_dns → INCONCLUSIVE verdict

## Relevant modules

- `src/shieldclaw/orchestrator.py`
- `src/shieldclaw/sandbox/docker_orchestrator.py`
- `src/shieldclaw/models.py`
