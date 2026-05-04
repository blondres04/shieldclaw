# Issue #42: Enforce conservative multi-CWE conflict resolution and warn on unmapped CWEs

- **Tier:** 2 (Correctness)
- **Blocked by:** None
- **afk:** true

## What to build

Fix two triage classifier gaps in `triage/classifier.py`:

1. **Multi-CWE conflict:** When a finding has multiple CWE IDs that map to different verdicts (e.g., one DYNAMICALLY_VERIFIABLE, one STATIC_ONLY), resolve conservatively — STATIC_ONLY wins. Current behavior depends on iteration order.

2. **Unmapped CWE warning:** When a CWE ID is not in the `_CWE_VERDICTS` lookup and falls through to the STATIC_ONLY default, emit a warning log so operators know the mapping table needs extending.

## Acceptance criteria

- [ ] Finding with CWE-89 (DV) + CWE-798 (STATIC_ONLY) → verdict is STATIC_ONLY
- [ ] Finding with only unmapped CWEs → STATIC_ONLY + warning logged with the unmapped CWE IDs
- [ ] Unit test: multi-CWE conflict resolution (mixed verdicts → STATIC_ONLY)
- [ ] Unit test: unmapped CWE emits warning (assert log output)

## Relevant modules

- `src/shieldclaw/triage/classifier.py`
- `src/shieldclaw/models.py`
