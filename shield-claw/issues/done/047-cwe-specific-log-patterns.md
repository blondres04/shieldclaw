# Issue #47: Add CWE-specific log corroboration patterns to TargetLogObserver

- **Tier:** 3 (Capability)
- **Blocked by:** None
- **afk:** true

## What to build

Replace the generic keyword matching in `observer/target_logs.py` (which matches `error`, `exception`, `traceback`, `500`) with CWE-specific log patterns that reduce false corroboration. For example:

- CWE-89 (SQL injection) → look for DB error patterns (`syntax error`, `ORA-`, `mysql`, `psycopg`)
- CWE-22 (path traversal) → look for `ENOENT`, `403`, `FileNotFoundError`, `Permission denied`
- CWE-78 (command injection) → look for `sh:`, `command not found`, unexpected process output
- CWE-79 (XSS) → look for reflected content in response (may need different observer tier)

End-to-end: pass the finding's CWE into the `TargetLogObserver` at construction, define per-CWE pattern sets, fall back to the current generic patterns for CWEs without specific patterns.

## Acceptance criteria

- [ ] `TargetLogObserver` accepts a CWE parameter at construction
- [ ] Per-CWE pattern sets defined for at least CWE-89, CWE-22, CWE-78
- [ ] CWEs without specific patterns fall back to current generic keywords
- [ ] Unit test: SQL injection CWE + DB error in logs → corroboration detected
- [ ] Unit test: SQL injection CWE + generic "error" in logs (unrelated) → no corroboration
- [ ] Unit test: unknown CWE → falls back to generic patterns

## Relevant modules

- `src/shieldclaw/observer/target_logs.py`
- `src/shieldclaw/models.py`
