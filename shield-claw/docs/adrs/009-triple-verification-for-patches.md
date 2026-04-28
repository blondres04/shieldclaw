# ADR-009: Triple Verification Protocol for Automated Patches

## Status

Accepted (implementation pending — v0.3) — 2026-04-28

## Context

The v0.3 patch-and-verify loop will trigger when a `TRUE_POSITIVE` verdict is
confirmed, ShieldClaw generates a fix, applies it to an isolated worktree, and
re-detonates to confirm the exploit no longer succeeds.

A single re-detonation is insufficient because:
- The LLM may generate a fix that masks the symptom rather than fixing the
  root cause (e.g., catching the exception rather than parameterising the query).
- Exit-code 1 on re-detonation could be a transient networking failure, not
  a confirmed fix.

## Decision

Require three consecutive failed detonations (exit code ≠ 0) of the same
exploit against the patched worktree before declaring the fix verified.
The iteration cap is three patch generations per finding.

**Verification protocol:**
1. Apply patch to isolated git worktree (see ADR-010).
2. Rebuild the compose stack from the patched source.
3. Detonate the original exploit (unchanged).
4. If exit code ≠ 0: increment consecutive-failure counter.
5. If counter reaches 3: verdict → `PATCH_VERIFIED`.
6. If exit code == 0: generate a new patch variant and restart from step 1.
7. If iteration cap (3 patches) reached without verification: verdict →
   `PATCH_FAILED`; alert operator.

The same observer evidence is collected on each re-detonation. A fix is
only `PATCH_VERIFIED` if all three detonations agree.

## Consequences

**Positive**
- Three-run consensus dramatically reduces the false-`PATCH_VERIFIED` rate
  from transient failures.
- The iteration cap prevents infinite patch loops that waste LLM tokens.

**Negative**
- The triple verification protocol requires at minimum 3× the detonation
  time per confirmed finding. For a 60-second detonation: up to 3 minutes
  per finding.
- The observer setup cost (compose up, compose down) is paid six times in
  the worst case. Optimisations (persistent sandbox per finding) are v0.4 work.

## Alternatives Considered

- **Single failed detonation**: Insufficient consensus. Rejected.
- **Five consecutive failures**: Slower convergence for legitimate transient
  failures. Rejected as premature.
- **Semantic diff of the patch**: Verify the fix is semantically correct
  (e.g., parameterised query present). Too complex to implement generically.
  Deferred to v0.4.
