# ADR-010: Ephemeral Git Worktree Isolation for Patch Testing

## Status

Accepted (implementation pending — Phase 5) — 2026-04-28

## Context

Phase 5's patch-and-verify loop must apply a generated fix to the target
repository and rebuild the compose stack to test whether the exploit still
succeeds. The patch must not:
- Modify the user's working tree (they may have uncommitted changes).
- Modify the user's current branch (the fix is experimental).
- Leave artefacts if the ShieldClaw process is killed mid-run.

## Decision

Use `git worktree add --detach <temp_dir>` to create an ephemeral, detached
HEAD worktree pointing to the same commit as the main tree. The patch is
applied to this worktree only. The compose stack is rebuilt from the worktree
copy.

After verification (success or failure), `git worktree remove --force <temp_dir>`
cleans up. The main working tree is never touched.

The worktree lives in `<target_dir>/.shieldclaw/worktrees/<finding_id>/`.
Because `.shieldclaw/` is gitignored (see Phase 2 gitignore update),
the worktrees are never staged or committed by accident.

## Consequences

**Positive**
- The user's working tree and current branch are completely untouched.
- If ShieldClaw is killed, the worktree is an orphaned directory inside
  `.shieldclaw/` — not a corrupted git state. `git worktree prune` reclaims it.
- Multiple concurrent patch verifications for different findings are possible
  (each gets a unique worktree path derived from `finding_id`).

**Negative**
- Requires git ≥ 2.5. The orchestrator checks this at startup.
- Large repositories pay a file-copy cost for the worktree. For most
  application repositories this is under a second; for monorepos it may be
  noticeable.
- The worktree rebuild still runs `docker compose build`, which is the
  dominant latency cost.

## Alternatives Considered

- **Apply patch to the main working tree, stash afterward**: Simple but
  fragile — a crash between patch and stash leaves the user's tree dirty.
  Rejected.
- **Docker volume overlay (copy-on-write)**: Correct but requires
  Docker overlay2 driver support and privileged containers. Rejected as
  over-engineered for the use case.
- **Copy the entire repository to a temp directory**: Works but slow for
  large repos and wastes disk space. Rejected in favour of git's native
  worktree mechanism.
