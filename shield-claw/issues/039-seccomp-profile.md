# Issue #39: Add default seccomp profile to attacker container

- **Tier:** 1 (Security)
- **Blocked by:** None
- **afk:** true

## What to build

Apply Docker's default seccomp profile to the attacker container launched during detonation. This restricts dangerous syscalls (e.g., `mount`, `reboot`, `kexec_load`) as a defense-in-depth layer alongside the existing read-only FS, non-root UID, and resource limits.

End-to-end: add `--security-opt seccomp=unconfined` removal (or explicit `--security-opt seccomp=default`) to the `docker run` command in `sandbox/docker_orchestrator.py`, then write an integration test proving the profile is active.

## Acceptance criteria

- [ ] Attacker container runs with Docker's default seccomp profile applied
- [ ] `docker inspect` on the attacker container shows seccomp profile is not `unconfined`
- [ ] Existing exploit detonation flow still works (seccomp does not block Python/bash execution)
- [ ] Integration test: verify seccomp is active via `docker inspect` on a test container

## Relevant modules

- `src/shieldclaw/sandbox/docker_orchestrator.py`
