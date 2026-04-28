# ADR-004: Docker Sandbox Strategy

## Status

Accepted — 2026-04-28

## Context

Detonating an LLM-generated exploit requires:
1. A running replica of the vulnerable application (compose stack).
2. An isolated attacker container that can reach the replica over a private
   network but is otherwise hardened against host escape and lateral movement.

The attacker container runs untrusted, AI-generated Python code. The threat
model includes:
- Exfiltration via side channels.
- Container escape via kernel exploits.
- Resource exhaustion (CPU/memory/fork bombs).
- Persistent artefacts after the run.

## Decision

**Target application**: launched with `docker compose up`, using a label
override file (`shieldclaw.run=<result_id>`) to tag all containers for
deterministic teardown.

**Attacker container**: a short-lived `docker run --rm` container with the
following hardening flags applied unconditionally:

| Flag | Value | Rationale |
|------|-------|-----------|
| `--memory` | 256 m | Limits RAM; prevents OOM bomb |
| `--cpus` | 0.5 | Limits CPU; prevents exhaustion |
| `--pids-limit` | 100 | Prevents fork bomb |
| `--user` | 1000:1000 | Non-root; limits file-system writes |
| `--read-only` | — | Immutable root FS; writes fail unless tmpfs |
| `--tmpfs /tmp` | rw,noexec,nosuid,size=32m | Controlled scratch space |
| `--network` | compose project network | Reaches replica; isolated from host |

**Result-ID scoping**: cleanup (`_cleanup_stale`, `teardown`) filters by
`label=shieldclaw.run=<result_id>` to prevent concurrent runs interfering
(see ADR-002 for resumability context).

**Readiness probe**: `_wait_for_compose_ready` calls `docker inspect` per
service and waits for `Health.Status == healthy` (or `<no value>` — no
healthcheck declared). This replaces the string-match `docker compose ps`
approach shipped in v0.1.

## Consequences

**Positive**
- Hardening flags are enforced at the lowest possible level (Docker); they
  cannot be overridden by exploit code.
- Residual kernel-escape risk is documented rather than silently accepted.
- The result-ID scoping fix (Phase 0) enables safe concurrent usage.

**Negative**
- Requires a Docker daemon. No Podman or containerd support in v0.2.
- The `--read-only` + `--tmpfs` combination breaks some exploit patterns that
  write to non-`/tmp` locations. Documented as a known limitation.
- Kernel-level container escapes remain a residual risk regardless of the
  flags above.

## Alternatives Considered

- **Firecracker/gVisor microVMs**: Stronger isolation, but requires a Linux
  host with KVM. Out of scope for a CLI tool targeting developer workstations.
- **No network isolation**: Running the attacker on the host network.
  Rejected: attacker code could reach internal services.
- **Docker-in-Docker for the full stack**: Adds significant complexity and
  latency with no meaningful security improvement over the current model.
