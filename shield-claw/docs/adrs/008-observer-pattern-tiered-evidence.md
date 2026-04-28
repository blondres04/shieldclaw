# ADR-008: Observer Pattern and Tiered Evidence Model

## Status

Accepted — 2026-04-28

## Context

When the attacker container exits, the exit code alone is insufficient to
classify the result. A well-written exploit script exits 0 only on confirmed
exploitation — but a poorly written script can exit 0 falsely, or the
compose stack might not have fully started. We need corroborating signals.

Additionally, the `DockerOrchestrator.detonate()` signature should not need
to know about every observation strategy. New signal collectors should be
addable without modifying the core sandbox code.

## Decision

Introduce the `DetonationObserver` ABC (defined in `models.py` to avoid
cross-feature imports) with two methods:
- `before_detonate(target_container_id, network_name) -> Any`
- `after_detonate(before_state, exit_code, stdout, stderr, target_container_id) -> ObserverEvidence`

`DockerOrchestrator.detonate()` accepts `observers: Sequence[DetonationObserver]`
and calls them before and after the run. The return type is `DetonationOutcome`
(exit code + evidence tuple).

**Evidence tiers (v0.2 implements Tiers 1–2):**

| Tier | Observer | Signal |
|------|----------|--------|
| 1 | `ExitCodeObserver` | exit code, stdout, stderr |
| 2 | `DockerDiffObserver` | filesystem changes on the target container |
| 2 | `TargetLogObserver` | target container logs since detonation start |
| 3 | Network capture (planned v0.3) | TCP flows proving data exfiltration |
| 4 | Application-layer assertion (planned v0.3) | Database row mutation confirmed |

The `verdict/synthesizer.py` applies deterministic rules:
- `exit_code == 0` AND Tier-2 corroboration → `TRUE_POSITIVE (0.95)`
- `exit_code == 0`, no corroboration → `INCONCLUSIVE (0.50)` (spoofed stdout)
- `exit_code == 124` → `FALSE_POSITIVE (0.85)` (timeout)
- `exit_code != 0` → `FALSE_POSITIVE (0.80)`

## Consequences

**Positive**
- The `INCONCLUSIVE` case catches scripts that exit 0 without actually
  exploiting anything — a common failure mode for weaker LLM-generated code.
- Observers are pluggable; adding network capture requires only a new class
  in `observer/`.
- Evidence is persisted to SQLite and available for post-run analysis.

**Negative**
- Tier-2 observers require `docker diff` and `docker logs` access to the
  target container, which requires `docker compose ps` to resolve the
  container ID (heuristic: first non-database service). This heuristic can
  fail for unusual compose topologies.
- Tiers 3 and 4 are not shipped in v0.2. The `INCONCLUSIVE` verdict therefore
  under-reports true positives when the exploit produces no filesystem side-effect
  (e.g., timing-based SQLi, response oracle attacks).

## Alternatives Considered

- **Single observer**: Always run all three signals. Rejected because
  `docker diff` and `docker logs` add latency even when exit code is
  definitive.
- **Callbacks on `DockerOrchestrator`**: Inline the observation logic in the
  sandbox class. Rejected: violates ADR-001 (sandbox importing observer).
- **Return only exit code**: Matches v0.1 behaviour. Rejected because of the
  spoofed-stdout false-positive class.
