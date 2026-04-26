# CONTEXT: sandbox/

## Role in the System

The `sandbox/` package is the **Detonation Stage** of the Shield Claw pipeline. It manages
the full lifecycle of a compose-backed target application (start → wait-for-ready → detonate →
teardown) and executes the LLM-generated exploit payload inside a hardened ephemeral container.
It corresponds to the "Sandbox" stage in the README architecture diagram.

The single class `DockerOrchestrator` owns the entire lifecycle. Do NOT split these
responsibilities across multiple classes.

---

## Conventions Specific to This Area

1. **The attacker container security constraints are mandatory and non-negotiable.** Every
   `docker run` call for detonation MUST carry all of the following flags. Removing or weakening
   any of them is a security defect requiring a new ADR:

   | Flag | Value | Constraint |
   |------|-------|------------|
   | `--memory` | `256m` | 256 MB RAM hard cap |
   | `--cpus` | `0.5` | Half a CPU core |
   | `--pids-limit` | `100` | PID fork-bomb prevention |
   | `--user` | `1000:1000` | Non-root execution — never `root` or `0` |
   | `--read-only` | (flag) | Read-only root filesystem |
   | `--tmpfs` | `/tmp:rw,noexec,nosuid,size=32m` | 32 MB tmpfs; no exec bit |
   | `--network` | `{compose_project}_default` | Compose network only; no host network |
   | `--rm` | (flag) | Auto-removed on exit |

   **`--privileged` is NEVER used. `--cap-add` that elevates capabilities is NEVER used.**
   See ADR-004 for the full rationale.

2. **Default detonation timeout is 15 seconds** (the `timeout` parameter default on
   `DockerOrchestrator.detonate`). The CLI `--timeout` flag overrides this. Exit code `124`
   is returned when the subprocess timeout fires, following the POSIX `timeout(1)` convention.
   `_force_remove_container` always runs after a timeout to prevent orphaned containers.

3. **Teardown is always best-effort.** `teardown()` MUST NOT raise, even if `docker compose down`
   fails. Failures are logged at WARNING level. This is intentional: `Orchestrator.run()` calls
   `teardown()` in a `finally` block and must always produce a report.

4. **Label-based ownership and cleanup.** Every compose service and every attacker container
   carries the label `shieldclaw.run={result_id}`. This label is the authoritative handle for
   cleanup. `teardown()` enumerates containers by label, not by name or image.

5. **Compose label override instead of `docker update --label-add`.** Labels are injected into
   compose services via a generated YAML override file (`_write_label_override`). This is
   required for Docker Desktop compatibility on Windows, which does not support
   `docker update --label-add`. Do not change this approach without confirming cross-platform
   compatibility.

6. **`noexec` on `/tmp` does not block `pip install --target`.** The bootstrap script installs
   `requests` and `urllib3` to `/tmp/pylib` via `pip install --target`. Python imports from
   `/tmp/pylib` do not require the exec bit on the directory itself. Direct shell script
   execution inside `/tmp` is blocked. See ADR-005.

7. **Feature module isolation.** Files in `sandbox/` may NOT import from `context/`,
   `intelligence/`, or `reporting/`. Only `shieldclaw.models` and `shieldclaw.exceptions` are
   permitted as internal `shieldclaw.*` imports.

---

## Patterns for Common Operations

1. **To change attacker container resource limits:**
   - Edit the `docker run` argument list in `DockerOrchestrator.detonate()` in
     `docker_orchestrator.py` (the `cmd` list built before `subprocess.run`)
   - Update the constraint table in Rule 1 above
   - If the change crosses a security boundary (e.g., removing `--read-only`, adding network
     access), it requires a new ADR entry

2. **To change the detonation timeout default:**
   - Update the `timeout: int = 15` parameter default in `DockerOrchestrator.detonate()`
   - The CLI's `--timeout` argument in `__main__.py` forwards this value; update its default
     and help text to match

3. **To support a non-Python exploit language:**
   - Change `_DETONATE_IMAGE` (currently `python:3.11-slim`) and `_DETONATE_BOOTSTRAP`
   - Update `prompts.py` in `intelligence/` to request the new language
   - This is a significant cross-cutting change — requires an ADR and a cross-model audit
     before merging

4. **To extend readiness probes beyond polling `docker compose ps`:**
   - Extend `_wait_for_compose_ready()` in `docker_orchestrator.py`
   - Keep the `_START_WAIT_SECONDS` (60 s default) polling loop as the final fallback

---

## Known Constraints

- **Stale container cleanup at startup:** `_cleanup_stale()` removes ALL containers carrying
  the `shieldclaw.run` label before each run. This handles orphans from crashed prior runs but
  will prematurely remove containers from any concurrent Shield Claw run on the same Docker daemon.
  Concurrent runs on the same machine are not supported in V1.

- **Compose project naming is deterministic:** `compose_project_name(result_id)` produces a
  20-character hex slug derived from `sha256(result_id)`. This is used as the Docker Compose
  project name and as the network name prefix (`{project}_default`). Two different `result_id`
  values produce different project names, preventing network collisions between sequential runs.

- **The bootstrap payload (`_DETONATE_BOOTSTRAP`) reads exploit code from stdin.** The
  `subprocess.run` call passes `payload.raw_code` as `input=`. Do not change to a file-based
  delivery mechanism without updating the Docker run flags (currently `--read-only` prevents
  writing exploit files to the container filesystem outside of `/tmp`).

- **Windows Docker Desktop requires Compose V2 (`docker compose`, not `docker-compose`).**
  All compose calls use `["docker", "compose", ...]` as the command prefix. Legacy
  `docker-compose` (V1) is not supported.
