# ADR-005: Attacker Container PyPI Access

## Status

Superseded by the pre-built attacker image — 2026-04-28

The original decision (accept PyPI access for MVP) has been superseded.
`docker/attacker.Dockerfile` now bakes `requests` and `urllib3` at build time.
Detonation no longer requires outbound internet access.

The original rationale is preserved below for historical context.

---

## Original Context (v0.1 decision)

The attacker container runs `python:3.11-slim`, which does not include
`requests`. LLM-generated exploits typically need `requests` for HTTP attacks.
A runtime `pip install --target /tmp/pylib requests urllib3` was added to
the detonation bootstrap.

This grants the attacker container outbound internet access to PyPI —
outside the original Trust Boundary 3 analysis that assumed the attacker
only communicates with compose-internal services.

## v0.2 Decision (2026-04-28)

Implement a pre-built attacker image (`docker/attacker.Dockerfile`):

```dockerfile
FROM python:3.11-slim
RUN pip install --no-cache-dir "requests==2.32.*" "urllib3==2.2.*" \
    && useradd -m -u 1000 attacker
USER 1000:1000
WORKDIR /tmp
ENTRYPOINT ["python", "-c", "import sys; exec(compile(sys.stdin.read(), '<exploit>', 'exec'))"]
```

The `ENTRYPOINT` reads exploit code from stdin and `exec`-compiles it —
exactly matching the existing `subprocess.run(input=payload.raw_code)`
interface. No bootstrap script or runtime pip install is needed.

The image tag is `ghcr.io/blondres04/shieldclaw-attacker:0.1` by default
and is overridable via `SHIELDCLAW_ATTACKER_IMAGE`.

`DockerOrchestrator.start_sandbox()` probes the image with
`docker image inspect` before starting the compose stack, and raises
`SandboxStartError` with build instructions if the image is missing.

## Consequences

**Positive**
- Zero outbound internet required at detonation time.
- The attacker container network can now be made `internal: true` in future
  phases without breaking exploit functionality.
- Detonation is faster (no pip install) and deterministic (pinned deps).

**Negative**
- The pre-built image must be rebuilt when `requests` or `urllib3` receive
  a security update. This is standard container maintenance.
- New contributors must run `scripts/build_attacker_image.sh` once before
  integration tests pass — `verify_harness.sh` automates this.

## Alternatives Considered

See original ADR-005 for the three alternatives evaluated at v0.1.
The pre-built image was Alternative 1 in that analysis and is now the
implemented decision.
