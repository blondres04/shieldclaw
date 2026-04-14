# ADR-004: Docker Sandbox Strategy

## Status

Accepted (placeholder — formalize from Phase 6 §8)

## Context

Exploits must run isolated from the host while still reaching the target application on a Compose network.

## Decision

Use `docker compose` for the target stack and a separate ephemeral container for detonation, with resource limits, read-only root where practical, and labeled resources for teardown.

## Consequences

- Requires a local or CI Docker engine; behavior is validated by integration tests where Docker is available.
- Trust-boundary details (including outbound access from the attacker container) are refined in ADR-005.
