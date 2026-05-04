# Issue #38: Block attacker container egress with internal compose network

- **Tier:** 1 (Security)
- **Blocked by:** None
- **afk:** true

## What to build

Switch the compose network used for detonation from the default bridge to a custom network with `internal: true`. This prevents the attacker container from making outbound internet requests while still allowing it to reach target services within the compose stack.

End-to-end: modify `sandbox/docker_orchestrator.py` to create/use an internal network, write an integration test that proves the attacker can reach the target service by hostname but cannot reach an external host (e.g., `ping 8.8.8.8` fails).

## Acceptance criteria

- [ ] Compose project creates a network with `internal: true`
- [ ] Attacker container is joined to the internal network
- [ ] Attacker can still resolve and reach target compose services by service name
- [ ] Attacker cannot route to any address outside the compose network
- [ ] Integration test: attacker container pings external IP → failure; curls target service → success

## Relevant modules

- `src/shieldclaw/sandbox/docker_orchestrator.py`
