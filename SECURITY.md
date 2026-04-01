# Security Policy

## Supported Versions
Currently, only the `main` branch is receiving security updates. Shield Claw is in **V0 Proof of Concept** stage.

## Reporting a Vulnerability
If you discover a vulnerability in the Shield Claw architecture—such as a sandbox escape, a telemetry injection flaw, or a JWT authentication bypass—**do not open a public GitHub issue.**

Please report it privately by emailing the repository maintainer. You will receive an acknowledgment within 48 hours. We will coordinate a fix and disclosure timeline with you before making any public announcement.

## Known Security Considerations (V0 Architecture)
Shield Claw is actively working to harden its execution environment. Users should be aware of the following accepted architectural risks in the V0 release:

1. **Docker Socket Mounting:** The Sandbox Orchestrator mounts the host's Docker socket (`/var/run/docker.sock`) to spin up the target containers. This means the target containers run as siblings on the host daemon, not as true nested Docker-in-Docker. This is a known privilege escalation surface. Do not run Shield Claw on a host containing sensitive production workloads.
2. **Outbound Network Access:** Sandbox containers currently require outbound network access to perform `git clone` operations on the target repository. While ephemeral, they are not completely air-gapped. 
3. **Default Credentials:** The Docker Compose stack ships with default JWT credentials (`auditor` / `secure2026`). These must be rotated if deployed outside of a local, air-gapped testing environment.
