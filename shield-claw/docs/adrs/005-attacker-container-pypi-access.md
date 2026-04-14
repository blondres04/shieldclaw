# ADR-005: PyPI Network Access from Attacker Container

## Context

The attacker container runs `python:3.11-slim`, which does not include the `requests` library. LLM-generated exploits typically use `requests` for HTTP-based attacks (SQLi, SSRF, command injection). During Task 10 integration, a runtime `pip install --target /tmp/pylib requests` was added to the detonation bootstrap.

This grants the attacker container outbound internet access to PyPI, which was not part of the original Phase 7 STRIDE analysis (Trust Boundary 3 assumed the attacker container only communicates with target services on the Docker network).

## Alternatives Considered

1. **Pre-built custom attacker image** with `requests` baked in. Eliminates runtime PyPI access. Requires maintaining a Docker image.
2. **Accept PyPI access and document the risk.** Simpler but expands the attack surface.
3. **Restrict the LLM to stdlib-only exploits** (urllib3, http.client). Reduces exploit quality significantly.

## Decision

Accept PyPI access for the MVP with documentation. The risk is that a malicious LLM-generated payload could `pip install` a package that exfiltrates data. This is mitigated by:

- The configurable execution timeout (CLI default 15 seconds, max 120) limits exfiltration volume
- The `--memory=256m` and `--pids-limit=100` constraints limit what can be installed
- The user is explicitly running untrusted AI-generated code (the core feature)

A future improvement (V2) should pre-build a custom attacker image to eliminate this trust boundary entirely.

## Consequences

- The attacker container has outbound internet access during detonation
- This is a known, documented, accepted risk for the MVP
- The README Security Considerations section must mention this
- Revisit this decision if Shield Claw is ever used in air-gapped environments
