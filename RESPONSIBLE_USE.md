# Responsible Use Policy

ShieldClaw is defensive security tooling for evidence-backed validation of
Semgrep SQL injection findings. The narrowed MVP validates `CWE-89` SQLi
findings against Docker Compose applications that you own or are explicitly
authorized to test.

Because ShieldClaw can generate and detonate real proof-of-concept exploit code,
its use carries risk even inside a constrained attacker container.

By using, cloning, or modifying this software, you agree to the following
conditions.

## 1. Authorization Requirement

You may only run ShieldClaw against repositories, codebases, networks, and
infrastructure that you own or have documented written permission to test.
Unauthorized scanning or exploitation of third-party systems is illegal under
the Computer Fraud and Abuse Act (CFAA) and equivalent laws in many
jurisdictions.

## 2. Prohibited Uses

- Do not use ShieldClaw to scan, exploit, or attack public open-source
  repositories without the maintainers' documented consent.
- Do not use ShieldClaw to generate exploits for attacking production systems,
  exfiltrating data, or causing harm.
- Do not use non-`CWE-89` experiments to claim broader ShieldClaw validation
  support than the project has actually proven.
- Do not redistribute modified versions with the responsible-use constraints or
  ethical boundaries removed.

## 3. MVP Scope Boundary

The default MVP validation path is SQLi-only:

- `CWE-89` findings may be scored, approved, PoC-generated, detonated, and
  reported as deterministic validation results.
- Non-`CWE-89` findings remain visible but are not scored, approved,
  PoC-generated, or detonated by default.
- `CWE-78`, `CWE-434`, patching, web UI workflows, and SARIF release gating are
  explicitly deferred.

## 4. Sandboxing Constraints

ShieldClaw starts a Docker Compose target and detonates approved PoCs in a
constrained attacker container with resource limits, read-only filesystem,
non-root execution, default seccomp, and internal networking. These controls
reduce risk; they do not make Docker a perfect containment boundary.

Do not run ShieldClaw on a host containing sensitive production workloads. Do
not run it against untrusted repositories or compose files unless you are
prepared to treat them as potentially malicious.

## 5. LLM Provider Considerations

LLM scoring and PoC generation may send finding context, source excerpts, and
compose metadata to the configured provider. Use a local provider when that data
must remain on your machine, or review your hosted provider's data handling
terms before use.

## 6. No Warranty

This software is provided "as is" for educational and defensive research
purposes only. The creators and contributors accept no responsibility or
liability for damage, data loss, or legal consequences resulting from use or
misuse.

## 7. Reporting Misuse

If you observe ShieldClaw being used maliciously or in violation of this policy,
please report it privately to the repository owner.
