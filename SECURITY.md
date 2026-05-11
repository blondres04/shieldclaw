# Security Policy

## Supported Versions

ShieldClaw is in pre-1.0 MVP development. Only the `main` branch receives
security updates.

## Current Security Scope

The default MVP path validates Semgrep `CWE-89` SQL injection findings against
owned Docker Compose applications. Other vulnerability classes are visible in
triage/reporting but are not default MVP-supported validation targets.

## Reporting a Vulnerability

If you discover a vulnerability in ShieldClaw itself, such as a sandbox escape,
unsafe detonation behavior, data exposure in reports, or approval bypass, do not
open a public GitHub issue.

Please report it privately to the repository maintainer. You will receive an
acknowledgment within 48 hours when possible, and we will coordinate a fix and
disclosure timeline before making any public announcement.

## Known Security Considerations

1. Docker is a containment boundary, not a guarantee. Run ShieldClaw only on
   development or lab hosts that do not contain sensitive production workloads.
2. The target Docker Compose stack runs on the local Docker daemon. Treat target
   repositories and compose files as code you are authorizing to run.
3. Approved PoCs are real exploit code. The approval gate exists to prevent
   accidental detonation; do not bypass it outside controlled local validation.
4. `SHIELDCLAW_AUTO_APPROVE=1` is an explicit risk acceptance path for CI or
   demos, not the default operator workflow.
5. Hosted LLM providers may receive source excerpts and finding context. Use a
   local provider when that data must stay local.
6. SARIF export is secondary in the SQLi MVP and is not a release gate for the
   current validation claim.

## Out-of-Scope Security Claims

ShieldClaw does not currently claim validated MVP support for `CWE-78`,
`CWE-434`, web UI approval, automated patching, or broad vulnerability-class
coverage.
