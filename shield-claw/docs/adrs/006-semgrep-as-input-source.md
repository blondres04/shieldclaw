# ADR-006: Semgrep JSON as the Primary Input Source

## Status

Accepted — 2026-04-28

## Context

ShieldClaw v0.1 operated in "diff mode": it read `git diff HEAD~1`, sent
the diff to an LLM, and asked the model to generate an exploit for whatever
vulnerability the diff introduced. This was simple but had three problems:

1. **False-positive rate**: the LLM had to both identify the vulnerability
   _and_ generate the exploit from unstructured diff text — two failure
   modes compounded.
2. **Non-determinism**: running the same diff twice could produce different
   exploits because the vulnerability classification was implicit in the
   prompt.
3. **Scalability**: processing a large diff (many files) gave no way to
   prioritise which change to test first.

The SAST-verifier pivot (v0.2) changes the input source to Semgrep JSON.

## Decision

Accept Semgrep `--json` output as the primary input. The `ingest/` package
parses it into `Finding` frozen dataclasses with deterministic `uuid5` IDs.
The `triage/` package classifies each finding by CWE before the LLM is
involved.

The diff mode is preserved as `_run_legacy()` inside the orchestrator for
users who do not have Semgrep installed, but it is no longer the default
or recommended path.

## Consequences

**Positive**
- **Separation of concerns**: the SAST tool identifies the vulnerability;
  ShieldClaw verifies it. Neither tool tries to do the other's job.
- **Determinism**: a finding's `finding_id` is `uuid5(NAMESPACE_URL, rule:path:line:line)`,
  so re-ingesting the same report produces identical IDs — enabling
  deduplication and resumable runs.
- **Prioritisation**: the triage classifier assigns `DYNAMICALLY_VERIFIABLE`,
  `STATIC_ONLY`, or `OUT_OF_SCOPE` before any LLM call, preventing wasted
  tokens on false alarms (e.g., hardcoded credentials, Docker rules).

**Negative**
- Semgrep must be installed and run separately before ShieldClaw. This
  increases the setup burden for new users.
- ShieldClaw is now coupled to Semgrep's JSON schema. CodeQL, Snyk, and
  Checkmarx integration is v0.3 work.
- Users whose repositories have no Semgrep-compatible language support must
  still use diff mode.

## Alternatives Considered

- **CodeQL SARIF**: Industry-standard format. Accepted as v0.3 work; SARIF
  parser can be added to `ingest/` without changing any other package.
- **Static analysis built into ShieldClaw**: Run Semgrep internally and
  pass results directly. Rejected: couples ShieldClaw to specific tool
  versions; operators should control their SAST configuration.
- **Keep diff mode as primary**: Rejected because of the false-positive rate
  issue above.
