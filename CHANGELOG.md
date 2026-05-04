# Changelog

All notable changes to ShieldClaw are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Added

- Inline `--interactive` approval mode for per-finding review during `shieldclaw run`.
- Pluggable report output formats: `json`, `sarif`, and `markdown`.
- CWE-specific corroboration patterns for `TargetLogObserver`.
- Externalized CWE verdict mapping config for easier classifier maintenance.

### Changed

- `--timeout` is now threaded through to live detonation calls.
- Conservative multi-CWE conflict resolution now warns on unmapped CWEs.
- Interrupted detonations resume as `INCONCLUSIVE` instead of silently continuing.
- Observer failures are surfaced in report output as per-finding warnings.
- LLM refusals retry once before a finding is marked `REFUSED`.
- PoC `target_dns` values are validated against compose service names before detonation.

### Security

- Attacker egress is blocked by using an internal compose network.
- Attacker containers now run with a default seccomp profile.

---

## [0.2.0] - 2026-04-28

### Added

- Sandbox isolation and healthcheck readiness checks.
- Semgrep JSON ingest and deterministic CWE-based triage.
- LLM exploitability scoring with resumable SQLite persistence.
- Human-in-the-loop approval, PoC generation, observer evidence, and verdict synthesis.
- OpenAI provider support and a pre-built attacker Docker image.
- ADR ratification, onboarding docs, and CI workflow refinement.

### Changed

- Docker detonation returns structured outcome data instead of a raw exit code.
- The orchestrator now supports both the legacy diff flow and the newer SAST flow.
- Branch protection on `main` requires linear history and gated quality checks.

### Security

- Detonation no longer requires outbound package installs at runtime.
- Concurrent run cleanup is scoped to the active result ID.
- Sandbox hardening is documented and enforced through container runtime flags.

---

## [0.1.0]

### Added

- Initial CLI-driven red-teaming workflow over a Docker sandbox.
- Context aggregation, LLM provider abstraction, and JSON reporting.
- Shared immutable models, architecture guardrails, and verification scripts.
- Bundled vulnerable Flask lab and offline evaluation harness.
