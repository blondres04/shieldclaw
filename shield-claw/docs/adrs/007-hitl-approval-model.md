# ADR-007: Human-in-the-Loop Approval Model

## Status

Accepted — 2026-04-28

## Context

Once a finding is scored as `DYNAMICALLY_VERIFIABLE` and the LLM assigns a
high exploitability score, ShieldClaw must decide: should it proceed to PoC
generation and live detonation automatically, or pause for human review?

The stakes are non-trivial. Detonation sends HTTP requests crafted to exploit
a live application. Even with a sandbox, a mistaken approval against the
wrong target could:
- Produce noisy access logs.
- Trigger WAF/IDS alerts.
- In the SSRF case, reach internal services the operator did not intend to probe.

## Decision

HITL approval is **mandatory by default**, per-finding (not per-scan).

The default workflow:
1. Pipeline runs to `SCORED` state and halts.
2. Operator reviews each finding via `shieldclaw approve <scan_id> <finding_id>`.
3. Operator resumes via `shieldclaw run --resume <scan_id>`.

Automation override: set `SHIELDCLAW_AUTO_APPROVE=1` to auto-approve all
scored findings in one pipeline run. This is explicitly logged as `WARN` and
is designed for CI/CD contexts where the operator accepts the risk.

Approval is **per-finding** rather than per-scan because:
- A scan may contain both high-confidence exploitable findings and low-confidence
  informational ones. Per-scan approval forces the operator to accept all or
  none.
- The approval record includes the finding details, score, reasoning, and source
  excerpt, enabling informed decisions without context switching.

Approval decisions are persisted in the `approvals` SQLite table with
`decided_by` (username), `decided_at`, `note`, and `auto` (boolean flag).

## Consequences

**Positive**
- Operators cannot accidentally fire exploits at production without an
  explicit decision for each target.
- The approval trail is a complete audit log.
- REJECTED findings are terminal-skipped; the operator can revisit them by
  resuming the scan.

**Negative**
- In interactive mode the pipeline requires human intervention between scoring
  and detonation, making fully automated pipelines impossible without
  `SHIELDCLAW_AUTO_APPROVE=1`.
- The CLI-based approval UX is minimal. A web UI (or Slack/GitHub comment
  approval) is deferred to v0.3.

## Alternatives Considered

- **Per-scan approval**: One decision for all findings. Rejected because it
  conflates high- and low-confidence findings.
- **Threshold-based auto-approval** (score ≥ 0.8): Operator sets a threshold;
  findings above it auto-detonate. Rejected in v0.2 because the scoring model
  calibration is not yet validated. Deferred to v0.3 with a configurable
  threshold.
- **Web UI / API**: Correct long-term direction. Out of scope for v0.2 CLI tool.
