# PRD: SAST Pipeline v0.2 Stabilization

> Serialization of shared design alignment reached 2026-05-02.
> This is not a proposal — these decisions are made.
>
> 2026-05-11 scope note: the current MVP validation claim is narrowed to
> Semgrep `CWE-89` SQL injection only. Other CWEs may remain visible through
> triage/reporting or operator experiments, but they are not default
> MVP-supported validation targets.

---

## 1. Problem Statement

ShieldClaw is a vulnerability verification pipeline that takes static analysis
findings (Semgrep) and, for the current MVP, validates `CWE-89` SQL injection
findings by generating and detonating approved PoC code in isolated containers.

The v0.2 SAST pipeline is architecturally complete — all 7 stages exist and connect — but has confirmed gaps in isolation, resumability, observability, and configurability that must be addressed before the pipeline can produce trustworthy results at scale.

The legacy v0.1 diff-based pipeline is temporary scaffolding and will be retired once v0.2 is stable. No further investment in the legacy path.

---

## 2. Solution Overview

Address 13 confirmed gaps organized into three tiers:

**Tier 1 — Security (must-fix before any real-target use):**
- Block outbound internet from attacker containers
- Add seccomp profile to attacker containers
- Validate LLM-generated `target_dns` against compose service names

**Tier 2 — Correctness (must-fix for trustworthy results):**
- Mark interrupted detonations as INCONCLUSIVE on resume (no silent re-detonation)
- Wire `--timeout` CLI flag to `detonate()` (currently ignored)
- Surface observer failures in report output
- Enforce conservative multi-CWE conflict resolution (STATIC_ONLY wins)
- Warn on unmapped CWEs (don't silently drop to STATIC_ONLY)
- Retry once on LLM refusal before marking REFUSED

**Tier 3 — Capability (post-stabilization):**
- Externalize CWE verdict map to config file
- CWE-specific log corroboration patterns
- In-process interactive HITL approval mode
- Pluggable report formats (JSON + SARIF + markdown)
- Agentic context enrichment (LLM tool-call for more source context)

---

## 3. User Stories

**Operator** = security engineer running ShieldClaw against a target application.

| # | As an... | I want to... | So that... |
|---|----------|-------------|------------|
| 1 | Operator | Run ShieldClaw against a Semgrep report and get a verdict per finding | I know which findings are real vulnerabilities vs. noise |
| 2 | Operator | Trust that exploit code cannot phone home or escape the sandbox | I can run ShieldClaw against production-representative targets without risk |
| 3 | Operator | Resume an interrupted scan without re-detonating completed findings | Interrupted runs don't produce inconsistent results or side effects |
| 4 | Operator | See which observers failed in the report | I know when a verdict was reached with degraded evidence |
| 5 | Operator | Approve findings interactively in a terminal session | I don't need to run a separate CLI command between pipeline stages |
| 6 | Operator | Control detonation timeout via `--timeout` | I can adjust for slow-starting target services |
| 7 | Operator | Extend the CWE-to-verdict mapping without modifying code | I can add new CWEs as my Semgrep rules evolve |
| 8 | Consumer | Import ShieldClaw results into GitHub Code Scanning (SARIF) | Verified findings appear in my existing security workflow |

---

## 4. Pipeline Architecture

```
Semgrep JSON ──> INGEST ──> TRIAGE ──> SCORE ──> APPROVE ──> POC GEN ──> DETONATE ──> VERDICT
                  (1)        (2)       (3)       (4)         (5)         (6)          (7)
```

All inter-stage data is persisted to SQLite. Each finding has a state that
enables resumability. Current SQLi MVP states include `INGESTED`, `TRIAGED`,
`DEFERRED`, `AWAITING_APPROVAL`, `APPROVED`, `REJECTED`, `POC_GENERATED`,
`VERDICTED`, and `REFUSED`. Legacy `SCORED` rows remain compatible for approval
and resume, but new supported SQLi findings should rest at `AWAITING_APPROVAL`
after LLM scoring completes.

### Stage 1: Ingest
- **Module:** `ingest/semgrep.py`
- **Input:** Semgrep JSON file path
- **Output:** `List[Finding]` written to SQLite
- **Interface:** `parse_semgrep_json(path) → List[Finding]`
- **Notes:** Extracts CWE IDs from `metadata.cwe`, normalizes severity, generates UUID per finding. No source excerpt is stored at ingest time — the `Finding` dataclass and the SQLite schema have no excerpt field. The excerpt is reconstructed on-the-fly from disk at scoring and PoC generation time via `_extract_source_lines()` (orchestrator.py) using the finding's `path`, `start_line`, and `end_line`. Resumed scans therefore read the current file on disk, not the file as it was when Semgrep ran.

### Stage 2: Triage
- **Module:** `triage/classifier.py`
- **Input:** `Finding`
- **Output:** `TriagedFinding(finding, verdict: TriageVerdict, reason: str)`
- **Interface:** `classify(finding) → TriagedFinding`
- **Verdicts:** `DYNAMICALLY_VERIFIABLE` | `STATIC_ONLY` | `OUT_OF_SCOPE`
- **Rules (pure, no LLM):**
  - Prefix filter: dockerfile/terraform/kubernetes/secrets/license rules → OUT_OF_SCOPE
  - INFO severity + no CWE → OUT_OF_SCOPE
  - CWE lookup in `_CWE_VERDICTS` dict → DV or STATIC_ONLY
  - Unmapped CWE fallback → STATIC_ONLY
- **Decision:** Multi-CWE conflict → STATIC_ONLY wins (conservative). Unmapped CWEs emit warning.

### Stage 3: Score
- **Module:** `scoring/exploitability.py`
- **Input:** `Finding` + `source_excerpt` + `compose_yaml` (only DYNAMICALLY_VERIFIABLE findings)
- **Output:** `ExploitabilityScore(score: float 0-1, attack_surface: str, prerequisites: List[str])`
- **Interface:** `scorer.score(finding, excerpt, compose_yaml) → ExploitabilityScore`
- **Decision:** Score is stored in SQLite but does NOT influence the final verdict. Score-to-verdict modulation is deferred pending empirical accuracy data.

### Stage 4: Approve
- **Module:** `approval/gate.py`
- **Input:** supported SQLi `Finding` in `AWAITING_APPROVAL` state, plus legacy
  `SCORED` compatibility rows
- **Output:** Finding state → APPROVED
- **Modes:**
  - `SHIELDCLAW_AUTO_APPROVE=1`: auto-approve all approval-ready findings
  - Async: orchestrator stops with supported SQLi findings in `AWAITING_APPROVAL`
  - Interactive: pipeline blocks on stdin prompt during `shieldclaw run --interactive`
- **Decision:** Both async and interactive modes are implemented for the CLI MVP.

### Stage 5: PoC Generate
- **Module:** `intelligence/poc_generator.py` + `intelligence/parser.py`
- **Input:** `Finding` + `source_excerpt` + `compose_yaml`
- **Output:** `ExploitPayload(raw_code, target_dns, execution_command, language)`
- **Interface:** `poc_gen.generate(finding, excerpt, compose_yaml) → ExploitPayload`
- **Decision:** `target_dns` must be validated against compose service names before detonation. On LLM refusal, retry once with rephrased prompt; if second attempt fails, mark finding as REFUSED.
- **Future:** Agentic context enrichment — LLM tool-call to request more source context.

### Stage 6: Detonate
- **Module:** `sandbox/docker_orchestrator.py`
- **Input:** `ExploitPayload` + target compose stack (already running)
- **Output:** `List[ObserverEvidence]`
- **Mechanism:**
  - Compose project scoped by `sha256(result_id)[:20]`
  - Attacker container: `--rm`, `--read-only`, `--user=1000:1000`, `--memory=256m`, `--cpus=0.5`, `--pids-limit=100`, `--tmpfs /tmp:rw,noexec,nosuid,size=32m`
  - Exploit piped via stdin; timeout controlled by `--timeout` flag
  - Observers: ExitCode (Tier-1), DockerDiff (Tier-2), TargetLogs (Tier-2)
- **Decisions:**
  - Network must use `internal: true` to block egress
  - Add Docker default seccomp profile
  - Observer failures surfaced in report (not silent)
  - Interrupted detonations → INCONCLUSIVE on resume (no re-run)

### Stage 7: Verdict
- **Module:** `verdict/synthesizer.py`
- **Input:** `List[ObserverEvidence]`
- **Output:** `Verdict: TRUE_POSITIVE (0.95) | FALSE_POSITIVE | INCONCLUSIVE`
- **Interface:** `synthesize(evidence_list) → Verdict`
- **Rules (first-match-wins, deterministic):**
  - exit_code=0 + Tier-2 corroboration → TRUE_POSITIVE
  - exit_code != 0 → FALSE_POSITIVE
  - otherwise → INCONCLUSIVE
- **Decision:** INCONCLUSIVE always means INCONCLUSIVE — LLM score does not tip it. CWE-specific log patterns replace generic keyword matching (future).

---

## 5. Module Map

### Deep (substantial logic, complex internals, simple interface)

| Module | LOC | Role | Status |
|--------|-----|------|--------|
| `orchestrator.py` | ~578 | 7-stage state machine, resumability | Stable but needs resume fix (Q18) |
| `sandbox/docker_orchestrator.py` | ~683 | Docker lifecycle, isolation, detonation | Needs security hardening (Q12, Q15) |
| `persistence/store.py` | ~450 | SQLite schema, scan/finding lifecycle | Stable. Test WAL under concurrency |
| `models.py` | ~340 | All frozen dataclasses, ABCs | Needs REFUSED state added |
| `ingest/semgrep.py` | ~223 | JSON parsing, CWE extraction | Stable |
| `intelligence/parser.py` | ~171 | Refusal detection, JSON validation | Needs retry-on-refusal logic |

### Medium (utility logic, will deepen)

| Module | LOC | Role | Status |
|--------|-----|------|--------|
| `verdict/synthesizer.py` | ~156 | Evidence → verdict rules | Needs CWE-specific patterns, observer_warnings |
| `triage/classifier.py` | ~125 | CWE → verdict mapping | Needs config externalization, multi-CWE fix |
| `scoring/exploitability.py` | ~146 | LLM scoring prompt + parsing | Stable (score influence deferred) |
| `observer/docker_diff.py` | ~112 | Tier-2 filesystem diff | Stable |
| `observer/target_logs.py` | ~97 | Tier-2 log capture | Needs CWE-specific patterns |
| `context/aggregator.py` | ~161 | Git diff + compose reader | Legacy — will be retired |

### Shallow (thin but correctly scoped — will deepen as gaps are addressed)

| Module | LOC | Role | Status |
|--------|-----|------|--------|
| `approval/gate.py` | ~48 | HITL gate logic | Will deepen with interactive mode |
| `reporting/builder.py` | ~79 | JSON serializer | Will deepen with SARIF + markdown |
| `observer/exit_code.py` | ~49 | Tier-1 exit code capture | Stable, correctly small |
| `observer/base.py` | ~13 | Re-export | Consolidate into `observer/__init__.py` |
| `exceptions.py` | ~30 | Error hierarchy | Stable, correctly small |

**Consolidation note:** Module boundaries align to pipeline stages — the right decomposition. Shallow modules are shallow because they haven't been built out, not because they're over-split. Only `observer/base.py` (13 LOC re-export) is a genuine consolidation candidate → fold into `observer/__init__.py`.

---

## 6. Implementation Decisions Made

| # | Decision | Rationale |
|---|----------|-----------|
| 1 | Legacy diff path will be retired | SAST pipeline is the target architecture |
| 2 | 1:1 finding-to-exploit cardinality | Deterministic baseline first; multi-variant is future work |
| 3 | INCONCLUSIVE means INCONCLUSIVE always | LLM score does not tip the verdict; needs empirical data first |
| 4 | Multi-CWE conflict → STATIC_ONLY wins | Conservative; don't detonate ambiguous findings |
| 5 | Egress blocked via `internal: true` compose network | No iptables needed; Docker-native |
| 6 | Seccomp: Docker default profile | Good baseline; custom profile is future work |
| 7 | `target_dns` validated against compose services | Cheap guard before expensive detonation |
| 8 | Interrupted detonation → INCONCLUSIVE | No silent re-detonation on resume |
| 9 | `--timeout` wires to `detonate()` | CLI flag must do what it says |
| 10 | Observer failures surfaced in report | Degraded evidence must be visible to reviewer |
| 11 | CWE map externalized to config | Extensible without code changes |
| 12 | Unmapped CWEs emit warning | Silent fallback to STATIC_ONLY is a gap |
| 13 | LLM refusal: retry once, then REFUSED state | Don't crash the scan; don't silently skip |
| 14 | Both HITL modes: async (CI) + interactive (dev) | Different workflows need different modes |
| 15 | Report formats: JSON + SARIF + markdown | Machines, CI, humans |
| 16 | Source context enrichment: agentic (LLM tool-call) | Deferred — requires multi-turn tool-use in intelligence/ |

---

## 7. Testing Decisions and Test Boundaries

### Unit test boundaries (per module, mocked dependencies)
- **Triage:** Given a Finding with known CWEs, assert correct verdict. Test multi-CWE conflict resolution. Test unmapped CWE warning emission.
- **Scoring:** Mock LLM provider. Assert prompt construction and response parsing.
- **Parser:** Test refusal detection against known refusal phrases. Test JSON fence stripping. Test malformed response handling.
- **Verdict synthesizer:** Given evidence lists, assert correct verdict. Test with missing observers (degraded evidence).
- **Ingest:** Parse known Semgrep JSON fixtures. Assert CWE extraction, severity normalization.
- **Approval gate:** Test auto-approve env var. Test interactive mode stdin (mock).

### Integration test boundaries (real Docker, no LLM)
- **Sandbox isolation:** Launch attacker container, verify: no egress (ping external host fails), seccomp active, read-only FS, non-root UID, resource limits enforced.
- **Observer collection:** Detonate a known-good exploit against a test target. Assert all three observers return evidence.
- **Resume:** Start a scan, kill mid-detonation, resume. Assert interrupted findings are INCONCLUSIVE.
- **Concurrency:** Run two scans in parallel against different compose projects. Assert no container/network collisions. Verify SQLite WAL handles concurrent access.

### What is NOT tested
- LLM output quality (non-deterministic; evaluated via accuracy benchmarks, not assertions)
- Semgrep itself (upstream tool; we test our parsing of its output)
- Docker internals (we test our orchestration of Docker, not Docker itself)

---

## 8. Out of Scope

| Item | Reason |
|------|--------|
| v0.3 patch generation / remediation output | Not implemented; specified in ADR-009 as v0.3 work (triple-verification patch loop) |
| LLM score influencing verdict | Deferred pending empirical accuracy data |
| Multi-variant exploit generation per finding | Future; 1:1 is the v0.2 model |
| Custom seccomp profiles | Docker default is sufficient for v0.2 |
| Legacy diff path improvements | Being retired |
| `ScoredFinding` dataclass usage in memory | Score lives in SQLite only; in-memory model not needed until score influences verdict |
| Agentic source context enrichment | Requires multi-turn tool-use refactor of intelligence/ |
| Multiple non-DB target service detection | Heuristic returns first match; multi-service targeting is future work |
