# Changelog

All notable changes to ShieldClaw are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

- Phase 5 — Patch-and-verify loop with triple verification
  (`remediation/`) — pending implementation.

---

## [0.2.0] — 2026-04-28

### Added

**Phase 0 — Pre-flight debt** ([#22](https://github.com/blondres04/shieldclaw/issues/22))
- `_cleanup_stale(result_id)` scoped to the calling run's label; prevents
  concurrent runs from destroying each other's containers.
- `_is_service_healthy()` probes `docker inspect Health.Status`; replaces
  string-match `docker compose ps` readiness check.
- Cross-platform Python launchers for pre-commit hooks
  (`scripts/pre_commit_mypy.py`, `scripts/pre_commit_pytest.py`).
- `pytest-cov` added to `requirements-dev.txt`.
- `integration` marker registered in `pyproject.toml`.

**Phase 1 — Semgrep ingest and triage classifier** ([#23](https://github.com/blondres04/shieldclaw/issues/23))
- `ingest/` package: `parse_semgrep_json(path) -> tuple[Finding, ...]`.
  Validates schema, normalises CWE strings, flattens metavars, derives
  `finding_id` via `uuid5(NAMESPACE_URL, rule:path:start:end)`.
- `triage/` package: `classify(finding) -> TriagedFinding`.  Four-step
  deterministic classifier covering 17 CWEs; OUT_OF_SCOPE for infra/secret rules.
- `Finding`, `TriageVerdict`, `TriagedFinding` frozen dataclasses in `models.py`.
- `IngestError(ShieldClawError)` in `exceptions.py`.
- `--semgrep-output PATH` CLI flag; Phase 1 triage summary printed to stderr.
- `tests/fixtures/semgrep_sample.json` — 5-finding realistic fixture.
- 53 new tests (22 ingest, 31 triage).

**Phase 2 — LLM scoring and resumable persistence** ([#24](https://github.com/blondres04/shieldclaw/issues/24))
- `ExploitabilityScore`, `ScoredFinding` frozen dataclasses in `models.py`.
- `LLMProvider.complete(system_prompt, user_prompt) -> str` abstract method;
  implemented in `OllamaProvider`.
- `strip_json_fences()` public function exposed in `intelligence/parser.py`.
- `scoring/` package: `ExploitabilityScorer.score()` with structured JSON prompt.
- `persistence/` package: `ScanStore` — SQLite WAL, three-table schema
  (`scans`, `findings`, `scores`), parameterised queries only.
- `Orchestrator._run_sast()`: ingest → triage → score with per-finding state
  persistence; `KeyboardInterrupt` at any scoring step is resumable.
- `--resume SCAN_ID` flag; `shieldclaw status` subcommand.
- `architecture` test allowlist: `scoring → intelligence` is the sole permitted
  cross-feature import.
- 5 resumability tests; `test_resume_skips_already_scored_findings` milestone.

**Phase 3 — HITL gate, PoC generator, observers, verdict synthesis** ([#25](https://github.com/blondres04/shieldclaw/issues/25))
- `approval/` package: `is_auto_approve_enabled()`, `get_current_user()`,
  `ApprovalContext`, `format_approval_context()`.
- Schema additions: `approvals`, `pocs`, `evidence`, `verdicts` tables.
- `shieldclaw approve` subcommand (single / `--all-pending` / `--auto` modes).
- `intelligence/poc_generator.py`: `PocGenerator` using `FINDING_SYSTEM_PROMPT`
  and `build_finding_prompt()`.
- `observer/` package: `DetonationObserver` ABC (in `models.py`), `ExitCodeObserver`
  (Tier 1), `DockerDiffObserver`, `TargetLogObserver` (Tier 2).
- `DetonationOutcome`, `ObserverEvidence`, `Verdict` frozen dataclasses in `models.py`.
- `DockerOrchestrator.detonate()` returns `DetonationOutcome`; accepts
  `observers: Sequence[DetonationObserver]`.
- `verdict/` package: `synthesize(evidence) -> Verdict` with five deterministic
  rules (TRUE_POSITIVE / FALSE_POSITIVE / INCONCLUSIVE).
- `Orchestrator._run_sast()` Phase 3 extension: auto-approve gate, PoC
  generation, detonation, verdict synthesis — all behind `SHIELDCLAW_AUTO_APPROVE=1`.
- `test_pipeline_e2e.py` integration test (requires Docker).
- Architecture guard: 11 packages in `_FEATURE_MODULES`.

**Phase 4 — OpenAI provider and pre-built attacker image** ([#26](https://github.com/blondres04/shieldclaw/issues/26))
- `intelligence/openai_provider.py`: real `/v1/chat/completions` implementation;
  `response_format={"type":"json_object"}` for supported models; refusal detection.
- `openai` added to `_ALLOWED_PROVIDERS`; `default_provider_factory` updated.
- `docker/attacker.Dockerfile`: `requests==2.32.*` + `urllib3==2.2.*` baked
  at build time; ENTRYPOINT reads exploit from stdin.
- `scripts/build_attacker_image.sh`: build helper with `SHIELDCLAW_ATTACKER_IMAGE` override.
- `DockerOrchestrator._probe_attacker_image()`: startup check with clear
  error message when image is missing.
- `_DETONATE_BOOTSTRAP` and runtime `pip install` removed from detonation.
- `SHIELDCLAW_ATTACKER_IMAGE` env-var override for image tag.
- 10 OpenAI provider unit tests; 3 sealed-network integration tests.

**Phase 6 — Documentation and onboarding** ([#28](https://github.com/blondres04/shieldclaw/issues/28))
- ADRs 001–005 promoted from placeholder to full ADRs.
- ADR-005 updated to reflect Phase 4 pre-built image superseding the original
  "accept PyPI access" decision.
- ADRs 006–010 added (Semgrep input, HITL model, observer tiers, triple
  verification, ephemeral worktrees).
- README rewritten for v0.2: mermaid pipeline diagram, quickstart,
  configuration tables, architectural invariants, limitations.
- `scripts/verify_harness.sh` rewritten as a full 6-step end-to-end verifier
  (prerequisites → lint → attacker image → semgrep scan → shieldclaw run).
- `.github/workflows/ci.yml` split into four jobs: `lint`, `typecheck`,
  `unit` (with coverage), `integration` (Docker; main/pivot branches only).

### Changed

- `_DETONATE_IMAGE` constant replaced by `_detonate_image()` function.
- `docker_orchestrator.py` `detonate()` return type changed from `int` to
  `DetonationOutcome`.
- `orchestrator.py` `run()` accepts both legacy positional and new keyword-only
  call forms; SAST flow and legacy diff flow are separate internal methods.
- `intelligence/prompts.py`: `build_user_prompt` renamed to `build_diff_prompt`
  (alias kept for backwards compatibility); `build_finding_prompt` added.
- `pyproject.toml`: `markers` added for `integration`; `pytest-cov` added.
- Branch protection on `main`: linear history required, 1 review required,
  `quality checks` status check gated.

### Removed

- `shield-claw/src/shieldclaw/intelligence/openai_provider.py` (v0.1 stub) — replaced.
- `shield-claw/src/shieldclaw/intelligence/anthropic_provider.py` (v0.1 stub) — removed.
- `shield-claw/src/shieldclaw/main.py` (dead two-line placeholder) — removed.
- `_DETONATE_BOOTSTRAP` bootstrap script — removed in favour of pre-built image.
- `_state_is_up` static method on `DockerOrchestrator` — replaced by
  `_is_service_healthy`.

### Security

- Detonation no longer requires outbound internet access (PyPI). The pre-built
  attacker image bakes dependencies at build time, enabling fully sealed
  Docker networks.
- Stale-container cleanup scoped to `result_id`; concurrent runs cannot
  destroy each other's containers.
- `--read-only` + `--tmpfs` hardening flags documented in ADR-004.

---

## [0.1.0] — Autonomous red-teaming baseline

### Added

- **CLI entry point** (`__main__.py`) — `python -m shieldclaw run`
  with `--target`, `--diff`, `--provider`, `--timeout`, `--output`
  flags; validates all arguments before dispatch.
- **Four-stage pipeline** driven by `orchestrator.py` as a deterministic
  state machine (`INIT → CONTEXT_AGGREGATED → PAYLOAD_GENERATED →
  SANDBOX_RUNNING → DETONATION_COMPLETE → TEARDOWN_COMPLETE`).
- **`context/` package** — `ContextAggregator` collects `git diff`
  and `docker-compose.yml` into an immutable `ScanContext` dataclass.
- **`intelligence/` package** — `LLMProvider` ABC with a working
  `OllamaProvider` (HTTP streaming via `httpx`); `OpenAIProvider` and
  `AnthropicProvider` are stub implementations that validate credentials
  and connectivity only.
- **`sandbox/` package** — `DockerOrchestrator` drives `docker compose`
  up/down and detonates the LLM-generated exploit in a hardened
  ephemeral container (`--read-only`, `--user=1000:1000`,
  `--memory=256m`, `--cpus=0.5`, `--pids-limit=100`, `tmpfs /tmp:noexec`).
- **`reporting/` package** — `ReportBuilder` serialises a `ScanResult`
  to JSON, writing to a file path or stdout.
- **Shared contracts** — `models.py` (frozen dataclasses: `ScanContext`,
  `ExploitPayload`, `ContainerState`, `ScanResult`) and `exceptions.py`
  (`ShieldClawError` hierarchy) carry zero internal `shieldclaw.*`
  imports.
- **Architecture fitness tests** (`tests/test_architecture.py`) — AST
  analysis enforces that feature packages do not cross-import; runs
  without Docker or LLM calls.
- **`docker_orchestrator.py` subprocess helpers** — `_run_required`,
  `_run_optional`, `_run_capture` canonical dispatchers over
  `subprocess.run`; no `Popen`.
- **Bundled integration target** — `test_repos/vulnerable-flask-app/`
  (Flask + Postgres, intentional SQL injection) with `context.patch`
  for git-less runs.
- **Offline eval harness** (`evals/`) — JSON-based LLM accuracy checks
  decoupled from the pipeline.
- **ADRs** — 001 module isolation, 002 pipeline orchestration, 003 LLM
  provider abstraction, 004 Docker sandbox strategy, 005 attacker
  container PyPI access.
- **Enforcement layer** — `ruff` (format + lint), `mypy --strict`, and
  `pytest` run via `scripts/verify_harness.sh`.

### Empirical baseline (gemma3:12b, bundled Flask lab)

- `is_vulnerable: true`, exit code 0, duration ≈ 54 s.
- SQL injection confirmed via `http://web:5000/user?id=1OR1=1`.

### Known limitations

- Single-shot exploit generation; no retry or agentic refinement.
- OpenAI and Anthropic providers are stubs only.
- Python-only exploit payloads.
- No CI/CD integration; no SAST report ingestion.
- Sub-12 B local models produce frequent false negatives.
