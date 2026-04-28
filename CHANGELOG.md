# Changelog

All notable changes to ShieldClaw are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased] — v0.2 pivot in progress on `pivot/sast-verifier`

### In Progress

- Phase 0 — pre-flight debt: scope cleanup, healthcheck readiness,
  dead-code removal, provider validation
- Phase 1 — Semgrep ingest and triage classifier (`ingest/`, `triage/`)
- Phase 2 — LLM exploitability scoring and SQLite persistence with
  resumable runs (`scoring/`, `persistence/`)
- Phase 3 — HITL approval gate, PoC generation, Tier-1/2 Observer
  Pattern (`approval/`, `observer/`)
- Phase 4 — Hosted LLM provider implementation and pre-built attacker
  image
- Phase 5 — Patch-and-verify loop with triple verification
  (`remediation/`)
- Phase 6 — ADR ratification, README rewrite, contributor onboarding
  flow

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
