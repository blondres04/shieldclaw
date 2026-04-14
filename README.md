# Shield Claw

**Shield Claw** is a local CLI tool that uses LLM-generated exploits to empirically verify application-layer vulnerabilities in Docker-based projects. Unlike static analysis tools that predict whether code *might* be vulnerable, Shield Claw proves it by detonating an exploit against a running replica of your application.

The primary implementation lives in [`shield-claw/`](./shield-claw/) (Python package `shieldclaw`). Optional offline LLM checks live under [`evals/`](./evals/).

---

## Prerequisites

- **Python** 3.11 or newer  
- **Docker** with Compose v2 (`docker compose`, not only legacy `docker-compose`)  
- **Ollama** running locally *or* API credentials for **OpenAI** / **Anthropic** (see `shield-claw/.env.example`)  
- **Git** (only required when your target repo uses `git diff HEAD~1` instead of a bundled patch file)

---

## Quick start

1. Clone the repository and enter it:

   ```bash
   git clone <repository-url>
   cd <repository-directory>
   ```

2. Create and activate a virtual environment (Unix-style shells):

   ```bash
   python3.11 -m venv .venv
   source .venv/bin/activate
   ```

   On Windows (PowerShell):

   ```powershell
   py -3.11 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

3. Install the CLI package and its dependencies:

   ```bash
   pip install -r shield-claw/requirements.txt
   pip install -e shield-claw/
   ```

4. Configure environment variables:

   ```bash
   cp shield-claw/.env.example shield-claw/.env
   ```

   Edit `shield-claw/.env` to set `OLLAMA_MODEL` (default `gemma3:4b`), `OLLAMA_BASE_URL`, or cloud provider keys if you use OpenAI/Anthropic.

5. Verify Docker and Compose:

   ```bash
   docker --version
   docker compose version
   ```

6. Verify Ollama is reachable and the model is present:

   ```bash
   curl http://localhost:11434/api/tags
   ```

   Pull a model if needed, for example:

   ```bash
   ollama pull gemma3:4b
   ```

7. Run the unit tests:

   ```bash
   cd shield-claw
   pytest tests/ -v
   ```

8. Run the pipeline against the bundled vulnerable Flask lab target (from `shield-claw/` so imports resolve when using editable install from repo root, or stay in repo root if `shieldclaw` is on `PYTHONPATH`):

   ```bash
   cd shield-claw
   python -m shieldclaw run --target ../test_repos/vulnerable-flask-app --timeout 120
   ```

   The lab app under `test_repos/vulnerable-flask-app/` is **not** a Git repository; it ships a [`context.patch`](./test_repos/vulnerable-flask-app/context.patch) file that Shield Claw loads automatically when `.git` is absent. For normal repositories, omit that file and use Git history (`git diff HEAD~1`) or pass `--diff path/to.patch`.

   The sample compose file **does not publish host ports** (avoids collisions with anything already bound to TCP 5000). The exploit still reaches the app at `http://web:5000` on the internal Compose network.

   After `docker compose` reports every service as running, the orchestrator waits a short **post-start grace** window so databases and web workers can finish booting before detonation. The field `is_vulnerable` is `true` only when the LLM-generated exploit exits `0`; small models may require a rerun or prompt tuning if they emit brittle scripts.

---

## Usage

```bash
# Default: Ollama provider, diff from git or context.patch fallback
python -m shieldclaw run --target /path/to/repo

# Optional unified diff file (relative paths resolve under the target directory)
python -m shieldclaw run --target /path/to/repo --diff my-change.patch

# Cloud LLM backends
python -m shieldclaw run --target /path/to/repo --provider openai
python -m shieldclaw run --target /path/to/repo --provider anthropic

# Detonation timeout (seconds) and JSON report to a file
python -m shieldclaw run --target /path/to/repo --timeout 60 --output report.json
```

JSON is written to **stdout** unless `--output` is set. The field `is_vulnerable` is `true` when the exploit process exits with code `0`.

---

## Architecture

```text
┌─────────────────────────────────────────────────┐
│              shieldclaw/__main__.py              │
│               (CLI entry point)                  │
│        argparse → validate → dispatch            │
└─────────────────┬───────────────────────────────┘
                  │ depends on
                  ▼
┌─────────────────────────────────────────────────┐
│               orchestrator.py                    │
│          (Pipeline state machine)                │
│    Drives: Context → LLM → Sandbox → Report     │
└──┬──────────┬──────────┬──────────┬─────────────┘
   │          │          │          │
   ▼          ▼          ▼          ▼
┌────────┐ ┌──────────┐ ┌────────┐ ┌──────────┐
│context/│ │intelli-  │ │sandbox/│ │reporting/│
│aggre-  │ │gence/    │ │docker_ │ │builder   │
│gator   │ │ollama,   │ │orches- │ │          │
│        │ │parser,   │ │trator   │ │          │
│        │ │prompts   │ │         │ │          │
└───┬────┘ └────┬─────┘ └───┬────┘ └────┬─────┘
    │           │           │            │
    ▼           ▼           ▼            ▼
┌─────────────────────────────────────────────────┐
│         models.py  +  exceptions.py              │
│            (Shared data objects)                 │
│         Zero internal dependencies               │
└─────────────────────────────────────────────────┘
```

---

## Security considerations

- **Exploit execution** runs LLM-authored Python inside a **hardened** Docker container (`--read-only`, non-root user, memory/CPU/pid limits, tmpfs for `/tmp`). The runtime runs `pip install --target /tmp/pylib` before your script so `requests` is available without a pre-baked image; that needs **outbound HTTPS to PyPI** (or a reachable mirror) from the attacker container. That materially reduces risk compared to running the same code on the host, but it does **not** reduce the risk to zero: **kernel-level container escape bugs** remain a residual threat class. See [ADR-005](shield-claw/docs/adrs/005-attacker-container-pypi-access.md) for the design record and trade-offs.
- **Compose-backed targets** run on the same Docker daemon as your workstation. Only scan code you trust enough to run as containers on your machine.
- **Cloud LLM providers** receive the **git diff** (and `docker-compose.yml` content) you pass into the model. Treat that as **sensitive source code exposure** to a third party unless you keep inference entirely local (e.g. Ollama).

---

## Known limitations (v1)

- **Single-shot** exploit generation (no automatic retry or agentic refinement loop).  
- **Target layout:** the scan expects a `docker-compose.yml` (or `.yaml`) at the repository root (the same layout the CLI validates).  
- **No built-in CI/CD** integration; operators run the CLI manually or wrap it in their own pipelines.  
- **Exploit payloads** are **Python-only** as generated and validated today.  
- **LLM quality** varies by model and prompt; see [`evals/README.md`](./evals/README.md) for an offline harness.

---

## Repository layout

| Path | Role |
|------|------|
| `shield-claw/` | Installable `shieldclaw` package, CLI, tests |
| `test_repos/vulnerable-flask-app/` | Intentionally vulnerable Flask + Postgres demo for integration runs |
| `evals/` | Standalone LLM JSON / refusal evaluation (does not import the app) |

---

## Responsible use

Use Shield Claw only against systems and repositories you own or are explicitly authorized to test. Generated exploits are real attack code.

---

## License

See [LICENSE](./LICENSE) in the repository root.
