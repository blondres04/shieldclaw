# Shield Claw

**Shield Claw** is a local CLI tool that uses LLM-generated exploits to empirically verify application-layer vulnerabilities in Docker-based projects. Unlike static analysis tools that predict whether code *might* be vulnerable, Shield Claw proves it by detonating an exploit against a running replica of your application.

The primary implementation lives in [`shield-claw/`](./shield-claw/) (Python package `shieldclaw`). Optional offline LLM accuracy checks live under [`evals/`](./evals/).

---

## Prerequisites

- **Python** 3.11 or newer
- **Docker Desktop** (or Docker Engine) with Compose v2 (`docker compose`, not legacy `docker-compose`) — must be **running** before you invoke the CLI
- **Ollama** running locally *or* API credentials for **OpenAI** / **Anthropic** (see `shield-claw/.env.example`)
- **Git** (only required when your target repo uses `git diff HEAD~1` instead of a bundled patch file)

---

## Quick start

1. Clone the repository and enter it:

   ```bash
   git clone <repository-url>
   cd <repository-directory>
   ```

2. Create and activate a virtual environment:

   ```bash
   # Unix / macOS
   python3.11 -m venv .venv
   source .venv/bin/activate
   ```

   ```powershell
   # Windows (PowerShell)
   py -3.11 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

   > **Why a virtual environment?** Without one, the `shieldclaw` entry-point script may not land on your `PATH`. If `shieldclaw` is unrecognised after installation, use `python -m shieldclaw` instead — this always works regardless of PATH state.

3. Install the package and its dependencies:

   ```bash
   pip install -r shield-claw/requirements.txt
   pip install -e shield-claw/
   ```

4. Configure environment variables:

   ```bash
   cp shield-claw/.env.example shield-claw/.env
   ```

   The default model is `gemma3:12b`. Edit `shield-claw/.env` to change `OLLAMA_MODEL`, `OLLAMA_BASE_URL`, or cloud provider keys.

5. Verify Docker and Compose are available and the daemon is running:

   ```bash
   docker compose version
   docker ps
   ```

6. Pull the model and verify Ollama is reachable:

   ```bash
   ollama pull gemma3:12b
   curl http://localhost:11434/api/tags
   ```

7. Run the unit tests:

   ```bash
   cd shield-claw
   pytest tests/ -v
   ```

8. Run the pipeline against the bundled vulnerable Flask lab:

   ```bash
   python -m shieldclaw run \
     --target ./test_repos/vulnerable-flask-app \
     --timeout 120 \
     --output report.json
   ```

   `report.json` is written to the current working directory. Drop `--output` to print JSON to stdout instead.

   The lab app ships a [`context.patch`](./test_repos/vulnerable-flask-app/context.patch) file. Shield Claw loads it automatically when `.git` is absent. For real repositories, omit that file — the tool uses `git diff HEAD~1` or a path you supply via `--diff`.

   The sample compose file does **not** publish host ports (avoids collisions on TCP 5000). The exploit reaches the app at `http://web:5000` on the internal Compose network.

---

## Usage

```bash
# Default: Ollama with gemma3:12b, diff from git or context.patch fallback
python -m shieldclaw run --target /path/to/repo

# Explicit diff file
python -m shieldclaw run --target /path/to/repo --diff my-change.patch

# Cloud LLM backends (OpenAI / Anthropic — see Known Limitations)
python -m shieldclaw run --target /path/to/repo --provider openai
python -m shieldclaw run --target /path/to/repo --provider anthropic

# Custom timeout and JSON output
python -m shieldclaw run --target /path/to/repo --timeout 60 --output report.json
```

`is_vulnerable` is `true` when the LLM-generated exploit process exits with code `0`. JSON is written to **stdout** unless `--output` is set.

---

## Sample output

A successful detection against the bundled Flask lab (`gemma3:12b`, 54 seconds):

```json
{
  "result_id": "c10274b7-5802-42eb-b328-080ca74a1414",
  "is_vulnerable": true,
  "exit_code": 0,
  "duration_seconds": 54.23,
  "pipeline_error": null,
  "exploit_payload": {
    "language": "python",
    "target_dns": "web",
    "execution_command": "python3 /exploit/exploit.py",
    "raw_code": "import sys\nimport requests\n\ndef exploit():\n    url = 'http://web:5000/user?id=1'\n    response = requests.get(url)\n    if response.status_code == 200:\n        injection_url = 'http://web:5000/user?id=1OR1=1'\n        injection_response = requests.get(injection_url)\n        if '1' in injection_response.text:\n            print('SQL injection vulnerability confirmed!')\n            sys.exit(0)\n    sys.exit(1)\n\nif __name__ == '__main__':\n    exploit()"
  },
  "container_state": null
}
```

---

## Model selection

Model quality is the primary lever for exploit reliability. Tested locally with Ollama:

| Model | Size | Result on lab | Notes |
|-------|------|---------------|-------|
| `gemma3:4b` | 4 B | ❌ False negative | Generated `request.args` (Flask server object) in the attacker script — `NameError` before first probe |
| `gemma3:12b` | 12 B | ✅ Confirmed `is_vulnerable: true` | Correct SQLi payload, clean `sys.exit(0)` on success |
| `llama3.1:8b` | 8 B | Not yet tested | — |
| OpenAI / Anthropic | — | Not yet available | Providers are stub implementations in v1 (see Known Limitations) |

**Recommendation:** Use `gemma3:12b` or larger for reliable results. Models below 10 B frequently produce syntactically broken scripts or copy server-side framework objects (`request`, `g`, `db`) into the attacker context where they do not exist.

Set the model in `shield-claw/.env`:

```
OLLAMA_MODEL=gemma3:12b
```

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
│        │ │parser,   │ │trator  │ │          │
│        │ │prompts   │ │        │ │          │
└───┬────┘ └────┬─────┘ └───┬────┘ └────┬─────┘
    │           │           │            │
    ▼           ▼           ▼            ▼
┌─────────────────────────────────────────────────┐
│         models.py  +  exceptions.py              │
│            (Shared data objects)                 │
│         Zero internal dependencies               │
└─────────────────────────────────────────────────┘
```

The four feature modules (`context`, `intelligence`, `sandbox`, `reporting`) are **strictly isolated** — none imports from another. `models.py` and `exceptions.py` have zero internal imports. This constraint is enforced by `tests/test_architecture.py` on every test run.

---

## Security considerations

- **Exploit execution** runs LLM-authored Python inside a **hardened** Docker container (`--read-only`, `--user=1000:1000`, `--memory=256m`, `--cpus=0.5`, `--pids-limit=100`, `tmpfs /tmp:noexec`). That materially reduces risk compared to running the same code on the host, but it does **not** reduce the risk to zero: **kernel-level container escape bugs** remain a residual threat class.
- **Attacker container network access:** The attacker container runs `pip install requests urllib3 --target /tmp/pylib` to bootstrap HTTP capabilities. This grants outbound internet access to PyPI during detonation. A future version will pre-bake dependencies into the image to remove this trust boundary. See [ADR-005](shield-claw/docs/adrs/005-attacker-container-pypi-access.md) for the full trade-off analysis.
- **Compose-backed targets** run on the same Docker daemon as your workstation. Only scan code you trust enough to run as containers on your machine.
- **Cloud LLM providers** receive the full **git diff** and `docker-compose.yml` content. Treat that as **sensitive source code exposure** to a third party unless you keep inference entirely local with Ollama.

---

## Known limitations (v1)

- **Single-shot** exploit generation — no automatic retry or agentic refinement loop. Re-run manually if the first attempt produces a broken script.
- **Target layout** — the scan expects a `docker-compose.yml` (or `.yaml`) at the repository root.
- **No built-in CI/CD integration** — run the CLI manually or wrap it in your own pipeline.
- **Python-only exploit payloads** — no other languages are generated or validated in v1.
- **OpenAI and Anthropic providers are stubs** — `OpenAIProvider.generate_exploit` raises `LLMResponseError` unconditionally. Both providers validate connectivity only. Use Ollama until cloud providers are fully implemented.
- **Sub-12B local models are unreliable** — empirically observed false negatives with `gemma3:4b` due to context confusion. Use `gemma3:12b` or larger.

---

## Repository layout

| Path | Role |
|------|------|
| `shield-claw/` | Installable `shieldclaw` package, CLI, tests |
| `test_repos/vulnerable-flask-app/` | Intentionally vulnerable Flask + Postgres demo for integration runs |
| `evals/` | Standalone LLM JSON / refusal evaluation harness (does not import the app) |

---

## Responsible use

Use Shield Claw only against systems and repositories you own or are explicitly authorized to test. Generated exploits are real attack code.

---

## License

See [LICENSE](./LICENSE) in the repository root.
