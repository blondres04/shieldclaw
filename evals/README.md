# ShieldClaw LLM evaluation harness

This folder exercises `OllamaProvider` and the exploit JSON parser against synthetic diffs **without Docker**. It is safe to run on a laptop with only Ollama available.

For the **documented portfolio baseline** (e.g. `gemma3:4b` accuracy range and production guidance), see the root [`README.md`](../README.md) section *Known limitations (v1)*.

## Prerequisites

- Python 3.11+
- Ollama running locally (`OLLAMA_BASE_URL`, default `http://localhost:11434`)
- A pulled model matching `OLLAMA_MODEL` (default `gemma3:4b` in `.env`)

## How to run

From the **repository root** (the directory that contains `shield-claw/` and `evals/`):

```bash
python evals/run_evals.py
```

The script adds `shield-claw/src` to `sys.path` automatically so `import shieldclaw` works without installing the package.

## Metrics

| Metric | Meaning |
|--------|--------|
| **Total accuracy** | Fraction of cases where the outcome matched the rubric: vulnerable cases should yield a parsed `ExploitPayload`; safe cases should yield a refusal, a parse error, or a connection error (not a successful payload). |
| **JSON compliance rate** | Share of cases that did **not** end in `LLMResponseError` (malformed / unparsable model JSON). |
| **Refusal rate** | Share of cases where the model raised `LLMRefusalError`. |
| **Avg inference time** | Mean wall time per `generate_exploit` call. |

Per-case lines show `PASS`/`FAIL`, whether the case was labeled `vuln` or `safe`, the outcome label (`payload`, `refusal`, `response_error`, `connection_error`, or `unexpected:…`), and elapsed seconds.

## Improving scores

If accuracy is low or refusals dominate, adjust the system prompt in `shield-claw/src/shieldclaw/intelligence/prompts.py`, re-run this harness, and compare metrics. Small local models are noisy: a `connection_error` on a safe case usually means an HTTP timeout to Ollama (default 60s per request), not a correct refusal—treat the headline accuracy as a rough baseline.

Benign cases pass when the model refuses (plain text, no JSON), returns unparsable output (`LLMResponseError`), or the request fails at the transport layer (`LLMConnectionError`). Vulnerable cases pass only when a structured `ExploitPayload` is parsed successfully.
