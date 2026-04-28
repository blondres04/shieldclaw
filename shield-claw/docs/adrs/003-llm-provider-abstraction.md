# ADR-003: LLM Provider Abstraction

## Status

Accepted — 2026-04-28

## Context

ShieldClaw uses LLMs in two distinct roles:
1. **Exploit generation** — produce a `ExploitPayload` from a diff or a
   `Finding`.
2. **Exploitability scoring** — return a structured JSON assessment from a
   `Finding` + source context.

v0.1 shipped one working provider (Ollama) and two stubs (OpenAI, Anthropic).
v0.2 added `OpenAIProvider` with a real implementation and introduced a new
`complete(system_prompt, user_prompt) -> str` method needed by the `scoring/`
package, which calls the LLM without going through the exploit-payload parsing
layer.

The question is: how do we support multiple backends without coupling
`scoring/` to a concrete HTTP client?

## Decision

Define `LLMProvider` as an ABC in `intelligence/base.py` with two abstract
methods:
- `generate_exploit(context: ScanContext) -> ExploitPayload`
- `complete(system_prompt: str, user_prompt: str) -> str`

Concrete implementations (`OllamaProvider`, `OpenAIProvider`) live in
`intelligence/`. The `scoring/` package imports only `LLMProvider` from
`intelligence.base` (permitted by the architectural allowlist in ADR-001) —
it never imports a concrete provider.

The orchestrator constructs the provider and injects it. Provider selection
is configured by the `--provider` CLI flag.

**Model defaults:**
- Ollama: `gemma3:4b` (override via `OLLAMA_MODEL`)
- OpenAI: `gpt-4o-mini` (cheapest capable model; override via `OPENAI_MODEL`)
  Cost rationale: at the default 5 findings/scan, `gpt-4o-mini` scoring costs
  ≈ $0.001/scan vs. ≈ $0.05 for `gpt-4o`.

## Consequences

**Positive**
- Adding a new backend (Anthropic, LM Studio, Azure OpenAI) requires one new
  class; nothing else changes.
- `scoring/` unit tests mock `LLMProvider` directly — no real HTTP calls.
- The `complete()` method is general enough for future scoring, summarisation,
  and classification tasks without adding new abstract methods per use case.

**Negative**
- `complete()` returns raw text; callers must parse the structure themselves.
  This is intentional (the caller knows what shape it expects) but it means
  parse errors surface at call sites, not in the provider.
- The `scoring → intelligence` allowlist is a documented exception to ADR-001
  isolation rules. If a third feature package needs `LLMProvider`, the
  allowlist will need updating and the ADR should be revisited.

## Alternatives Considered

- **Duplicate the ABC in `scoring/`**: Creates two parallel hierarchies that
  drift apart. Rejected.
- **Move `LLMProvider` to `models.py`**: `models.py` is a pure-data leaf; an
  ABC with abstract methods is not a data type. Rejected on semantic grounds.
- **Generic `complete()` only; derive `generate_exploit` via a prompt adapter**:
  Cleaner long-term but requires all existing v0.1 callers to be rewritten.
  Deferred to v0.3.
