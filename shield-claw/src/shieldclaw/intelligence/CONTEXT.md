# CONTEXT: intelligence/

## Role in the System

The `intelligence/` package is the **Exploit Generation Stage** of the Shield Claw pipeline.
It receives a `ScanContext` from the orchestrator, sends it to an LLM, and returns a structured
`ExploitPayload`. It corresponds to the "LLM" stage in the README architecture diagram.

This package implements the **Strategy Pattern**: `LLMProvider` (in `base.py`) is the abstract
interface; `OllamaProvider`, `OpenAIProvider`, and `AnthropicProvider` are the concrete strategies.
The orchestrator selects the strategy by name at runtime via `default_provider_factory`.

---

## Conventions Specific to This Area

1. **All providers subclass `LLMProvider` from `base.py`.** Every new provider must implement
   `generate_exploit(context: ScanContext) -> ExploitPayload`. No other interface is recognized
   by the orchestrator. Registering a new provider requires adding a `case` to
   `default_provider_factory` in `orchestrator.py`.

2. **Temperature=0 is mandatory for all providers.** Deterministic decoding is non-negotiable —
   reproducible outputs are required for reliable scan results and eval comparisons.
   - Ollama: `"options": {"temperature": 0}` in the request body.
   - OpenAI: `"temperature": 0` in the chat completions request.
   - Anthropic: `"temperature": 0` in the messages request.
   Any provider that omits temperature control is a defect.

3. **JSON-only output is required.** `SYSTEM_PROMPT` in `prompts.py` instructs the model to
   respond with ONLY a JSON object — no markdown fences, no preamble, no explanation.
   When configuring a new provider, set the API's equivalent of "JSON mode" or "structured output"
   if the provider supports it, in addition to the system prompt instruction.

4. **Python-only exploit scripts.** The prompt constrains the model to Python 3 scripts.
   Do not alter the language constraint in `SYSTEM_PROMPT`. The sandbox runner only supports
   Python; changing the language requires a new ADR and changes to `sandbox/docker_orchestrator.py`.

5. **All raw model output passes through `parse_llm_response()` in `parser.py`.** Do NOT
   bypass the parser. It handles: markdown fence stripping, JSON parsing, field validation,
   refusal detection, and `target_dns` normalization (strips trailing `:port`).

6. **The model contract is defined in two places that must stay in sync:**
   - `prompts.py` → `SYSTEM_PROMPT`: defines the required JSON schema for the model.
   - `parser.py` → `_REQUIRED_JSON_FIELDS`: defines the fields the parser validates.
   If you change the JSON schema, update BOTH files in the same commit.

7. **Feature module isolation.** Files in `intelligence/` may NOT import from `context/`,
   `sandbox/`, or `reporting/`. Only `shieldclaw.models` and `shieldclaw.exceptions` are
   permitted as internal `shieldclaw.*` imports.

---

## Patterns for Common Operations

1. **To add a new LLM provider:**
   - Create `intelligence/{name}_provider.py`
   - Subclass `LLMProvider` from `base.py`
   - Implement `generate_exploit(context: ScanContext) -> ExploitPayload`
   - Call `build_user_prompt(context)` from `prompts.py` to format the input
   - Set `temperature=0` (or provider equivalent) in the API call
   - Parse the raw response via `parse_llm_response(raw)` from `parser.py`
   - Add a `case "{name}":` to `default_provider_factory` in `orchestrator.py`
   - Add a test file at `tests/test_{name}_provider.py`

2. **To change what the model is asked to produce:**
   - Edit `SYSTEM_PROMPT` in `prompts.py`
   - Update `_REQUIRED_JSON_FIELDS` in `parser.py` if field names change
   - Update `ExploitPayload` in `models.py` if the data shape changes
   - All three must be updated in the same commit — they form a single logical contract

3. **To tune refusal detection:**
   - Edit `_REFUSAL_MARKERS` in `parser.py`
   - Run `pytest tests/test_llm_parser.py` to verify no regressions

---

## Known Constraints

- **`OpenAIProvider` is a stub.** `generate_exploit` raises `LLMResponseError` unconditionally.
  It validates API key presence and HTTP connectivity only. Do not use in production until
  fully implemented.

- **`AnthropicProvider` status** should be verified before relying on it. Treat it as a stub
  until confirmed otherwise.

- **Ollama response envelope** differs from the OpenAI format. Ollama wraps content under
  `body["message"]["content"]` (chat endpoint `/api/chat`). OpenAI uses
  `body["choices"][0]["message"]["content"]`. Do not conflate these shapes.

- **Accuracy baseline:** On `gemma3:4b` (4B local model via Ollama) the eval harness reports
  60–70% accuracy. Models under 7B parameters are unreliable for production use. See
  `evals/README.md` for methodology.

- **`parser.py` defensively strips markdown fences** because some models wrap JSON in
  ` ```json ` blocks despite the system prompt instruction. This is a known failure mode of
  smaller models and must be retained.
