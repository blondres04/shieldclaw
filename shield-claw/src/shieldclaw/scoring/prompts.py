"""LLM prompts for exploitability scoring.

The scoring prompt instructs the model to return a strict JSON object with
four fields.  ``scored_at`` and ``model_name`` are stamped by the scorer,
not the model.
"""

from __future__ import annotations

SCORING_SYSTEM_PROMPT = """\
You are a security-assessment assistant evaluating SAST findings for practical exploitability.

Given a code finding with surrounding source context and the Docker Compose service topology, \
output a single JSON object with EXACTLY these fields:

{
  "score": <float 0.0 to 1.0; 1.0 = almost certainly exploitable with no prerequisites>,
  "attack_surface": <one of: "NETWORK", "FILE", "ENV", "OTHER">,
  "prerequisites": <JSON array of strings describing what an attacker needs first>,
  "reasoning": <one plain-English sentence explaining the score>
}

Rules:
- Output ONLY valid JSON. No prose, no markdown fences, no extra keys.
- score must be a JSON number, not a string.
- attack_surface must be exactly one of the four values above.
- prerequisites may be an empty array if there are none.
- reasoning must be a single sentence (no newlines).
"""


def build_scoring_prompt(
    rule_id: str,
    severity: str,
    cwe: tuple[str, ...],
    message: str,
    file_path: str,
    start_line: int,
    end_line: int,
    source_excerpt: str,
    compose_yaml: str,
) -> str:
    """Construct the user-turn prompt for a single finding.

    Args:
        rule_id: Semgrep rule identifier.
        severity: Finding severity (INFO/WARNING/ERROR).
        cwe: CWE identifiers associated with the finding.
        message: Human-readable description from Semgrep.
        file_path: Relative path to the affected file.
        start_line: First affected line (1-based).
        end_line: Last affected line (1-based).
        source_excerpt: Annotated source lines surrounding the finding.
        compose_yaml: Raw Docker Compose YAML (truncated if large).

    Returns:
        Formatted user-turn string ready for the LLM.
    """
    cwe_str = ", ".join(cwe) if cwe else "(none)"
    return f"""\
## Finding

rule_id : {rule_id}
severity: {severity}
cwe     : {cwe_str}
message : {message}
location: {file_path}  lines {start_line}–{end_line}

## Source excerpt

{source_excerpt}

## Docker Compose services (truncated to 2000 chars)

{compose_yaml[:2000]}

Assess the exploitability and return the JSON object described in your instructions.
"""
