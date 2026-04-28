"""System instructions and user prompt assembly for exploit-generation requests.

Two prompt strategies are supported:

* ``build_diff_prompt(context)`` — the original v0.1 diff-centric prompt
  (used by ``OllamaProvider.generate_exploit`` in legacy mode).
* ``build_finding_prompt(finding, source_excerpt, compose_yaml)`` — finding-centric
  prompt for the v0.2 SAST pipeline (used by ``PocGenerator``).
"""

from __future__ import annotations

from shieldclaw.models import Finding, ScanContext

# ---------------------------------------------------------------------------
# Shared exploit-output contract (both prompts request the same JSON shape)
# ---------------------------------------------------------------------------
_EXPLOIT_JSON_CONTRACT = """\
You MUST respond with ONLY a JSON object. No markdown, no explanation, no preamble.

The JSON object MUST have exactly these fields:
{
  "language": "python",
  "target_dns": "<ONLY the Docker Compose service hostname, e.g. web — never include a port>",
  "raw_code": "<a complete Python 3 script that attempts to exploit the vulnerability>",
  "execution_command": "python3 /exploit/exploit.py"
}

Rules for the exploit script:
- Generate the exploit as a single Python 3 script. Do not use bash, curl, or any other language.
- Include every import you use at the top. The first two lines must be ``import sys`` then ``import requests``.
- The script runs standalone (no web framework request object). Build URLs with plain Python strings; use requests.get(url, params=...).
- Never call input() or read from stdin; the exploit must be fully non-interactive.
- The container installs requests and urllib3 before your code runs. Do not import other third-party libraries.
- Always include the container listen port in the URL (e.g. ``http://web:5000``).
- For SQL injection: prefer short boolean tautology payloads (e.g. "1 OR 1=1") over destructive multi-statement attempts.
- Call sys.exit(0) if exploitation succeeds (vulnerability confirmed).
- Call sys.exit(non-zero) if it fails. Always use sys.exit, not exit().
- Keep the script under 100 lines.
"""

# ---------------------------------------------------------------------------
# Legacy diff-centric prompt (v0.1 pipeline)
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = (
    "You are a security research assistant. Your task is to generate a Python "
    "exploit script that tests whether a specific vulnerability exists in a "
    "target web application.\n\nYou will receive:\n"
    "1. A git diff showing recent code changes\n"
    "2. The docker-compose.yml describing the target environment\n\n" + _EXPLOIT_JSON_CONTRACT
)


def build_diff_prompt(context: ScanContext) -> str:
    """Format scan context into the user message for the legacy diff-based path.

    Args:
        context: Immutable diff and compose snapshot for the target repository.

    Returns:
        A single string containing labeled sections for the model consumer.
    """
    return (
        "Git diff:\n"
        f"{context.git_diff_content}\n\n"
        "docker-compose.yml:\n"
        f"{context.docker_compose_content}\n\n"
        f"Target directory (reference only): {context.target_dir}\n"
        f"Captured at: {context.timestamp.isoformat()}\n"
    )


# Keep the old name for backwards compatibility within the intelligence package.
build_user_prompt = build_diff_prompt

# ---------------------------------------------------------------------------
# Finding-centric prompt (v0.2 SAST pipeline)
# ---------------------------------------------------------------------------
FINDING_SYSTEM_PROMPT = (
    "You are a security research assistant. Your task is to generate a Python "
    "exploit script that proves whether a specific SAST finding is exploitable "
    "in the described Docker Compose environment.\n\n"
    "You will receive:\n"
    "1. Details of a SAST finding (rule ID, CWE, source lines, metavariables)\n"
    "2. The docker-compose.yml describing the target environment\n\n"
    "Use the metavariable values to construct concrete payload strings "
    "wherever applicable.\n\n" + _EXPLOIT_JSON_CONTRACT
)


def build_finding_prompt(
    finding: Finding,
    source_excerpt: str,
    compose_yaml: str,
) -> str:
    """Build the user-turn prompt for finding-centric PoC generation.

    Args:
        finding: The SAST finding to exploit.
        source_excerpt: Annotated source lines around the finding.
        compose_yaml: Docker Compose YAML for the target application.

    Returns:
        Formatted user-turn message for the LLM.
    """
    cwe_str = ", ".join(finding.cwe) if finding.cwe else "(none)"
    metavar_lines = "\n".join(f"  {name}: {value}" for name, value in finding.metavars.items())
    metavar_section = metavar_lines or "  (none)"
    return (
        f"## SAST Finding\n\n"
        f"rule_id : {finding.rule_id}\n"
        f"severity: {finding.severity}\n"
        f"cwe     : {cwe_str}\n"
        f"message : {finding.message}\n"
        f"location: {finding.path}  lines {finding.start_line}–{finding.end_line}\n\n"
        f"### Metavariables\n{metavar_section}\n\n"
        f"### Source excerpt\n{source_excerpt}\n\n"
        f"## Docker Compose services (truncated to 3000 chars)\n\n"
        f"{compose_yaml[:3000]}\n\n"
        "Generate the exploit script that targets this specific finding.\n"
    )
