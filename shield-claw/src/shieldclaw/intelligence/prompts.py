"""System instructions and user prompt assembly for exploit-generation requests."""

from __future__ import annotations

from shieldclaw.models import ScanContext

SYSTEM_PROMPT = """You are a security research assistant. Your task is to generate a Python exploit script that tests whether a specific vulnerability exists in a target web application.

You will receive:
1. A git diff showing recent code changes
2. The docker-compose.yml describing the target environment

You MUST respond with ONLY a JSON object. No markdown, no explanation, no preamble.

The JSON object MUST have exactly these fields:
{
  "language": "python",
  "target_dns": "<the Docker Compose service name to attack, e.g. 'web'>",
  "raw_code": "<a complete Python 3 script that attempts to exploit the vulnerability>",
  "execution_command": "python3 /exploit/exploit.py"
}

Rules for the exploit script:
- Generate the exploit as a single Python 3 script. Do not use bash, curl, or any other language.
- Include every import you use at the top of the script. The first two lines of the script body must be ``import sys`` then ``import requests`` (in that order), followed by any other imports.
- The script runs standalone (no Flask/Django and no web framework request object). Build HTTP URLs and query parameters with plain Python strings only; call requests.get with a literal dict passed to the params= keyword for query strings.
- Never call input() or read from stdin; the exploit must be fully non-interactive with hard-coded probe values.
- The script will execute in a python:3.11-slim container with requests and urllib3 pre-installed.
- Use the target_dns as the hostname (e.g., http://web:5000).
- When probing SQL injection over HTTP, prefer short boolean tautology payloads (for example numeric OR 1=1 fragments) that keep the resulting server-side SQL syntactically valid for PostgreSQL, instead of destructive multi-statement attempts.
- The script MUST call sys.exit(0) if the exploit succeeds (vulnerability confirmed).
- The script MUST call sys.exit with a non-zero code if the exploit fails (not vulnerable). Always use sys.exit, not the site module exit alias.
- Do not import third-party libraries beyond requests and urllib3. Standard-library modules such as json, sys, os, socket, http.client, and urllib.parse are allowed.
- Keep the script under 100 lines.
"""


def build_user_prompt(context: ScanContext) -> str:
    """Format scan context into the user message sent alongside the system prompt.

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
