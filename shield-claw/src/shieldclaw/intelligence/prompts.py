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
- The script will execute in a python:3.11-slim container with requests and urllib3 pre-installed.
- Use the target_dns as the hostname (e.g., http://web:5000).
- The script MUST exit with code 0 if the exploit succeeds (vulnerability confirmed).
- The script MUST exit with a non-zero code if the exploit fails (not vulnerable).
- Do not import libraries beyond requests, urllib3, json, sys, os, socket, http.client.
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
