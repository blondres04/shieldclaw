"""
ShieldClaw Red Team Agent
Targeted PR analyzer that uses GitHub Recon to fetch real diffs and a local
Ollama model to identify vulnerabilities and generate exploit payloads.
"""

import json
import logging
import os
import re
import sys
import time
import uuid
from pathlib import Path
from typing import Optional

from ollama import Client
from pydantic import BaseModel, ValidationError

from github_recon import GitHubRecon
from sandbox_orchestrator import SandboxOrchestrator

logging.basicConfig(level=logging.INFO, format="%(message)s")

# ---------------------------------------------------------------------------
# Targets (hardcoded safe defaults for Phase 1 testing)
# ---------------------------------------------------------------------------

TARGET_REPO = "octocat/Hello-World"
TARGET_PR = 1

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_default_output = (
    Path(__file__).resolve().parent.parent
    / "src" / "main" / "resources" / "offline-payloads"
)
OUTPUT_DIR = Path(os.environ.get("PAYLOAD_DIR", str(_default_output)))
TEMP_DIR = OUTPUT_DIR / "temp"
READY_DIR = OUTPUT_DIR / "ready"
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
MODEL = "gemma3:12b"

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

class PRPayload(BaseModel):
    prId: str
    threatCategory: str
    isPoisoned: bool
    originalSnippet: str
    poisonedSnippet: str
    aiJustificationGroundTruth: str


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = (
    "You are an elite DevSecOps Red Team Agent. "
    "Your mission is to analyze a Pull Request code diff, identify the most "
    "critical business logic flaw or security vulnerability present, classify "
    "it by its OWASP Top 10 category, extract the vulnerable code section, "
    "and write a malicious exploit payload that demonstrates how the flaw "
    "can be exploited.\n\n"
    "CRITICAL: Your payload will be executed as a bash script inside an "
    "Alpine Linux container. The target repository has been cloned into the "
    "/workspace/repo_name directory (repo_name is the repository name segment "
    "of the GitHub slug, e.g. owner/repo_name). You are currently in that "
    "directory when the script runs. Write your exploit code accordingly.\n\n"
    "Output ONLY raw JSON. No markdown formatting, no backticks, no "
    "conversational text. The JSON keys must exactly match:\n"
    "  prId            - string, use the value provided in the user message\n"
    "  threatCategory  - string, the OWASP category (e.g. "
    '"OWASP_A03 - Injection")\n'
    "  isPoisoned      - boolean, always true\n"
    "  originalSnippet - string, the relevant vulnerable code extracted "
    "verbatim from the diff\n"
    "  poisonedSnippet - string, a working exploit script or payload that "
    "demonstrates the vulnerability\n"
    "  aiJustificationGroundTruth - string, a detailed technical explanation "
    "of why the code is vulnerable and how the exploit works"
)


def build_user_prompt(pr_id: str, diff: str) -> str:
    return (
        f'Analyze this Pull Request diff and generate an exploit payload. '
        f'Use "{pr_id}" as the prId value.\n\n'
        f'--- BEGIN PR DIFF ---\n{diff}\n--- END PR DIFF ---'
    )


# ---------------------------------------------------------------------------
# LLM output cleaning
# ---------------------------------------------------------------------------

def clean_llm_output(raw: str) -> str:
    """Strip whitespace and remove markdown code fences the LLM may emit."""
    text = raw.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    return text.strip()


def clean_and_parse_llm_output(raw_text: str) -> dict:
    """Clean LLM output and parse it as JSON.

    Handles three common LLM failure modes:
      1. Clean JSON
      2. JSON wrapped in markdown code fences
      3. JSON preceded by conversational preamble text
    """
    cleaned = clean_llm_output(raw_text)

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end != -1 and end > start:
        return json.loads(cleaned[start : end + 1])

    raise json.JSONDecodeError("No JSON object found in LLM output", cleaned, 0)


# ---------------------------------------------------------------------------
# Core analysis cycle
# ---------------------------------------------------------------------------

def analyze_diff(diff: str, repo: str, pr_number: int) -> None:
    """Analyze a PR diff, validate via sandbox, and produce a payload."""
    pr_id = f"PR-{uuid.uuid4().hex[:8].upper()}"
    user_prompt = build_user_prompt(pr_id, diff)

    print(f"[*] Generated PR ID          : {pr_id}")
    print(f"[*] Diff length              : {len(diff)} chars")
    print(f"[*] Ollama host              : {OLLAMA_HOST}")
    print(f"[*] Calling Ollama ({MODEL})...")

    client = Client(host=OLLAMA_HOST)
    response = client.chat(
        model=MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        format="json",
    )

    raw_output = response["message"]["content"]
    print(f"[*] Raw LLM output length    : {len(raw_output)} chars")

    data = clean_and_parse_llm_output(raw_output)

    data["prId"] = pr_id
    data["isPoisoned"] = True

    payload = PRPayload(**data)
    print(f"[+] Pydantic validation passed (threat: {payload.threatCategory})")

    sandbox = SandboxOrchestrator()
    verified = sandbox.execute_payload(repo, pr_number, payload.poisonedSnippet)
    print(f"[+] Empirical verification   : {'PASS' if verified else 'FAIL'}")

    output_dict = payload.model_dump()
    output_dict["status"] = "PENDING_REVIEW"
    output_dict["empiricallyVerified"] = verified

    TEMP_DIR.mkdir(parents=True, exist_ok=True)
    READY_DIR.mkdir(parents=True, exist_ok=True)

    filename = f"ai-generated-{pr_id}.json"
    temp_path = TEMP_DIR / filename
    ready_path = READY_DIR / filename

    temp_path.write_text(json.dumps(output_dict, indent=2), encoding="utf-8")
    os.rename(str(temp_path), str(ready_path))
    print(f"[+] Payload staged to {ready_path}")


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main() -> None:
    print("[*] ShieldClaw Red Team Agent starting (recon mode)")
    print(f"[*] Target: {TARGET_REPO} PR #{TARGET_PR}")

    recon = GitHubRecon()

    try:
        while True:
            try:
                print(f"\n[*] Fetching diff for {TARGET_REPO}#{TARGET_PR}...")
                diff = recon.get_pr_diff(TARGET_REPO, TARGET_PR)

                if not diff:
                    print("[!] No diff available — skipping cycle")
                    time.sleep(15)
                    continue

                analyze_diff(diff, TARGET_REPO, TARGET_PR)

            except KeyboardInterrupt:
                print("\n[*] Shutting down gracefully")
                sys.exit(0)
            except Exception as e:
                print(f"[!] Error during analysis: {e}")

            print("[*] Sleeping 15s before next cycle...")
            time.sleep(15)
    finally:
        recon.close()


if __name__ == "__main__":
    main()
