"""
AegisGate Red Team Agent
Autonomous payload generator that uses a local Ollama model to produce
adversarial Java Spring Boot snippets for the DevSecOps audit pipeline.
"""

import json
import os
import re
import sys
import uuid
from pathlib import Path
from random import choice

import ollama
from ollama import Client
from pydantic import BaseModel, ValidationError

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

OWASP_CATEGORIES = [
    "OWASP_A01 - Broken Access Control",
    "OWASP_A02 - Cryptographic Failures",
    "OWASP_A03 - Injection",
    "OWASP_A04 - Insecure Design",
    "OWASP_A05 - Security Misconfiguration",
    "OWASP_A06 - Vulnerable and Outdated Components",
    "OWASP_A07 - Identification and Authentication Failures",
    "OWASP_A08 - Software and Data Integrity Failures",
    "OWASP_A09 - Security Logging and Monitoring Failures",
    "OWASP_A10 - Server-Side Request Forgery (SSRF)",
]

_default_output = Path(__file__).resolve().parent.parent / "src" / "main" / "resources" / "offline-payloads"
OUTPUT_DIR = Path(os.environ.get("PAYLOAD_DIR", str(_default_output)))
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
MODEL = "gemma3:12b"


class PRPayload(BaseModel):
    prId: str
    threatCategory: str
    isPoisoned: bool
    originalSnippet: str
    poisonedSnippet: str


# ---------------------------------------------------------------------------
# Prompt
# ---------------------------------------------------------------------------

def build_system_prompt(owasp_category: str) -> str:
    return (
        "You are an expert DevSecOps Red Teamer. "
        "Output ONLY raw JSON. No markdown formatting, no backticks, no conversational text. "
        "You must generate a JSON object representing a vulnerable Java Spring Boot snippet "
        f"with a subtle, critical vulnerability related to {owasp_category}. "
        "The JSON keys must exactly match: prId, threatCategory, isPoisoned, originalSnippet, poisonedSnippet. "
        'The "originalSnippet" should be a safe, correct Spring Boot code snippet. '
        'The "poisonedSnippet" should be a subtly modified version introducing the vulnerability. '
        f'Set "threatCategory" to "{owasp_category}". '
        'Set "isPoisoned" to true.'
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


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    category = choice(OWASP_CATEGORIES)
    pr_id = f"PR-{uuid.uuid4().hex[:8].upper()}"
    system_prompt = build_system_prompt(category)

    user_prompt = (
        f'Generate the JSON payload now. Use "{pr_id}" as the prId value.'
    )

    print(f"[*] Targeting OWASP category : {category}")
    print(f"[*] Generated PR ID          : {pr_id}")
    print(f"[*] Ollama host              : {OLLAMA_HOST}")
    print(f"[*] Calling Ollama ({MODEL})...")

    client = Client(host=OLLAMA_HOST)
    response = client.chat(
        model=MODEL,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        format="json",
    )

    raw_output = response["message"]["content"]
    print(f"[*] Raw LLM output length    : {len(raw_output)} chars")

    cleaned = clean_llm_output(raw_output)

    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError as e:
        print(f"[!] JSON parse error: {e}")
        print(f"[!] Cleaned output was:\n{cleaned}")
        sys.exit(1)

    # Force our deterministic values so the LLM can't override them
    data["prId"] = pr_id
    data["isPoisoned"] = True

    try:
        payload = PRPayload(**data)
    except ValidationError as e:
        print(f"[!] Pydantic validation failed:\n{e}")
        sys.exit(1)

    print("[+] Pydantic validation passed")

    # Serialize with the extra `status` field the backend ingester expects
    output_dict = payload.model_dump()
    output_dict["status"] = "PENDING_REVIEW"

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    filename = f"ai-generated-{pr_id}.json"
    filepath = OUTPUT_DIR / filename

    filepath.write_text(json.dumps(output_dict, indent=2), encoding="utf-8")
    print(f"[+] Payload written to {filepath}")


if __name__ == "__main__":
    main()
