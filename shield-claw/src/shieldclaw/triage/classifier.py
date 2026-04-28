"""Rule-based triage classifier: maps CWE numbers and rule-id prefixes to verdicts.

Classification order (evaluated top-to-bottom; first match wins):

1. **OUT_OF_SCOPE by rule-id prefix** — rules whose check_id starts with
   ``dockerfile.``, ``terraform.``, ``kubernetes.``, ``secrets.``, or
   ``license.`` describe infrastructure or secret-detection concerns that the
   exploit pipeline cannot verify dynamically.

2. **OUT_OF_SCOPE by severity + CWE absence** — an ``INFO``-severity finding
   with no CWE attached is informational only; no exploit detonation is useful.

3. **CWE lookup** — the first CWE id in ``finding.cwe`` that exists in
   ``_CWE_VERDICTS`` determines the verdict.  CWE ids are matched after
   stripping the ``CWE-`` prefix and normalising to uppercase.

4. **Default fallback** — STATIC_ONLY with an explanatory reason.

Public API
----------
- ``classify(finding: Finding) -> TriagedFinding``
"""

from __future__ import annotations

from shieldclaw.models import Finding, TriagedFinding, TriageVerdict

# ---------------------------------------------------------------------------
# CWE → verdict map (module-level constant; order is significant only within
# the dict for documentation purposes — actual priority is handled by the
# classifier logic above).
# ---------------------------------------------------------------------------
_DV = TriageVerdict.DYNAMICALLY_VERIFIABLE
_SO = TriageVerdict.STATIC_ONLY

_CWE_VERDICTS: dict[str, TriageVerdict] = {
    # --- Dynamically verifiable ---
    "CWE-22": _DV,  # Path traversal
    "CWE-78": _DV,  # OS command injection
    "CWE-79": _DV,  # Cross-site scripting (XSS)
    "CWE-89": _DV,  # SQL injection
    "CWE-94": _DV,  # Code injection
    "CWE-352": _DV,  # CSRF
    "CWE-434": _DV,  # Unrestricted file upload
    "CWE-502": _DV,  # Deserialization of untrusted data
    "CWE-601": _DV,  # Open redirect
    "CWE-611": _DV,  # XML external entity (XXE)
    "CWE-918": _DV,  # Server-side request forgery (SSRF)
    # --- Static analysis only ---
    "CWE-259": _SO,  # Use of hard-coded password
    "CWE-321": _SO,  # Use of hard-coded cryptographic key
    "CWE-326": _SO,  # Inadequate encryption strength
    "CWE-327": _SO,  # Use of broken or risky cryptographic algorithm
    "CWE-328": _SO,  # Use of weak hash
    "CWE-330": _SO,  # Use of insufficiently random values
    "CWE-798": _SO,  # Use of hard-coded credentials
}

# Rule-id prefix patterns that are always out of scope.
_OUT_OF_SCOPE_PREFIXES: tuple[str, ...] = (
    "dockerfile.",
    "terraform.",
    "kubernetes.",
    "secrets.",
    "license.",
)


def classify(finding: Finding) -> TriagedFinding:
    """Classify a ``Finding`` into one of three triage verdicts.

    The classification is **pure** and **deterministic** — the same input always
    produces the same output.  No network calls, no LLM inference, no I/O.

    Classification order (see module docstring for full rationale):

    1. Out-of-scope rule-id prefixes.
    2. INFO severity with no CWE.
    3. CWE lookup in ``_CWE_VERDICTS``.
    4. Default STATIC_ONLY fallback.

    Args:
        finding: The SAST finding to classify.

    Returns:
        A ``TriagedFinding`` with the assigned verdict and a short reason string.
    """
    rule_lower = finding.rule_id.lower()

    # Step 1: out-of-scope by rule-id prefix.
    for prefix in _OUT_OF_SCOPE_PREFIXES:
        if rule_lower.startswith(prefix):
            return TriagedFinding(
                finding=finding,
                verdict=TriageVerdict.OUT_OF_SCOPE,
                reason=f"rule-id starts with {prefix!r}; infrastructure/secret scan out of scope",
            )

    # Step 2: INFO severity with no CWE.
    if finding.severity == "INFO" and not finding.cwe:
        return TriagedFinding(
            finding=finding,
            verdict=TriageVerdict.OUT_OF_SCOPE,
            reason="INFO severity with no CWE; informational only",
        )

    # Step 3: CWE lookup — first CWE that maps wins.
    for cwe_raw in finding.cwe:
        # Normalise "CWE-89: description" → "CWE-89"
        cwe_key = cwe_raw.split(":")[0].strip().upper()
        verdict = _CWE_VERDICTS.get(cwe_key)
        if verdict is not None:
            return TriagedFinding(
                finding=finding,
                verdict=verdict,
                reason=f"{cwe_key} mapped to {verdict.value}",
            )

    # Step 4: default fallback.
    return TriagedFinding(
        finding=finding,
        verdict=TriageVerdict.STATIC_ONLY,
        reason="no rule mapped; defaulting to static-only to avoid wasted detonation",
    )
