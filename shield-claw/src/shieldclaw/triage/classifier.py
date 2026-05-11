"""Rule-based triage classifier: maps CWE numbers and rule-id prefixes to verdicts.

Classification order (evaluated top-to-bottom; first match wins):

1. **OUT_OF_SCOPE by rule-id prefix** - rules whose check_id starts with
   ``dockerfile.``, ``terraform.``, ``kubernetes.``, ``secrets.``, or
   ``license.`` describe infrastructure or secret-detection concerns that the
   exploit pipeline cannot verify dynamically.

2. **OUT_OF_SCOPE by severity + CWE absence** - an ``INFO``-severity finding
   with no CWE attached is informational only; no exploit detonation is useful.

3. **CWE lookup** - mapped CWEs are resolved conservatively:
   ``STATIC_ONLY`` wins whenever any mapped CWE requires it, otherwise the
   mapped dynamic verdict is used. The bundled MVP map only marks ``CWE-89``
   SQL injection as dynamically verifiable by default; other former dynamic
   classes stay visible as deferred/static-only unless an operator supplies an
   explicit override config for experiments.

4. **Default fallback** - STATIC_ONLY with an explanatory reason.

Public API
----------
- ``classify(finding: Finding) -> TriagedFinding``

Operators may extend the bundled CWE verdict map by placing a TOML file at
``~/.shieldclaw/cwe_verdicts.toml`` or by pointing
``SHIELDCLAW_CWE_VERDICTS_PATH`` at an alternate file. The custom file
overlays the bundled defaults and is validated at import time.
"""

from __future__ import annotations

import importlib.resources
import logging
import os
import tomllib
from pathlib import Path
from typing import Any

from shieldclaw.models import Finding, TriagedFinding, TriageVerdict, normalize_cwe_id

_LOG = logging.getLogger(__name__)

_CWE_VERDICTS_ENV = "SHIELDCLAW_CWE_VERDICTS_PATH"
_DEFAULT_CWE_VERDICTS_RESOURCE = "cwe_verdicts.toml"

# Rule-id prefix patterns that are always out of scope.
_OUT_OF_SCOPE_PREFIXES: tuple[str, ...] = (
    "dockerfile.",
    "terraform.",
    "kubernetes.",
    "secrets.",
    "license.",
)

_SQLI_ONLY_MVP_DEFERRED_CWES: frozenset[str] = frozenset(
    {
        "CWE-22",
        "CWE-78",
        "CWE-79",
        "CWE-94",
        "CWE-352",
        "CWE-434",
        "CWE-502",
        "CWE-601",
        "CWE-611",
        "CWE-918",
    }
)


def _user_cwe_verdicts_path() -> Path:
    """Return the operator override path for the CWE verdict config."""
    raw_override = os.environ.get(_CWE_VERDICTS_ENV)
    if raw_override:
        return Path(raw_override).expanduser()
    return Path.home() / ".shieldclaw" / _DEFAULT_CWE_VERDICTS_RESOURCE


def _read_packaged_cwe_verdicts() -> dict[str, Any]:
    """Load the bundled default config shipped inside the package."""
    resource = importlib.resources.files("shieldclaw.triage").joinpath(
        _DEFAULT_CWE_VERDICTS_RESOURCE
    )
    return tomllib.loads(resource.read_text(encoding="utf-8"))


def _read_user_cwe_verdicts(path: Path) -> dict[str, Any]:
    """Load a user-supplied config file from disk."""
    with path.open("rb") as handle:
        return tomllib.load(handle)


def _validate_cwe_verdicts(raw_config: dict[str, Any], *, source: str) -> dict[str, TriageVerdict]:
    """Validate and normalize a parsed CWE verdict config."""
    raw_mappings = raw_config.get("cwe_verdicts")
    if not isinstance(raw_mappings, dict):
        raise ValueError(f"CWE verdict config {source} must define a [cwe_verdicts] table")

    verdicts: dict[str, TriageVerdict] = {}
    for raw_cwe, raw_verdict in raw_mappings.items():
        if not isinstance(raw_cwe, str):
            raise ValueError(f"CWE verdict config {source} has a non-string CWE key")
        if not isinstance(raw_verdict, str):
            raise ValueError(
                f"CWE verdict config {source} must map {raw_cwe!r} to a string verdict"
            )

        cwe_key = raw_cwe.strip().upper()
        if not cwe_key.startswith("CWE-") or not cwe_key[4:].isdigit():
            raise ValueError(
                f"CWE verdict config {source} has invalid CWE key {raw_cwe!r}; "
                "expected CWE-<number>"
            )

        verdict_key = raw_verdict.strip().upper()
        try:
            verdicts[cwe_key] = TriageVerdict(verdict_key)
        except ValueError as exc:
            valid = ", ".join(verdict.value for verdict in TriageVerdict)
            raise ValueError(
                f"CWE verdict config {source} has invalid verdict {raw_verdict!r} for "
                f"{raw_cwe!r}; expected one of: {valid}"
            ) from exc

    return verdicts


def _load_cwe_verdicts() -> dict[str, TriageVerdict]:
    """Load bundled defaults, then overlay a user config when present."""
    merged = _validate_cwe_verdicts(
        _read_packaged_cwe_verdicts(),
        source=f"package resource {_DEFAULT_CWE_VERDICTS_RESOURCE}",
    )

    user_path = _user_cwe_verdicts_path()
    if not user_path.exists():
        return merged

    merged.update(
        _validate_cwe_verdicts(
            _read_user_cwe_verdicts(user_path),
            source=str(user_path),
        )
    )
    return merged


_CWE_VERDICTS = _load_cwe_verdicts()


def classify(finding: Finding) -> TriagedFinding:
    """Classify a ``Finding`` into one of three triage verdicts.

    The classification is pure and deterministic - the same input always
    produces the same output. No network calls, no LLM inference, no I/O
    beyond warning logs for unmapped CWEs.
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

    # Step 3: resolve mapped CWEs conservatively and log unmapped ones.
    mapped_cwes: list[tuple[str, TriageVerdict]] = []
    unmapped_cwes: list[str] = []
    for cwe_raw in finding.cwe:
        cwe_key = normalize_cwe_id(cwe_raw)
        verdict = _CWE_VERDICTS.get(cwe_key)
        if verdict is None:
            unmapped_cwes.append(cwe_key)
        else:
            mapped_cwes.append((cwe_key, verdict))

    if mapped_cwes:
        verdicts = {verdict for _, verdict in mapped_cwes}
        if TriageVerdict.STATIC_ONLY in verdicts:
            detail = ", ".join(f"{cwe}={verdict.value}" for cwe, verdict in mapped_cwes)
            deferred = sorted(
                cwe
                for cwe, verdict in mapped_cwes
                if cwe in _SQLI_ONLY_MVP_DEFERRED_CWES and verdict == TriageVerdict.STATIC_ONLY
            )
            if deferred:
                return TriagedFinding(
                    finding=finding,
                    verdict=TriageVerdict.STATIC_ONLY,
                    reason=(
                        "deferred by SQLi-only MVP boundary; visible but not scored, "
                        "approved, or detonated by default: " + ", ".join(deferred)
                    ),
                )
            return TriagedFinding(
                finding=finding,
                verdict=TriageVerdict.STATIC_ONLY,
                reason=f"mixed/STATIC_ONLY CWE mappings resolved conservatively: {detail}",
            )
        first_cwe, first_verdict = mapped_cwes[0]
        return TriagedFinding(
            finding=finding,
            verdict=first_verdict,
            reason=f"{first_cwe} mapped to {first_verdict.value}",
        )

    if unmapped_cwes:
        _LOG.warning(
            "Unmapped CWE ids for %s defaulting to STATIC_ONLY: %s",
            finding.rule_id,
            ", ".join(unmapped_cwes),
        )

    # Step 4: default fallback.
    return TriagedFinding(
        finding=finding,
        verdict=TriageVerdict.STATIC_ONLY,
        reason="no rule mapped; defaulting to static-only to avoid wasted detonation",
    )
