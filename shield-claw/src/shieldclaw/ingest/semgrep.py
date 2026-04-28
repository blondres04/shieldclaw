"""Parse Semgrep JSON output into immutable Finding records.

Semgrep's ``--json`` output schema (v1.x)::

    {
        "results": [ <result>, ... ],
        "errors":  [ <error>,  ... ]
    }

Each result has the shape::

    {
        "check_id": "python.flask.security.sqli",
        "path":     "app/views.py",
        "start":    {"line": 42, "col": 5},
        "end":      {"line": 42, "col": 77},
        "extra": {
            "severity": "ERROR",
            "message":  "SQL injection ...",
            "metadata": {"cwe": ["CWE-89: ..."], ...},
            "metavars": {
                "$VAR": {"abstract_content": "request.args.get('id')", ...}
            }
        }
    }

Public API
----------
- ``parse_semgrep_json(path: Path) -> tuple[Finding, ...]``
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from shieldclaw.exceptions import IngestError
from shieldclaw.models import Finding

# Normalise severity strings that Semgrep may emit.
_SEVERITY_MAP: dict[str, str] = {
    "INFO": "INFO",
    "WARNING": "WARNING",
    "WARN": "WARNING",
    "ERROR": "ERROR",
    "CRITICAL": "ERROR",
}

# Pattern to extract the canonical CWE identifier from a descriptive string such as
# "CWE-89: Improper Neutralisation of Special Elements ..."
_CWE_RE = re.compile(r"(CWE-\d+)", re.IGNORECASE)


def _extract_cwe_id(raw: str) -> str:
    """Return the canonical ``CWE-N`` prefix from a descriptive CWE string."""
    m = _CWE_RE.search(raw)
    return m.group(1).upper() if m else raw.strip()


def _normalise_cwe(raw: object) -> tuple[str, ...]:
    """Convert ``extra.metadata.cwe`` (str, list, or absent) to a CWE id tuple."""
    if raw is None:
        return ()
    if isinstance(raw, str):
        return (_extract_cwe_id(raw),)
    if isinstance(raw, list):
        return tuple(_extract_cwe_id(str(item)) for item in raw if str(item).strip())
    return ()


def _normalise_severity(raw: object, rule_id: str) -> str:
    """Map a raw Semgrep severity string to one of INFO / WARNING / ERROR."""
    if not isinstance(raw, str):
        raise IngestError(
            f"finding '{rule_id}': expected string for extra.severity, got {type(raw).__name__}"
        )
    mapped = _SEVERITY_MAP.get(raw.upper())
    if mapped is None:
        raise IngestError(
            f"finding '{rule_id}': unrecognised severity {raw!r}; expected INFO, WARNING, or ERROR"
        )
    return mapped


def _flatten_metavars(raw: object) -> dict[str, str]:
    """Flatten ``extra.metavars`` to ``{name: abstract_content}``."""
    if not isinstance(raw, dict):
        return {}
    result: dict[str, str] = {}
    for name, info in raw.items():
        if isinstance(info, dict):
            content = info.get("abstract_content")
            if isinstance(content, str):
                result[str(name)] = content
    return result


def _parse_result(raw: Any, idx: int) -> Finding:
    """Convert a single Semgrep result object to a ``Finding``.

    Args:
        raw: Parsed JSON object for one result entry.
        idx: Zero-based index in the results list (used in error messages).

    Raises:
        IngestError: On any structural or value problem.
    """
    if not isinstance(raw, dict):
        raise IngestError(f"results[{idx}] is not an object")

    def _req(obj: dict[str, Any], key: str, ctx: str) -> Any:
        if key not in obj:
            raise IngestError(f"{ctx}: missing required key {key!r}")
        return obj[key]

    rule_id = _req(raw, "check_id", f"results[{idx}]")
    if not isinstance(rule_id, str) or not rule_id:
        raise IngestError(f"results[{idx}].check_id must be a non-empty string")

    path = _req(raw, "path", f"results[{idx}]")
    if not isinstance(path, str):
        raise IngestError(f"results[{idx}].path must be a string")

    start = _req(raw, "start", f"results[{idx}]")
    end = _req(raw, "end", f"results[{idx}]")
    if not isinstance(start, dict) or not isinstance(end, dict):
        raise IngestError(f"results[{idx}]: start/end must be objects")

    start_line_raw = _req(start, "line", f"results[{idx}].start")
    end_line_raw = _req(end, "line", f"results[{idx}].end")
    if not isinstance(start_line_raw, int) or not isinstance(end_line_raw, int):
        raise IngestError(f"results[{idx}]: start.line and end.line must be integers")
    start_line: int = start_line_raw
    end_line: int = end_line_raw

    extra = _req(raw, "extra", f"results[{idx}]")
    if not isinstance(extra, dict):
        raise IngestError(f"results[{idx}].extra must be an object")

    severity = _normalise_severity(extra.get("severity", "WARNING"), rule_id)
    message_raw = extra.get("message", "")
    message = str(message_raw) if message_raw is not None else ""

    metadata = extra.get("metadata") or {}
    cwe = _normalise_cwe(metadata.get("cwe") if isinstance(metadata, dict) else None)

    metavars = _flatten_metavars(extra.get("metavars"))

    try:
        raw_extra = json.dumps(extra, ensure_ascii=False, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise IngestError(f"results[{idx}]: could not serialise extra field: {exc}") from exc

    finding_id = uuid5(NAMESPACE_URL, f"{rule_id}:{path}:{start_line}:{end_line}")

    # severity is guaranteed by _normalise_severity to be one of the three literals.
    from typing import Literal, cast

    return Finding(
        finding_id=finding_id,
        rule_id=rule_id,
        severity=cast(Literal["INFO", "WARNING", "ERROR"], severity),
        path=path,
        start_line=start_line,
        end_line=end_line,
        message=message,
        cwe=cwe,
        metavars=metavars,
        raw_extra=raw_extra,
    )


def parse_semgrep_json(path: Path) -> tuple[Finding, ...]:
    """Parse a Semgrep ``--json`` output file into an immutable tuple of Findings.

    Args:
        path: Filesystem path to the Semgrep JSON report.

    Returns:
        Tuple of ``Finding`` instances, one per result entry.  May be empty if
        the report contains no results.

    Raises:
        IngestError: When the file cannot be read, is not valid JSON, or the
            Semgrep schema is not satisfied.  Never raises raw ``KeyError``,
            ``ValueError``, or ``json.JSONDecodeError`` across this boundary.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise IngestError(f"Cannot read Semgrep report {path}: {exc}") from exc

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise IngestError(f"Semgrep report {path} is not valid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise IngestError(f"Semgrep report {path}: top-level value must be an object")

    if "results" not in data:
        raise IngestError(f"Semgrep report {path}: missing top-level key 'results'")
    if "errors" not in data:
        raise IngestError(f"Semgrep report {path}: missing top-level key 'errors'")

    results = data["results"]
    if not isinstance(results, list):
        raise IngestError(f"Semgrep report {path}: 'results' must be a list")

    findings: list[Finding] = []
    for idx, raw in enumerate(results):
        try:
            findings.append(_parse_result(raw, idx))
        except IngestError:
            raise
        except Exception as exc:
            raise IngestError(f"results[{idx}]: unexpected parse error: {exc}") from exc

    return tuple(findings)
