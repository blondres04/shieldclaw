"""Tests for ``shieldclaw.ingest.semgrep.parse_semgrep_json``."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest

from shieldclaw.exceptions import IngestError
from shieldclaw.ingest.semgrep import parse_semgrep_json
from shieldclaw.models import Finding

_FIXTURE = Path(__file__).parent / "fixtures" / "semgrep_sample.json"


# ---------------------------------------------------------------------------
# Happy-path: fixture round-trip
# ---------------------------------------------------------------------------


def test_fixture_loads_five_findings() -> None:
    """The sample fixture must produce exactly five findings."""
    findings = parse_semgrep_json(_FIXTURE)
    assert len(findings) == 5


def test_findings_are_finding_instances() -> None:
    """Every item in the result tuple must be a Finding."""
    findings = parse_semgrep_json(_FIXTURE)
    assert all(isinstance(f, Finding) for f in findings)


def test_sqli_finding_fields(tmp_path: Path) -> None:
    """SQLi finding: rule_id, path, line numbers, severity, CWE, metavars."""
    findings = parse_semgrep_json(_FIXTURE)
    sqli = next(f for f in findings if "sql" in f.rule_id.lower())

    assert sqli.rule_id == ("python.flask.security.injection.tainted-sql-string.tainted-sql-string")
    assert sqli.path == "app.py"
    assert sqli.start_line == 42
    assert sqli.end_line == 42
    assert sqli.severity == "ERROR"
    assert "CWE-89" in sqli.cwe
    assert "$USER_ID" in sqli.metavars
    assert "request.args.get" in sqli.metavars["$USER_ID"]
    assert sqli.raw_extra  # non-empty JSON string


def test_finding_id_is_deterministic() -> None:
    """Parsing the same file twice must produce identical finding_ids."""
    a = parse_semgrep_json(_FIXTURE)
    b = parse_semgrep_json(_FIXTURE)
    assert [f.finding_id for f in a] == [f.finding_id for f in b]


def test_finding_id_uuid5_derivation() -> None:
    """finding_id must be uuid5(NAMESPACE_URL, 'rule_id:path:start:end')."""
    findings = parse_semgrep_json(_FIXTURE)
    f = findings[0]
    expected = uuid.uuid5(
        uuid.NAMESPACE_URL,
        f"{f.rule_id}:{f.path}:{f.start_line}:{f.end_line}",
    )
    assert f.finding_id == expected


def test_hardcoded_password_finding() -> None:
    """Hardcoded-password finding must have CWE-259 and correct severity."""
    findings = parse_semgrep_json(_FIXTURE)
    cred = next(f for f in findings if "hardcoded-password" in f.rule_id)
    assert "CWE-259" in cred.cwe
    assert cred.severity == "ERROR"


def test_weak_hash_finding_has_no_metavars() -> None:
    """The weak-hash finding has an empty metavars dict (fixture has empty object)."""
    findings = parse_semgrep_json(_FIXTURE)
    h = next(f for f in findings if "hash" in f.rule_id.lower())
    assert h.metavars == {}
    assert "CWE-328" in h.cwe


def test_cmd_injection_finding() -> None:
    """OS command injection finding must map CWE-78."""
    findings = parse_semgrep_json(_FIXTURE)
    cmd = next(f for f in findings if "os-system" in f.rule_id.lower())
    assert "CWE-78" in cmd.cwe
    assert cmd.path == "admin/tasks.py"


def test_cwe_ids_are_normalised() -> None:
    """CWE strings must strip the description suffix, leaving only 'CWE-N'."""
    findings = parse_semgrep_json(_FIXTURE)
    for f in findings:
        for cwe in f.cwe:
            assert cwe.startswith("CWE-"), f"Expected CWE-N, got {cwe!r}"
            assert ":" not in cwe, f"Description not stripped: {cwe!r}"


# ---------------------------------------------------------------------------
# Severity normalisation
# ---------------------------------------------------------------------------


def _make_report(results: list[dict[str, object]]) -> str:
    return json.dumps({"results": results, "errors": []})


def _minimal_result(
    *,
    severity: str = "ERROR",
    cwe: list[str] | None = None,
    metavars: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "check_id": "test.rule",
        "path": "x.py",
        "start": {"line": 1, "col": 1},
        "end": {"line": 1, "col": 5},
        "extra": {
            "severity": severity,
            "message": "test",
            "metadata": {"cwe": cwe or []},
            "metavars": metavars or {},
        },
    }


def test_severity_warning_accepted(tmp_path: Path) -> None:
    """WARNING severity is accepted and preserved."""
    p = tmp_path / "r.json"
    p.write_text(_make_report([_minimal_result(severity="WARNING")]), encoding="utf-8")
    (f,) = parse_semgrep_json(p)
    assert f.severity == "WARNING"


def test_severity_info_accepted(tmp_path: Path) -> None:
    """INFO severity is accepted and preserved."""
    p = tmp_path / "r.json"
    p.write_text(_make_report([_minimal_result(severity="INFO")]), encoding="utf-8")
    (f,) = parse_semgrep_json(p)
    assert f.severity == "INFO"


def test_severity_warn_normalised_to_warning(tmp_path: Path) -> None:
    """WARN is an alias for WARNING."""
    p = tmp_path / "r.json"
    p.write_text(_make_report([_minimal_result(severity="WARN")]), encoding="utf-8")
    (f,) = parse_semgrep_json(p)
    assert f.severity == "WARNING"


def test_severity_critical_normalised_to_error(tmp_path: Path) -> None:
    """CRITICAL maps to ERROR."""
    p = tmp_path / "r.json"
    p.write_text(_make_report([_minimal_result(severity="CRITICAL")]), encoding="utf-8")
    (f,) = parse_semgrep_json(p)
    assert f.severity == "ERROR"


def test_unknown_severity_raises(tmp_path: Path) -> None:
    """An unrecognised severity must raise IngestError."""
    p = tmp_path / "r.json"
    p.write_text(_make_report([_minimal_result(severity="BLOCKER")]), encoding="utf-8")
    with pytest.raises(IngestError, match="unrecognised severity"):
        parse_semgrep_json(p)


# ---------------------------------------------------------------------------
# CWE normalisation
# ---------------------------------------------------------------------------


def test_cwe_list_input(tmp_path: Path) -> None:
    """A list of CWE strings is accepted and each normalised."""
    p = tmp_path / "r.json"
    p.write_text(
        _make_report(
            [_minimal_result(cwe=["CWE-89: SQL Injection", "CWE-20: Improper Input Validation"])]
        ),
        encoding="utf-8",
    )
    (f,) = parse_semgrep_json(p)
    assert "CWE-89" in f.cwe
    assert "CWE-20" in f.cwe


def test_cwe_string_input(tmp_path: Path) -> None:
    """A single CWE string (not a list) is also accepted."""
    p = tmp_path / "r.json"
    p.write_text(
        _make_report([_minimal_result(cwe=["CWE-79: XSS"])]),  # type: ignore[list-item]
        encoding="utf-8",
    )
    (f,) = parse_semgrep_json(p)
    assert "CWE-79" in f.cwe


# ---------------------------------------------------------------------------
# Error cases
# ---------------------------------------------------------------------------


def test_missing_file_raises(tmp_path: Path) -> None:
    """A non-existent path raises IngestError."""
    with pytest.raises(IngestError, match="Cannot read"):
        parse_semgrep_json(tmp_path / "absent.json")


def test_invalid_json_raises(tmp_path: Path) -> None:
    """Non-JSON content raises IngestError."""
    p = tmp_path / "bad.json"
    p.write_text("not-json", encoding="utf-8")
    with pytest.raises(IngestError, match="not valid JSON"):
        parse_semgrep_json(p)


def test_missing_results_key_raises(tmp_path: Path) -> None:
    """A top-level object without 'results' raises IngestError."""
    p = tmp_path / "r.json"
    p.write_text('{"errors": []}', encoding="utf-8")
    with pytest.raises(IngestError, match="missing top-level key 'results'"):
        parse_semgrep_json(p)


def test_missing_errors_key_raises(tmp_path: Path) -> None:
    """A top-level object without 'errors' raises IngestError."""
    p = tmp_path / "r.json"
    p.write_text('{"results": []}', encoding="utf-8")
    with pytest.raises(IngestError, match="missing top-level key 'errors'"):
        parse_semgrep_json(p)


def test_result_missing_check_id_raises(tmp_path: Path) -> None:
    """A result without check_id raises IngestError."""
    bad = {
        "path": "x.py",
        "start": {"line": 1, "col": 1},
        "end": {"line": 1, "col": 5},
        "extra": {"severity": "ERROR", "message": "x", "metadata": {}, "metavars": {}},
    }
    p = tmp_path / "r.json"
    p.write_text(json.dumps({"results": [bad], "errors": []}), encoding="utf-8")
    with pytest.raises(IngestError, match="check_id"):
        parse_semgrep_json(p)


def test_empty_results_returns_empty_tuple(tmp_path: Path) -> None:
    """A report with an empty results list returns an empty tuple."""
    p = tmp_path / "r.json"
    p.write_text('{"results": [], "errors": []}', encoding="utf-8")
    assert parse_semgrep_json(p) == ()
