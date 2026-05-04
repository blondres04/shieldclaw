"""Tests for ``shieldclaw.triage.classifier.classify``."""

from __future__ import annotations

import importlib
import uuid
from pathlib import Path
from typing import Literal

import pytest

from shieldclaw.models import Finding, TriagedFinding, TriageVerdict
from shieldclaw.triage import classifier as classifier_module
from shieldclaw.triage.classifier import classify

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SEVERITY = Literal["INFO", "WARNING", "ERROR"]


def _finding(
    *,
    rule_id: str = "test.rule",
    severity: str = "ERROR",
    cwe: tuple[str, ...] = (),
    path: str = "app.py",
) -> Finding:
    return Finding(
        finding_id=uuid.uuid5(uuid.NAMESPACE_URL, f"{rule_id}:{path}:1:1"),
        rule_id=rule_id,
        severity=severity,  # type: ignore[arg-type]
        path=path,
        start_line=1,
        end_line=1,
        message="test finding",
        cwe=cwe,
        metavars={},
        raw_extra="{}",
    )


# ---------------------------------------------------------------------------
# Parametrised: 20 findings covering all three verdict buckets
# ---------------------------------------------------------------------------

_CASES: list[tuple[str, Finding, TriageVerdict]] = [
    # --- DYNAMICALLY_VERIFIABLE (10) ---
    (
        "sqli",
        _finding(rule_id="python.flask.sqli", cwe=("CWE-89",)),
        TriageVerdict.DYNAMICALLY_VERIFIABLE,
    ),
    (
        "xss",
        _finding(rule_id="python.jinja2.xss", cwe=("CWE-79",)),
        TriageVerdict.DYNAMICALLY_VERIFIABLE,
    ),
    (
        "cmd_injection",
        _finding(rule_id="python.os.cmd-injection", cwe=("CWE-78",)),
        TriageVerdict.DYNAMICALLY_VERIFIABLE,
    ),
    (
        "code_injection",
        _finding(rule_id="python.eval.code-injection", cwe=("CWE-94",)),
        TriageVerdict.DYNAMICALLY_VERIFIABLE,
    ),
    (
        "ssrf",
        _finding(rule_id="python.requests.ssrf", cwe=("CWE-918",)),
        TriageVerdict.DYNAMICALLY_VERIFIABLE,
    ),
    (
        "path_traversal",
        _finding(rule_id="python.pathlib.traversal", cwe=("CWE-22",)),
        TriageVerdict.DYNAMICALLY_VERIFIABLE,
    ),
    (
        "csrf",
        _finding(rule_id="python.flask.csrf", cwe=("CWE-352",)),
        TriageVerdict.DYNAMICALLY_VERIFIABLE,
    ),
    (
        "xxe",
        _finding(rule_id="python.xml.xxe", cwe=("CWE-611",)),
        TriageVerdict.DYNAMICALLY_VERIFIABLE,
    ),
    (
        "deserialization",
        _finding(rule_id="python.pickle.deser", cwe=("CWE-502",)),
        TriageVerdict.DYNAMICALLY_VERIFIABLE,
    ),
    (
        "open_redirect",
        _finding(rule_id="python.flask.redirect", cwe=("CWE-601",)),
        TriageVerdict.DYNAMICALLY_VERIFIABLE,
    ),
    # --- STATIC_ONLY (5) ---
    (
        "weak_hash",
        _finding(rule_id="python.crypto.md5", cwe=("CWE-328",)),
        TriageVerdict.STATIC_ONLY,
    ),
    (
        "weak_crypto_algo",
        _finding(rule_id="python.crypto.des", cwe=("CWE-327",)),
        TriageVerdict.STATIC_ONLY,
    ),
    (
        "insecure_random",
        _finding(rule_id="python.random.weak", cwe=("CWE-330",)),
        TriageVerdict.STATIC_ONLY,
    ),
    (
        "hardcoded_creds",
        _finding(rule_id="python.secrets.hardcoded", cwe=("CWE-798",)),
        TriageVerdict.STATIC_ONLY,
    ),
    (
        "hardcoded_password",
        _finding(rule_id="python.password.literal", cwe=("CWE-259",)),
        TriageVerdict.STATIC_ONLY,
    ),
    # --- OUT_OF_SCOPE (5) ---
    (
        "dockerfile_rule",
        _finding(rule_id="dockerfile.security.apt-get-upgrade"),
        TriageVerdict.OUT_OF_SCOPE,
    ),
    (
        "terraform_rule",
        _finding(rule_id="terraform.aws.s3-public-access"),
        TriageVerdict.OUT_OF_SCOPE,
    ),
    (
        "kubernetes_rule",
        _finding(rule_id="kubernetes.pod-security-context"),
        TriageVerdict.OUT_OF_SCOPE,
    ),
    (
        "secrets_rule",
        _finding(rule_id="secrets.aws.access-key"),
        TriageVerdict.OUT_OF_SCOPE,
    ),
    (
        "info_no_cwe",
        _finding(rule_id="python.best-practice.info-note", severity="INFO", cwe=()),
        TriageVerdict.OUT_OF_SCOPE,
    ),
]


@pytest.mark.parametrize(
    "label,finding,expected_verdict",
    _CASES,
    ids=[c[0] for c in _CASES],
)
def test_classifier_buckets_correctly(
    label: str, finding: Finding, expected_verdict: TriageVerdict
) -> None:
    """Every test case must receive the expected triage verdict."""
    result = classify(finding)
    assert isinstance(result, TriagedFinding)
    assert result.finding is finding
    assert result.verdict == expected_verdict, (
        f"[{label}] expected {expected_verdict.value}, got {result.verdict.value}: {result.reason}"
    )


def test_at_least_18_of_20_correctly_bucketed() -> None:
    """Guard: at least 18 of the 20 parametrised cases must classify correctly."""
    correct = sum(1 for _, finding, expected in _CASES if classify(finding).verdict == expected)
    assert correct >= 18, f"Only {correct}/20 findings classified correctly"


# ---------------------------------------------------------------------------
# Unit tests for specific classifier rules
# ---------------------------------------------------------------------------


def test_returns_triaged_finding_type() -> None:
    """classify must always return a TriagedFinding."""
    result = classify(_finding(cwe=("CWE-89",)))
    assert isinstance(result, TriagedFinding)


def test_finding_reference_preserved() -> None:
    """The original Finding must be preserved in TriagedFinding.finding."""
    f = _finding(cwe=("CWE-89",))
    assert classify(f).finding is f


def test_reason_is_non_empty() -> None:
    """Every classification must produce a non-empty reason string."""
    for _, f, _ in _CASES:
        assert classify(f).reason, f"Empty reason for {f.rule_id}"


def test_default_fallback_is_static_only() -> None:
    """A finding with no CWE and no out-of-scope prefix defaults to STATIC_ONLY."""
    f = _finding(rule_id="python.custom.unknown", severity="WARNING", cwe=())
    result = classify(f)
    assert result.verdict == TriageVerdict.STATIC_ONLY
    assert "no rule mapped" in result.reason


def test_info_severity_with_cwe_is_not_out_of_scope() -> None:
    """INFO + known CWE must NOT be OUT_OF_SCOPE; it gets the CWE-mapped verdict."""
    f = _finding(rule_id="python.rule", severity="INFO", cwe=("CWE-89",))
    result = classify(f)
    assert result.verdict == TriageVerdict.DYNAMICALLY_VERIFIABLE


def test_multi_cwe_conflict_resolves_conservatively_to_static_only() -> None:
    """Mixed DV + STATIC_ONLY CWE mappings must resolve to STATIC_ONLY."""
    f = _finding(cwe=("CWE-89", "CWE-798"))
    result = classify(f)
    assert result.verdict == TriageVerdict.STATIC_ONLY
    assert "STATIC_ONLY" in result.reason


def test_unmapped_cwe_defaults_static_only_and_logs_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Unknown CWEs should default to STATIC_ONLY and emit a warning for operators."""
    f = _finding(cwe=("CWE-9999",))
    with caplog.at_level("WARNING"):
        result = classify(f)
    assert result.verdict == TriageVerdict.STATIC_ONLY
    assert "CWE-9999" in caplog.text
    assert "unmapped" in caplog.text.lower()


def test_license_prefix_is_out_of_scope() -> None:
    """Rules prefixed with 'license.' must be OUT_OF_SCOPE."""
    f = _finding(rule_id="license.gpl.compliance", cwe=("CWE-89",))
    result = classify(f)
    assert result.verdict == TriageVerdict.OUT_OF_SCOPE


def test_cwe_with_description_suffix_normalised() -> None:
    """CWE ids still containing the description suffix must be stripped."""
    f = _finding(cwe=("CWE-89: SQL Injection (see OWASP Top 10)",))
    result = classify(f)
    assert result.verdict == TriageVerdict.DYNAMICALLY_VERIFIABLE


def _reload_classifier() -> None:
    """Reload the classifier module so import-time config is re-evaluated."""
    importlib.reload(classifier_module)


def test_custom_cwe_config_extends_default_mapping(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A user config file may add new CWE mappings without editing source code."""
    config_path = tmp_path / "cwe_verdicts.toml"
    config_path.write_text(
        '[cwe_verdicts]\n"CWE-1337" = "DYNAMICALLY_VERIFIABLE"\n',
        encoding="utf-8",
    )

    monkeypatch.setenv("SHIELDCLAW_CWE_VERDICTS_PATH", str(config_path))
    _reload_classifier()
    try:
        custom = _finding(cwe=("CWE-1337",))
        default = _finding(cwe=("CWE-89",))

        assert classify(custom).verdict == TriageVerdict.DYNAMICALLY_VERIFIABLE
        assert classify(default).verdict == TriageVerdict.DYNAMICALLY_VERIFIABLE
    finally:
        monkeypatch.delenv("SHIELDCLAW_CWE_VERDICTS_PATH", raising=False)
        _reload_classifier()


def test_missing_user_cwe_config_falls_back_to_bundled_defaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A missing user config must not break triage; bundled defaults still apply."""
    missing_path = tmp_path / "missing.toml"
    monkeypatch.setenv("SHIELDCLAW_CWE_VERDICTS_PATH", str(missing_path))
    _reload_classifier()
    try:
        result = classify(_finding(cwe=("CWE-89",)))
        assert result.verdict == TriageVerdict.DYNAMICALLY_VERIFIABLE
    finally:
        monkeypatch.delenv("SHIELDCLAW_CWE_VERDICTS_PATH", raising=False)
        _reload_classifier()


def test_malformed_user_cwe_config_fails_fast(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Malformed config should raise immediately when the classifier loads."""
    config_path = tmp_path / "cwe_verdicts.toml"
    config_path.write_text('[cwe_verdicts]\n"CWE-89" = 123\n', encoding="utf-8")

    monkeypatch.setenv("SHIELDCLAW_CWE_VERDICTS_PATH", str(config_path))
    try:
        with pytest.raises(ValueError, match="CWE verdict"):
            _reload_classifier()
    finally:
        monkeypatch.delenv("SHIELDCLAW_CWE_VERDICTS_PATH", raising=False)
        _reload_classifier()
