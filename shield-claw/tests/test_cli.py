"""Tests for ``shieldclaw.__main__`` argument parsing and validation."""

from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from shieldclaw.__main__ import (
    CLIValidationError,
    _build_parser,
    validate_run_configuration,
)


def _run_namespace(**kwargs: object) -> argparse.Namespace:
    defaults = {
        "command": "run",
        "target": str(Path.cwd()),
        "diff": None,
        "provider": "ollama",
        "timeout": 15,
        "output": None,
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def test_parser_requires_run_subcommand() -> None:
    """The top-level parser must demand a subcommand."""
    parser = _build_parser()
    with pytest.raises(SystemExit) as excinfo:
        parser.parse_args([])
    assert excinfo.value.code == 1


def test_parser_run_accepts_expected_flags(tmp_path: Path) -> None:
    """The ``run`` subparser should bind all documented options."""
    (tmp_path / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    (tmp_path / "x.patch").write_text("diff --git\n", encoding="utf-8")
    parser = _build_parser()
    args = parser.parse_args(
        [
            "run",
            "--target",
            str(tmp_path),
            "--diff",
            str(tmp_path / "x.patch"),
            "--provider",
            "anthropic",
            "--timeout",
            "42",
            "--output",
            str(tmp_path / "out.json"),
        ]
    )
    assert args.command == "run"
    assert Path(args.target) == tmp_path
    assert args.provider == "anthropic"
    assert args.timeout == 42
    assert args.output.endswith("out.json")


def test_validate_rejects_missing_target(tmp_path: Path) -> None:
    """Non-existent targets must fail validation."""
    missing = tmp_path / "nope"
    args = _run_namespace(target=str(missing))
    with pytest.raises(CLIValidationError, match="does not exist"):
        validate_run_configuration(args)


def test_validate_rejects_file_target(tmp_path: Path) -> None:
    """A file path must not pass as ``--target``."""
    file_path = tmp_path / "file.txt"
    file_path.write_text("x", encoding="utf-8")
    args = _run_namespace(target=str(file_path))
    with pytest.raises(CLIValidationError, match="not a directory"):
        validate_run_configuration(args)


def test_validate_rejects_missing_compose(tmp_path: Path) -> None:
    """Directories without compose metadata must be rejected."""
    args = _run_namespace(target=str(tmp_path))
    with pytest.raises(CLIValidationError, match="docker-compose"):
        validate_run_configuration(args)


def test_validate_rejects_invalid_provider(tmp_path: Path) -> None:
    """Unknown providers must be rejected explicitly."""
    (tmp_path / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    args = _run_namespace(target=str(tmp_path), provider="unknown")
    with pytest.raises(CLIValidationError, match="Provider must be one of"):
        validate_run_configuration(args)


def test_validate_rejects_timeout_out_of_range(tmp_path: Path) -> None:
    """Timeouts outside 1..120 must fail."""
    (tmp_path / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    args = _run_namespace(target=str(tmp_path), timeout=0)
    with pytest.raises(CLIValidationError, match="Timeout"):
        validate_run_configuration(args)


def test_validate_rejects_empty_diff(tmp_path: Path) -> None:
    """Patch files with zero bytes must be rejected."""
    (tmp_path / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    empty = tmp_path / "empty.patch"
    empty.write_bytes(b"")
    args = _run_namespace(target=str(tmp_path), diff=str(empty))
    with pytest.raises(CLIValidationError, match="empty"):
        validate_run_configuration(args)


def test_validate_accepts_minimal_valid_target(tmp_path: Path) -> None:
    """A directory with compose and default flags should validate."""
    (tmp_path / "docker-compose.yaml").write_text("services: {}\n", encoding="utf-8")
    args = _run_namespace(target=str(tmp_path))
    validate_run_configuration(args)
