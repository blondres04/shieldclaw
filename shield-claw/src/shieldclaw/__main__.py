"""
File:        src/shieldclaw/__main__.py
Purpose:     CLI entry point — parses arguments, validates inputs, and dispatches to Orchestrator.
Public API:
  - CLIValidationError (exception class, raised for invalid CLI arguments)
  - validate_run_configuration(args: Namespace) -> None
  - main(argv: list[str] | None = None) -> int
Depends On:
  - dotenv (load_dotenv)
  - shieldclaw.ingest (parse_semgrep_json)
  - shieldclaw.orchestrator (Orchestrator)
  - shieldclaw.triage (classify)
Used By:
  - Python runtime (python -m shieldclaw)
Use Cases:
  - SCAN-001 (Run Vulnerability Scan)
  - SCAN-002 (Ingest and Triage SAST Findings)
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from argparse import Namespace
from pathlib import Path
from typing import Final, NoReturn

from dotenv import load_dotenv

from shieldclaw.orchestrator import Orchestrator

_COMPOSE_NAMES: Final[tuple[str, ...]] = ("docker-compose.yml", "docker-compose.yaml")
# Only Ollama is implemented. OpenAI and Anthropic will be re-added in Phase 4.
_ALLOWED_PROVIDERS: Final[frozenset[str]] = frozenset({"ollama"})
_LOG = logging.getLogger(__name__)


class CLIValidationError(Exception):
    """Raised when user-supplied arguments fail validation before the pipeline runs."""

    def __init__(self, message: str) -> None:
        self.message: str = message
        super().__init__(message)


class _ShieldClawArgumentParser(argparse.ArgumentParser):
    """Argument parser that maps usage errors to exit code ``1``."""

    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        self.exit(1, f"{self.prog}: error: {message}\n")


def _configure_logging() -> None:
    """Attach a stderr handler using ``SHIELDCLAW_LOG_LEVEL`` (default ``INFO``)."""
    raw = os.environ.get("SHIELDCLAW_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, raw, logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stderr,
        force=True,
    )


def validate_run_configuration(args: Namespace) -> None:
    """Validate ``run`` subcommand arguments beyond what ``argparse`` enforces.

    Args:
        args: Parsed namespace for the ``run`` command.

    Raises:
        CLIValidationError: When filesystem or logical checks fail.
    """
    target = Path(args.target).expanduser()
    if not target.exists():
        raise CLIValidationError(f"Target path does not exist: {args.target}")
    if not target.is_dir():
        raise CLIValidationError(f"Target path is not a directory: {args.target}")
    resolved = target.resolve()
    if not any((resolved / name).is_file() for name in _COMPOSE_NAMES):
        raise CLIValidationError(
            f"Target directory must contain one of: {', '.join(_COMPOSE_NAMES)}"
        )

    if args.diff is not None:
        diff_path = Path(args.diff).expanduser()
        if not diff_path.exists():
            raise CLIValidationError(f"Diff file does not exist: {args.diff}")
        if not diff_path.is_file():
            raise CLIValidationError(f"Diff path is not a file: {args.diff}")
        if diff_path.stat().st_size == 0:
            raise CLIValidationError(f"Diff file is empty: {args.diff}")

    semgrep_output: str | None = getattr(args, "semgrep_output", None)
    if semgrep_output is not None:
        sp = Path(semgrep_output).expanduser()
        if not sp.exists():
            raise CLIValidationError(f"Semgrep output file does not exist: {semgrep_output}")
        if not sp.is_file():
            raise CLIValidationError(f"Semgrep output path is not a file: {semgrep_output}")
        if not sp.stat().st_size:
            raise CLIValidationError(f"Semgrep output file is empty: {semgrep_output}")

    provider = str(args.provider).lower()
    if provider not in _ALLOWED_PROVIDERS:
        raise CLIValidationError(
            f"Only {', '.join(sorted(_ALLOWED_PROVIDERS))} is supported in this release; "
            f"got {args.provider!r}. OpenAI and Anthropic land in Phase 4."
        )

    timeout = int(args.timeout)
    if timeout < 1 or timeout > 120:
        raise CLIValidationError("Timeout must be a positive integer between 1 and 120.")


def _print_triage_summary(semgrep_path: str) -> None:
    """Ingest a Semgrep report, classify all findings, and print a summary to stderr.

    This is a Phase 1 preview: the findings are not yet plumbed into the
    orchestrator pipeline (that happens in Phase 2).

    Args:
        semgrep_path: Filesystem path to the Semgrep ``--json`` output file.
    """
    from shieldclaw.exceptions import IngestError
    from shieldclaw.ingest.semgrep import parse_semgrep_json
    from shieldclaw.triage.classifier import classify

    try:
        findings = parse_semgrep_json(Path(semgrep_path))
    except IngestError as exc:
        _LOG.error("Failed to ingest Semgrep report: %s", exc.message)
        return

    triaged = [classify(f) for f in findings]

    print(
        f"\n[ShieldClaw] Semgrep triage: {len(triaged)} findings\n",
        file=sys.stderr,
    )
    for tf in triaged:
        verdict_tag = tf.verdict.value
        print(
            f"  [{verdict_tag:24s}] {tf.finding.rule_id}\n"
            f"    {tf.finding.path}:{tf.finding.start_line}  {tf.reason}",
            file=sys.stderr,
        )
    print("", file=sys.stderr)


def _build_parser() -> argparse.ArgumentParser:
    """Construct the top-level CLI parser with a ``run`` subcommand."""
    parser = _ShieldClawArgumentParser(
        prog="shieldclaw", description="ShieldClaw security scan pipeline."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="Run the vulnerability scan pipeline.")
    run.add_argument("--target", required=True, help="Path to the repository under test.")
    run.add_argument("--diff", default=None, help="Optional path to a unified diff patch file.")
    run.add_argument(
        "--semgrep-output",
        dest="semgrep_output",
        default=None,
        metavar="PATH",
        help=(
            "Path to a Semgrep --json report.  Findings are triaged and printed to "
            "stderr before the exploit pipeline runs.  Mutually exclusive with --diff "
            "(both accepted in Phase 1 with a warning; Phase 2 will integrate findings)."
        ),
    )
    run.add_argument(
        "--provider",
        default="ollama",
        help="LLM backend to use. Currently: ollama. (openai/anthropic land in Phase 4)",
    )
    run.add_argument(
        "--timeout",
        type=int,
        default=15,
        help="Detonation timeout in seconds (1-120).",
    )
    run.add_argument(
        "--output",
        default=None,
        help="Write JSON report to this path instead of stdout.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Parse CLI arguments, validate inputs, and execute the orchestrator.

    Args:
        argv: Optional argument vector (defaults to ``sys.argv`` tail).

    Returns:
        ``0`` on successful completion, ``1`` on validation or fatal errors.
    """
    load_dotenv()
    _configure_logging()
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command != "run":
        parser.error(f"unknown command {args.command!r}")

    # Warn when --diff and --semgrep-output are both supplied.
    semgrep_output: str | None = getattr(args, "semgrep_output", None)
    if args.diff is not None and semgrep_output is not None:
        _LOG.warning(
            "--diff and --semgrep-output were both supplied.  "
            "In Phase 1 both are accepted; Phase 2 will integrate findings into the "
            "pipeline and may change this behaviour."
        )

    try:
        validate_run_configuration(args)
    except CLIValidationError as exc:
        print(exc.message, file=sys.stderr)
        return 1

    # Phase 1: ingest and triage before the exploit pipeline.
    if semgrep_output is not None:
        _print_triage_summary(semgrep_output)

    try:
        Orchestrator().run(
            str(Path(args.target).expanduser().resolve()),
            args.diff,
            str(args.provider).lower(),
            int(args.timeout),
            args.output,
        )
    except Exception as exc:  # noqa: BLE001 - CLI safety net per product spec
        _LOG.critical("Unhandled failure during orchestration: %s", exc, exc_info=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
