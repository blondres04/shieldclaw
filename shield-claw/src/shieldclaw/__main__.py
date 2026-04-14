"""Command-line entrypoint for ShieldClaw: loads env, configures logging, runs the pipeline."""

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
_ALLOWED_PROVIDERS: Final[frozenset[str]] = frozenset({"ollama", "openai", "anthropic"})
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

    provider = str(args.provider).lower()
    if provider not in _ALLOWED_PROVIDERS:
        raise CLIValidationError(
            f"Provider must be one of {', '.join(sorted(_ALLOWED_PROVIDERS))}; got {args.provider!r}."
        )

    timeout = int(args.timeout)
    if timeout < 1 or timeout > 120:
        raise CLIValidationError("Timeout must be a positive integer between 1 and 120.")


def _build_parser() -> argparse.ArgumentParser:
    """Construct the top-level CLI parser with a ``run`` subcommand."""
    parser = _ShieldClawArgumentParser(prog="shieldclaw", description="ShieldClaw security scan pipeline.")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="Run the vulnerability scan pipeline.")
    run.add_argument("--target", required=True, help="Path to the repository under test.")
    run.add_argument("--diff", default=None, help="Optional path to a unified diff patch file.")
    run.add_argument(
        "--provider",
        default="ollama",
        help="LLM backend to use (ollama, openai, anthropic).",
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

    try:
        validate_run_configuration(args)
    except CLIValidationError as exc:
        print(exc.message, file=sys.stderr)
        return 1

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
