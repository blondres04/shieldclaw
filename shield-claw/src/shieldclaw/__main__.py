"""
File:        src/shieldclaw/__main__.py
Purpose:     CLI entry point — parses arguments, validates inputs, and dispatches to Orchestrator.
Public API:
  - CLIValidationError (exception class, raised for invalid CLI arguments)
  - validate_run_configuration(args: Namespace) -> None
  - main(argv: list[str] | None = None) -> int
Depends On:
  - dotenv (load_dotenv)
  - shieldclaw.orchestrator (Orchestrator)
  - shieldclaw.persistence.store (ScanStore) — for status subcommand
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
_OUTPUT_FORMATS: Final[tuple[str, ...]] = ("json", "sarif", "markdown")
# ollama: local inference; openai: hosted via OPENAI_API_KEY.
# Anthropic provider is not yet implemented; planned for v0.3.
_ALLOWED_PROVIDERS: Final[frozenset[str]] = frozenset({"ollama", "openai"})
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
            f"Provider must be one of {', '.join(sorted(_ALLOWED_PROVIDERS))}; "
            f"got {args.provider!r}."
        )

    timeout = int(args.timeout)
    if timeout < 1 or timeout > 120:
        raise CLIValidationError("Timeout must be a positive integer between 1 and 120.")

    if getattr(args, "interactive", False) and os.environ.get("SHIELDCLAW_AUTO_APPROVE") == "1":
        raise CLIValidationError(
            "--interactive and SHIELDCLAW_AUTO_APPROVE=1 are mutually exclusive."
        )


def _print_triage_summary(semgrep_path: str) -> None:
    """Ingest a Semgrep report, classify all findings, and print a summary to stderr."""
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


def _run_status(args: Namespace) -> int:
    """Print a summary of all persisted scans to stdout.

    If ``--scan-id`` is provided only that scan is shown; otherwise all scans
    for the current working directory are listed, falling back to all scans
    when none match.
    """
    from shieldclaw.persistence.store import ScanStore

    target_dir = getattr(args, "target", None) or str(Path.cwd())
    scan_id_filter: str | None = getattr(args, "scan_id", None)

    store = ScanStore(target_dir)

    if scan_id_filter:
        row = store.load_scan(scan_id_filter)
        scans = [row] if row is not None else []
    else:
        scans = store.list_scans(target_dir)
        if not scans:
            scans = store.list_scans()  # fall back to all scans

    if not scans:
        print("No persisted scans found.", file=sys.stderr)
        return 0

    col_w = (36, 30, 12, 24)
    header = (
        f"{'SCAN ID':<{col_w[0]}}  "
        f"{'TARGET':<{col_w[1]}}  "
        f"{'STATE':<{col_w[2]}}  "
        f"{'CREATED':<{col_w[3]}}"
    )
    print(header)
    print("-" * (sum(col_w) + 6))

    for scan in scans:
        counts = store.count_findings_by_state(scan.scan_id)
        count_str = " ".join(f"{s}:{n}" for s, n in sorted(counts.items())) or "—"
        target_short = (
            scan.target_dir[-col_w[1] :] if len(scan.target_dir) > col_w[1] else scan.target_dir
        )
        print(
            f"{scan.scan_id:<{col_w[0]}}  "
            f"{target_short:<{col_w[1]}}  "
            f"{scan.state:<{col_w[2]}}  "
            f"{scan.created_at[:19]:<{col_w[3]}}"
        )
        print(f"  findings: {count_str}")

    return 0


def _build_parser() -> argparse.ArgumentParser:
    """Construct the top-level CLI parser with ``run`` and ``status`` subcommands."""
    parser = _ShieldClawArgumentParser(
        prog="shieldclaw", description="ShieldClaw security scan pipeline."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ---- run ----
    run = sub.add_parser("run", help="Run the vulnerability scan pipeline.")
    run.add_argument("--target", required=True, help="Path to the repository under test.")
    run.add_argument("--diff", default=None, help="Optional path to a unified diff patch file.")
    run.add_argument(
        "--semgrep-output",
        dest="semgrep_output",
        default=None,
        metavar="PATH",
        help=(
            "Path to a Semgrep --json report.  Enables the SAST ingest→triage→score "
            "pipeline with SQLite persistence.  Mutually exclusive with --diff "
            "(both accepted with a warning)."
        ),
    )
    run.add_argument(
        "--resume",
        dest="resume_scan_id",
        default=None,
        metavar="SCAN_ID",
        help="Resume a previously interrupted SAST scan by its UUID.",
    )
    run.add_argument(
        "--provider",
        default="ollama",
        help="LLM backend to use: ollama (local) or openai (requires OPENAI_API_KEY).",
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
    run.add_argument(
        "--output-format",
        dest="output_format",
        choices=_OUTPUT_FORMATS,
        default="json",
        help="Report format: json (default), sarif, or markdown.",
    )
    run.add_argument(
        "--interactive",
        action="store_true",
        default=False,
        help="Prompt for per-finding approval inline instead of stopping for async review.",
    )

    # ---- status ----
    status = sub.add_parser(
        "status",
        help="List persisted scan runs and their finding state counts.",
    )
    status.add_argument(
        "--target",
        default=None,
        help="Filter scans by target directory (defaults to cwd).",
    )
    status.add_argument(
        "--scan-id",
        dest="scan_id",
        default=None,
        help="Show details for a specific scan UUID.",
    )

    # ---- approve ----
    approve = sub.add_parser(
        "approve",
        help="Approve or reject findings awaiting review before detonation.",
    )
    approve.add_argument("scan_id", help="Scan UUID to act on.")
    approve.add_argument(
        "finding_id",
        nargs="?",
        default=None,
        help="Specific finding UUID to approve/reject.  Omit when using --all-pending or --auto.",
    )
    approve.add_argument(
        "--reject",
        action="store_true",
        default=False,
        help="Reject the finding(s) instead of approving.",
    )
    approve.add_argument(
        "--note",
        default=None,
        help="Optional audit note recorded with the decision.",
    )
    approve.add_argument(
        "--all-pending",
        dest="all_pending",
        action="store_true",
        default=False,
        help="Apply the decision to all AWAITING_APPROVAL findings in the scan (logs WARN per approval).",
    )
    approve.add_argument(
        "--auto",
        action="store_true",
        default=False,
        help=(
            "Machine-mode: auto-approve all pending findings.  "
            "Requires SHIELDCLAW_AUTO_APPROVE=1; refuses otherwise."
        ),
    )
    approve.add_argument(
        "--target",
        default=None,
        metavar="PATH",
        help="Target directory containing the scan DB (defaults to cwd).",
    )

    return parser


def _run_approve(args: Namespace) -> int:
    """Process an approval or rejection for one or more findings.

    Modes:
      - Single finding:   ``approve <scan_id> <finding_id> [--reject]``
      - All pending:      ``approve <scan_id> --all-pending [--reject]`` (WARN logged per finding)
      - Auto-approve all: ``approve <scan_id> --auto``  (requires ``SHIELDCLAW_AUTO_APPROVE=1``)
    """
    from shieldclaw.approval.gate import get_current_user, is_auto_approve_enabled
    from shieldclaw.persistence.store import FindingRow, ScanStore

    target_dir = getattr(args, "target", None) or str(Path.cwd())
    store = ScanStore(target_dir)

    def pending_for_approval() -> list[FindingRow]:
        pending: list[FindingRow] = []
        seen: set[str] = set()
        for state in ("AWAITING_APPROVAL", "SCORED"):
            for row in store.get_pending_findings(args.scan_id, state):
                if row.finding_id in seen:
                    continue
                pending.append(row)
                seen.add(row.finding_id)
        return pending

    scan_row = store.load_scan(args.scan_id)
    if scan_row is None:
        print(f"Scan {args.scan_id!r} not found.", file=sys.stderr)
        return 1

    # -- auto mode --
    if args.auto:
        if not is_auto_approve_enabled():
            print(
                "ERROR: --auto requires SHIELDCLAW_AUTO_APPROVE=1 in the environment.",
                file=sys.stderr,
            )
            return 1
        pending = pending_for_approval()
        if not pending:
            print("No findings are awaiting approval.", file=sys.stderr)
            return 0
        decided_by = get_current_user()
        for row in pending:
            _LOG.warning(
                "AUTO-APPROVING finding %s in scan %s (SHIELDCLAW_AUTO_APPROVE=1)",
                row.finding_id,
                args.scan_id,
            )
            store.record_approval(
                row.finding_id,
                "APPROVED",
                decided_by,
                note="auto-approved via SHIELDCLAW_AUTO_APPROVE=1",
                auto=True,
            )
            store.update_finding_state(row.finding_id, "APPROVED")
        print(f"Auto-approved {len(pending)} finding(s).", file=sys.stderr)
        return 0

    # -- all-pending mode --
    if args.all_pending:
        decision = "REJECTED" if args.reject else "APPROVED"
        pending = pending_for_approval()
        if not pending:
            print("No findings are awaiting approval.", file=sys.stderr)
            return 0
        decided_by = get_current_user()
        for row in pending:
            _LOG.warning(
                "Bulk-%s finding %s in scan %s",
                decision,
                row.finding_id,
                args.scan_id,
            )
            store.record_approval(
                row.finding_id,
                decision,
                decided_by,
                note=args.note,
                auto=False,
            )
            store.update_finding_state(row.finding_id, decision)
        print(f"{decision} {len(pending)} finding(s).", file=sys.stderr)
        return 0

    # -- single-finding mode --
    if not args.finding_id:
        print(
            "ERROR: provide a finding_id, or use --all-pending / --auto.",
            file=sys.stderr,
        )
        return 1

    finding_rows = pending_for_approval()
    target_id = args.finding_id
    match = next((r for r in finding_rows if r.finding_id == target_id), None)
    if match is None:
        print(
            f"Finding {target_id!r} is not in AWAITING_APPROVAL state for scan {args.scan_id!r}.",
            file=sys.stderr,
        )
        return 1

    decision = "REJECTED" if args.reject else "APPROVED"
    decided_by = get_current_user()
    store.record_approval(
        target_id,
        decision,
        decided_by,
        note=args.note,
        auto=False,
    )
    store.update_finding_state(target_id, decision)
    print(
        f"Finding {target_id} → {decision}  (decided by {decided_by})",
        file=sys.stderr,
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    """Parse CLI arguments, validate inputs, and dispatch to the pipeline.

    Args:
        argv: Optional argument vector (defaults to ``sys.argv`` tail).

    Returns:
        ``0`` on successful completion, ``1`` on validation or fatal errors.
    """
    load_dotenv()
    _configure_logging()
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "status":
        return _run_status(args)

    if args.command == "approve":
        return _run_approve(args)

    if args.command != "run":
        parser.error(f"unknown command {args.command!r}")

    semgrep_output: str | None = getattr(args, "semgrep_output", None)
    resume_scan_id: str | None = getattr(args, "resume_scan_id", None)

    # Warn when --diff and --semgrep-output are both supplied.
    if args.diff is not None and semgrep_output is not None:
        _LOG.warning(
            "--diff and --semgrep-output were both supplied.  "
            "Findings are integrated in SAST mode; diff is used for legacy detonation only."
        )

    try:
        validate_run_configuration(args)
    except CLIValidationError as exc:
        print(exc.message, file=sys.stderr)
        return 1

    # Print triage summary before the full orchestrator SAST pipeline runs.
    if semgrep_output is not None and resume_scan_id is None:
        _print_triage_summary(semgrep_output)

    try:
        Orchestrator().run(
            target_dir=str(Path(args.target).expanduser().resolve()),
            diff_path=args.diff,
            provider_name=str(args.provider).lower(),
            timeout=int(args.timeout),
            output_path=args.output,
            output_format=str(getattr(args, "output_format", "json")),
            semgrep_output=semgrep_output,
            resume_scan_id=resume_scan_id,
            interactive=bool(getattr(args, "interactive", False)),
        )
    except Exception as exc:  # noqa: BLE001 - CLI safety net per product spec
        _LOG.critical("Unhandled failure during orchestration: %s", exc, exc_info=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
