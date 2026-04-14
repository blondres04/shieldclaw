"""Collect docker-compose metadata and unified diffs into a ``ScanContext``."""

from __future__ import annotations

import logging
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from shieldclaw.exceptions import AggregationError
from shieldclaw.models import ScanContext

_LOG = logging.getLogger(__name__)

_COMPOSE_CANDIDATES: tuple[str, ...] = ("docker-compose.yml", "docker-compose.yaml")
_DIFF_MAX_CHARS = 8000
_DIFF_HEAD = 4000
_DIFF_TAIL = 4000
_GIT_DIFF_TIMEOUT_SECONDS = 60.0
_MARKER = "\n[TRUNCATED]\n"


def _truncate_diff(diff: str) -> str:
    """Keep diffs bounded while preserving the head and tail of large hunks."""
    if len(diff) <= _DIFF_MAX_CHARS:
        return diff
    return diff[:_DIFF_HEAD] + _MARKER + diff[-_DIFF_TAIL:]


def _resolve_under_target(target_root: Path, candidate: str) -> Path:
    """Resolve a user-supplied path against the repository root when relative."""
    path = Path(candidate)
    if path.is_absolute():
        return path.resolve()
    return (target_root / path).resolve()


class ContextAggregator:
    """Loads compose files and diff text from disk or a local git worktree."""

    def __init__(self, *, git_diff_timeout_seconds: float = _GIT_DIFF_TIMEOUT_SECONDS) -> None:
        """Configure aggregator behavior.

        Args:
            git_diff_timeout_seconds: Hard limit for ``git diff`` subprocess runs.
        """
        self._git_timeout = git_diff_timeout_seconds

    def aggregate(self, target_dir: str, diff_path: str | None) -> ScanContext:
        """Build a ``ScanContext`` from compose metadata and a diff source.

        Args:
            target_dir: Root directory of the repository under analysis.
            diff_path: Optional path to a patch file; when ``None``, ``git diff HEAD~1`` is used.

        Returns:
            Immutable snapshot containing compose text, diff text, and capture time.

        Raises:
            AggregationError: When compose or diff inputs are missing, empty, or unreadable.
        """
        try:
            root = Path(target_dir).expanduser().resolve()
        except OSError as exc:
            raise AggregationError(f"Unable to resolve target directory {target_dir!r}.") from exc

        if not root.is_dir():
            raise AggregationError(f"Target directory is not a folder: {root}")

        compose_text = self._read_compose(root)
        diff_text = self._load_diff(root, diff_path)
        diff_text = diff_text.strip()
        if not diff_text:
            raise AggregationError("Diff content is empty after loading.")

        truncated = _truncate_diff(diff_text)
        timestamp = datetime.now(UTC)
        return ScanContext(
            target_dir=str(root),
            git_diff_content=truncated,
            docker_compose_content=compose_text,
            timestamp=timestamp,
        )

    def _read_compose(self, root: Path) -> str:
        """Locate and read a docker compose file from the repository root.

        Raises:
            AggregationError: When no compose file exists or cannot be read.
        """
        for name in _COMPOSE_CANDIDATES:
            candidate = root / name
            if candidate.is_file():
                try:
                    return candidate.read_text(encoding="utf-8")
                except OSError as exc:
                    raise AggregationError(
                        f"Unable to read docker compose file {candidate}."
                    ) from exc
        raise AggregationError(
            "No docker-compose.yml or docker-compose.yaml found in the target directory."
        )

    def _load_diff(self, root: Path, diff_path: str | None) -> str:
        """Load diff text from a patch file or by querying git.

        Raises:
            AggregationError: When the patch cannot be read or git invocation fails.
        """
        if diff_path is not None:
            path = _resolve_under_target(root, diff_path)
            try:
                return path.read_text(encoding="utf-8")
            except OSError as exc:
                raise AggregationError(f"Unable to read diff file {path}.") from exc

        if not (root / ".git").is_dir():
            for filename in ("context.patch", "shieldclaw.context.patch"):
                candidate = root / filename
                if candidate.is_file():
                    try:
                        return candidate.read_text(encoding="utf-8")
                    except OSError as exc:
                        raise AggregationError(
                            f"Unable to read diff fallback file {candidate}."
                        ) from exc

        return self._git_diff_head_minus_one(root)

    def _git_diff_head_minus_one(self, root: Path) -> str:
        """Run ``git diff HEAD~1`` inside the repository with explicit status handling.

        Raises:
            AggregationError: When git is missing, times out, or exits non-zero.
        """
        command = ["git", "-C", str(root), "diff", "HEAD~1"]
        _LOG.debug("Running command: %s", command)
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self._git_timeout,
            )
        except FileNotFoundError as exc:
            raise AggregationError("git executable not found on PATH.") from exc
        except subprocess.TimeoutExpired as exc:
            raise AggregationError(
                f"git diff timed out after {self._git_timeout} seconds."
            ) from exc
        except OSError as exc:
            raise AggregationError("Unable to execute git diff subprocess.") from exc

        if completed.returncode != 0:
            stderr = (completed.stderr or "").strip()
            detail = stderr or "git produced no stderr output."
            raise AggregationError(
                f"git diff HEAD~1 failed with exit code {completed.returncode}: {detail}"
            )
        return completed.stdout or ""
