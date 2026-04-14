"""Tests for ``ContextAggregator`` covering compose discovery, patches, and git diffs."""

from __future__ import annotations

import subprocess
import textwrap

import pytest

from shieldclaw.context.aggregator import ContextAggregator
from shieldclaw.exceptions import AggregationError


def _git_available() -> bool:
    try:
        subprocess.run(
            ["git", "--version"],
            capture_output=True,
            text=True,
            timeout=5.0,
        )
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def test_aggregate_with_patch_file(tmp_path) -> None:
    """Patch-based diffs should hydrate a ``ScanContext`` when compose exists."""
    root = tmp_path / "repo"
    root.mkdir()
    compose = root / "docker-compose.yml"
    compose.write_text("services:\n  web:\n    image: nginx\n", encoding="utf-8")
    patch = root / "changes.patch"
    patch.write_text(
        textwrap.dedent(
            """\
            diff --git a/app.py b/app.py
            --- a/app.py
            +++ b/app.py
            @@ -0,0 +1 @@
            +print("hi")
            """
        ),
        encoding="utf-8",
    )

    aggregator = ContextAggregator()
    context = aggregator.aggregate(str(root), "changes.patch")

    assert context.target_dir == str(root.resolve())
    assert "services:" in context.docker_compose_content
    assert "diff --git" in context.git_diff_content
    assert context.timestamp.tzinfo is not None


def test_aggregate_accepts_yaml_compose(tmp_path) -> None:
    """``docker-compose.yaml`` should be accepted as an alternate filename."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "docker-compose.yaml").write_text("version: '3'\n", encoding="utf-8")
    (root / "delta.patch").write_text("diff --git a/x b/x\n", encoding="utf-8")

    context = ContextAggregator().aggregate(str(root), "delta.patch")
    assert "version" in context.docker_compose_content


def test_missing_compose_raises(tmp_path) -> None:
    """Missing compose files must surface ``AggregationError``."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "only.patch").write_text("diff --git a/x b/x\n", encoding="utf-8")

    with pytest.raises(AggregationError) as excinfo:
        ContextAggregator().aggregate(str(root), "only.patch")
    assert "docker-compose" in str(excinfo.value).lower()


def test_empty_diff_raises(tmp_path) -> None:
    """Whitespace-only diffs are treated as empty and rejected."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "docker-compose.yml").write_text("version: '3'\n", encoding="utf-8")
    (root / "empty.patch").write_text("   \n", encoding="utf-8")

    with pytest.raises(AggregationError) as excinfo:
        ContextAggregator().aggregate(str(root), "empty.patch")
    assert "empty" in str(excinfo.value).lower()


def test_git_diff_requires_repository(tmp_path) -> None:
    """``git diff`` without a repository should fail with ``AggregationError``."""
    root = tmp_path / "not-a-repo"
    root.mkdir()
    (root / "docker-compose.yml").write_text("version: '3'\n", encoding="utf-8")

    with pytest.raises(AggregationError) as excinfo:
        ContextAggregator().aggregate(str(root), None)
    assert "git" in str(excinfo.value).lower()


@pytest.mark.skipif(not _git_available(), reason="git executable not available")
def test_git_diff_head_minus_one(tmp_path) -> None:
    """Two commits should yield a non-empty diff via ``HEAD~1``."""
    root = tmp_path / "git-repo"
    root.mkdir()

    def run_git(args: list[str]) -> None:
        subprocess.run(
            args,
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
            timeout=30.0,
        )

    run_git(["git", "init", "-b", "main"])
    run_git(["git", "config", "user.email", "test@example.com"])
    run_git(["git", "config", "user.name", "Tester"])
    (root / "file.txt").write_text("first\n", encoding="utf-8")
    run_git(["git", "add", "."])
    run_git(["git", "commit", "-m", "first"])
    (root / "file.txt").write_text("second\n", encoding="utf-8")
    (root / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    run_git(["git", "add", "."])
    run_git(["git", "commit", "-m", "second"])

    context = ContextAggregator().aggregate(str(root), None)
    assert "docker-compose" in context.git_diff_content
    assert "file.txt" in context.git_diff_content


def test_truncation_inserts_marker(tmp_path) -> None:
    """Very long diffs should include the truncation marker between head and tail."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "docker-compose.yml").write_text("version: '3'\n", encoding="utf-8")
    head = "A" * 4500
    tail = "B" * 4500
    (root / "big.patch").write_text(head + tail, encoding="utf-8")

    context = ContextAggregator().aggregate(str(root), "big.patch")
    assert "[TRUNCATED]" in context.git_diff_content
    assert context.git_diff_content.startswith("A" * 4000)
    assert context.git_diff_content.endswith("B" * 4000)


def test_absolute_patch_path(tmp_path) -> None:
    """Absolute patch paths outside the repo root should still be honored."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "docker-compose.yml").write_text("version: '3'\n", encoding="utf-8")
    patch_path = tmp_path / "external.patch"
    patch_path.write_text("diff --git a/x b/x\n", encoding="utf-8")

    context = ContextAggregator().aggregate(str(root), str(patch_path))
    assert "diff --git" in context.git_diff_content
