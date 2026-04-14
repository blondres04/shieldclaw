"""Architectural fitness tests: module isolation rules (no runtime I/O)."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Final

_FEATURE_MODULES: Final[tuple[str, ...]] = ("context", "intelligence", "sandbox", "reporting")
_ALLOWED_SHIELDCLAW_LEAVES: Final[frozenset[str]] = frozenset({"models", "exceptions"})


def _shieldclaw_src_root() -> Path:
    """Return ``src/shieldclaw`` (the package directory under tests)."""
    return Path(__file__).resolve().parent.parent / "src" / "shieldclaw"


def _package_for_module_file(py_file: Path, shieldclaw_root: Path) -> str:
    """Infer dotted ``__package__`` for a module file under ``shieldclaw``."""
    rel = py_file.relative_to(shieldclaw_root).with_suffix("")
    parts = rel.parts
    if not parts:
        return "shieldclaw"
    if len(parts) == 1:
        return f"shieldclaw.{parts[0]}"
    return "shieldclaw." + ".".join(parts[:-1])


def _resolved_import_from(
    *,
    current_package: str,
    level: int,
    module: str | None,
) -> str | None:
    """Resolve ``ImportFrom`` to an absolute module name, or ``None`` if invalid."""
    pkg_parts = current_package.split(".")
    if level < 1 or level > len(pkg_parts):
        return None
    drop = level - 1
    anchor_parts = pkg_parts[: len(pkg_parts) - drop]
    if not anchor_parts:
        return None
    anchor = ".".join(anchor_parts)
    if module:
        return f"{anchor}.{module}"
    return anchor


def _shieldclaw_top_after_prefix(module_name: str) -> str | None:
    """Return the segment after ``shieldclaw.`` or ``None`` if not a shieldclaw import."""
    if not module_name.startswith("shieldclaw."):
        return None
    rest = module_name[len("shieldclaw.") :]
    if not rest:
        return None
    return rest.split(".", 1)[0]


def _violates_cross_feature(
    *,
    resolved: str,
    home_feature: str,
) -> bool:
    """Return True if ``resolved`` refers to a different feature module."""
    top = _shieldclaw_top_after_prefix(resolved)
    if top is None:
        return False
    if top in _ALLOWED_SHIELDCLAW_LEAVES:
        return False
    if top in _FEATURE_MODULES:
        return top != home_feature
    return False


def _iter_import_violations(py_file: Path, shieldclaw_root: Path) -> list[str]:
    """Collect human-readable cross-feature import violations for one file."""
    rel_under = py_file.relative_to(shieldclaw_root)
    home = rel_under.parts[0]
    if home not in _FEATURE_MODULES:
        return []

    current_package = _package_for_module_file(py_file, shieldclaw_root)
    source = py_file.read_text(encoding="utf-8")
    try:
        tree = ast.parse(source, filename=str(py_file))
    except SyntaxError as exc:
        return [f"{py_file}: syntax error: {exc}"]

    violations: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.name
                if name.startswith("shieldclaw."):
                    if _violates_cross_feature(resolved=name, home_feature=home):
                        violations.append(
                            f"{py_file}:{node.lineno}: import {name!r} (cross-feature from {home!r})"
                        )
        elif isinstance(node, ast.ImportFrom):
            if node.module is not None and node.level == 0:
                mod = node.module
                if mod == "shieldclaw":
                    for alias in node.names:
                        resolved = f"shieldclaw.{alias.name}"
                        if _violates_cross_feature(resolved=resolved, home_feature=home):
                            violations.append(
                                f"{py_file}:{node.lineno}: from shieldclaw import {alias.name!r} "
                                f"(cross-feature from {home!r})"
                            )
                elif mod.startswith("shieldclaw."):
                    if _violates_cross_feature(resolved=mod, home_feature=home):
                        violations.append(
                            f"{py_file}:{node.lineno}: from {mod!r} import ... (cross-feature from {home!r})"
                        )
            else:
                resolved = _resolved_import_from(
                    current_package=current_package,
                    level=node.level,
                    module=node.module,
                )
                if resolved is None:
                    continue
                if not resolved.startswith("shieldclaw."):
                    continue
                if _violates_cross_feature(resolved=resolved, home_feature=home):
                    violations.append(
                        f"{py_file}:{node.lineno}: relative import resolves to {resolved!r} "
                        f"(cross-feature from {home!r})"
                    )
                if node.module is None and node.names:
                    base = _resolved_import_from(
                        current_package=current_package,
                        level=node.level,
                        module=None,
                    )
                    if base is None or not base.startswith("shieldclaw."):
                        continue
                    for alias in node.names:
                        if alias.name == "*":
                            continue
                        joined = f"{base}.{alias.name}"
                        if _violates_cross_feature(resolved=joined, home_feature=home):
                            violations.append(
                                f"{py_file}:{node.lineno}: from ... import {alias.name!r} "
                                f"resolves to {joined!r} (cross-feature from {home!r})"
                            )

    return violations


def test_no_cross_module_imports() -> None:
    """Feature packages must not import each other (only models/exceptions + own tree)."""
    root = _shieldclaw_src_root()
    all_violations: list[str] = []
    for feature in _FEATURE_MODULES:
        pkg_dir = root / feature
        if not pkg_dir.is_dir():
            continue
        for py_file in sorted(pkg_dir.rglob("*.py")):
            all_violations.extend(_iter_import_violations(py_file, root))

    assert not all_violations, "Cross-feature imports detected:\n" + "\n".join(all_violations)


def _leaf_shieldclaw_imports(py_file: Path) -> list[tuple[int, str]]:
    """Return (lineno, description) for any ``shieldclaw.*`` import in a leaf module."""
    source = py_file.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(py_file))
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("shieldclaw."):
                    found.append((node.lineno, f"import {alias.name!r}"))
        elif isinstance(node, ast.ImportFrom) and node.module:
            if node.module.startswith("shieldclaw."):
                found.append((node.lineno, f"from {node.module!r} import ..."))
            elif node.module == "shieldclaw" and node.level == 0:
                for alias in node.names:
                    found.append((node.lineno, f"from shieldclaw import {alias.name!r}"))
    return found


def test_leaf_modules_have_no_internal_imports() -> None:
    """``models`` and ``exceptions`` must not import other ``shieldclaw.*`` modules."""
    root = _shieldclaw_src_root()
    for name in ("models.py", "exceptions.py"):
        path = root / name
        assert path.is_file(), f"missing {path}"
        bad = _leaf_shieldclaw_imports(path)
        assert not bad, f"{path} must not import shieldclaw submodules; found: {bad}"

