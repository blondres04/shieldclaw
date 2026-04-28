#!/usr/bin/env python3
"""Pre-commit helper: run mypy --strict from the shield-claw package root.

Launched by the pre-commit mypy hook so the working directory is the
package root where pyproject.toml lives, regardless of where git runs.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parent.parent

sys.exit(
    subprocess.run(
        [sys.executable, "-m", "mypy", "--strict", "src/"],
        cwd=_PKG_ROOT,
    ).returncode
)
