#!/usr/bin/env python3
"""Pre-commit helper: run unit pytest from the shield-claw package root.

Launched by the pre-commit pytest-unit hook so the working directory is
the package root where pyproject.toml lives. Integration tests are
excluded; coverage measurement is disabled for speed.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parent.parent

sys.exit(
    subprocess.run(
        [sys.executable, "-m", "pytest", "-m", "not integration", "--no-cov", "-q"],
        cwd=_PKG_ROOT,
    ).returncode
)
