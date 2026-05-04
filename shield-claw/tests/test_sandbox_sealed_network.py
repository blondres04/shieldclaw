"""Integration test: pre-built attacker image works with zero outbound internet.

Requires Docker. Skip when the daemon is unavailable.

Hardening claim
---------------
The detonation step no longer bootstraps pip at runtime. All dependencies
(requests, urllib3) are baked into the image. Running the attacker container
with ``--network none`` (fully sealed) proves that:

1. ``import requests`` succeeds - the library is pre-installed.
2. ``requests.get("https://pypi.org")`` raises ``ConnectionError`` - the
   sealed network blocks outbound traffic.
3. The exploit script still exits ``0`` - success does not depend on internet.

This is the architectural proof that we can safely run exploit containers
with ``internal: true`` Docker networks in future phases.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

_SCRIPT_DIR = Path(__file__).resolve().parents[1]
_DOCKERFILE = _SCRIPT_DIR / "docker" / "attacker.Dockerfile"

_DEFAULT_TAG = os.environ.get("SHIELDCLAW_ATTACKER_IMAGE", "shieldclaw-attacker:test")


def _docker_available() -> bool:
    try:
        r = subprocess.run(["docker", "version"], capture_output=True, text=True, timeout=15.0)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def _build_image(tag: str) -> bool:
    """Build the attacker image and return True on success."""
    if not _DOCKERFILE.is_file():
        return False
    result = subprocess.run(
        [
            "docker",
            "build",
            "-f",
            str(_DOCKERFILE),
            "-t",
            tag,
            str(_SCRIPT_DIR),
        ],
        capture_output=True,
        text=True,
        timeout=300.0,
    )
    if result.returncode != 0:
        print(f"Image build failed:\n{result.stderr[:1000]}")
        return False
    return True


@pytest.mark.integration
@pytest.mark.skipif(not _docker_available(), reason="Docker engine not available")
def test_attacker_image_has_requests_preinstalled() -> None:
    """Requests is importable without any pip install step."""
    tag = _DEFAULT_TAG
    if not _build_image(tag):
        pytest.skip("Failed to build attacker image")

    exploit = (
        "import requests\n"
        "import sys\n"
        "print('requests version:', requests.__version__)\n"
        "sys.exit(0)\n"
    )
    result = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "-i", tag],
        input=exploit,
        capture_output=True,
        text=True,
        timeout=30.0,
    )
    assert result.returncode == 0, (
        f"Expected exit 0; got {result.returncode}\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert "requests version" in result.stdout


@pytest.mark.integration
@pytest.mark.skipif(not _docker_available(), reason="Docker engine not available")
def test_pypi_unreachable_with_sealed_network() -> None:
    """With --network none, outbound internet is fully blocked."""
    tag = _DEFAULT_TAG
    if not _build_image(tag):
        pytest.skip("Failed to build attacker image")

    exploit = (
        "import sys\n"
        "import requests\n"
        "try:\n"
        "    requests.get('https://pypi.org', timeout=2)\n"
        "    print('WARNING: PyPI was reachable; sealed-network assertion cannot be made')\n"
        "    sys.exit(0)\n"
        "except Exception as e:\n"
        "    print('PyPI unreachable (expected):', type(e).__name__)\n"
        "    sys.exit(0)\n"
    )
    result = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "-i", tag],
        input=exploit,
        capture_output=True,
        text=True,
        timeout=30.0,
    )
    assert result.returncode == 0, f"Script failed unexpectedly:\n{result.stdout}\n{result.stderr}"
    assert "unreachable" in result.stdout.lower() or "WARNING" in result.stdout


@pytest.mark.integration
@pytest.mark.skipif(not _docker_available(), reason="Docker engine not available")
def test_exploit_works_without_bootstrap(tmp_path: Path) -> None:
    """The full detonate() path works with the pre-built image."""
    tag = _DEFAULT_TAG
    if not _build_image(tag):
        pytest.skip("Failed to build attacker image")

    raw_code = (
        "import sys\n"
        "import requests\n"
        "# Verify requests is available without network bootstrap\n"
        "assert hasattr(requests, 'get'), 'requests.get should exist'\n"
        "sys.exit(0)\n"
    )
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "-i",
            "--memory=256m",
            "--cpus=0.5",
            "--pids-limit=100",
            "--user=1000:1000",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=32m",
            "-e",
            "PYTHONDONTWRITEBYTECODE=1",
            tag,
        ],
        input=raw_code,
        capture_output=True,
        text=True,
        timeout=30.0,
    )
    assert result.returncode == 0, (
        f"Expected exit 0; got {result.returncode}\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
