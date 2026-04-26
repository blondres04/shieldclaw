#!/usr/bin/env bash
# Harness validation gate for Shield Claw V1.
#
# Run from any directory — the script resolves its own location and
# executes all checks relative to the shield-claw/ package root.
#
# Prerequisites: pip install -r requirements-dev.txt
#
# Exit codes:
#   0  All checks passed
#   1  One or more checks failed (first failure stops execution)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_ROOT="$SCRIPT_DIR/.."

cd "$PKG_ROOT"

echo "==> [1/4] ruff format . (canonicalize structure)"
ruff format .

echo "==> [2/4] ruff check . --fix (enforce style)"
ruff check . --fix

echo "==> [3/4] mypy src/ (enforce types, strict)"
mypy src/

echo "==> [4/4] pytest tests/test_architecture.py (enforce BCE arrows)"
pytest tests/test_architecture.py

echo ""
echo "All harness checks passed."
