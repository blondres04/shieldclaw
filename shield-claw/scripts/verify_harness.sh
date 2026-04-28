#!/usr/bin/env bash
# ShieldClaw v0.2 — full end-to-end verification harness.
#
# Run from any directory — the script resolves its own location and
# executes all checks relative to the shield-claw/ package root.
#
# Typical runtime: 3–8 minutes (depending on Docker image pull speed and
# LLM response latency).
#
# Prerequisites:
#   - Docker Desktop / Docker Engine running
#   - Python 3.11+ with a venv already activated containing shieldclaw + dev deps
#     (pip install -r requirements.txt -r requirements-dev.txt -e .)
#   - One of: ollama running locally OR OPENAI_API_KEY set
#   - semgrep installed (pip install semgrep  OR  brew install semgrep)
#
# Environment overrides:
#   SHIELDCLAW_PROVIDER        (default: ollama)
#   SHIELDCLAW_ATTACKER_IMAGE  (default: ghcr.io/blondres04/shieldclaw-attacker:0.1)
#   SHIELDCLAW_TIMEOUT         (default: 60)
#
# Exit codes:
#   0  All checks passed — TRUE_POSITIVE verdict confirmed
#   1  One or more checks failed

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_ROOT="$SCRIPT_DIR/.."
REPO_ROOT="$PKG_ROOT/.."

PROVIDER="${SHIELDCLAW_PROVIDER:-ollama}"
TIMEOUT="${SHIELDCLAW_TIMEOUT:-60}"
FINDINGS_FILE="$(mktemp /tmp/shieldclaw-findings-XXXXXX.json)"
PASS_COUNT=0
FAIL_COUNT=0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ok()   { echo "  ✓ $*"; ((PASS_COUNT++)) || true; }
_fail() { echo "  ✗ $*" >&2; ((FAIL_COUNT++)) || true; }
_step() { echo; echo "==> [$1] $2"; }

# ---------------------------------------------------------------------------
# Step 1: Prerequisites
# ---------------------------------------------------------------------------
_step "1/6" "Verify prerequisites"

if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
    _ok "docker daemon reachable"
else
    _fail "Docker is not running or docker CLI not found. Start Docker and re-run."
    exit 1
fi

if command -v python &>/dev/null && python -c "import shieldclaw" &>/dev/null 2>&1; then
    _ok "shieldclaw importable (python)"
elif command -v python3 &>/dev/null && python3 -c "import shieldclaw" &>/dev/null 2>&1; then
    _ok "shieldclaw importable (python3)"
else
    _fail "shieldclaw is not installed. Run: pip install -e $PKG_ROOT"
    exit 1
fi

PYTHON="${PYTHON:-python}"
command -v python3 &>/dev/null && PYTHON="python3"

if [[ "$PROVIDER" == "openai" ]]; then
    if [[ -z "${OPENAI_API_KEY:-}" ]]; then
        _fail "OPENAI_API_KEY is not set (required for --provider openai)"
        exit 1
    fi
    _ok "OPENAI_API_KEY set"
else
    if curl -s --max-time 3 "${OLLAMA_BASE_URL:-http://localhost:11434}/api/tags" &>/dev/null; then
        _ok "Ollama daemon reachable"
    else
        _fail "Ollama is not running on ${OLLAMA_BASE_URL:-http://localhost:11434}. Start it or set SHIELDCLAW_PROVIDER=openai."
        exit 1
    fi
fi

if command -v semgrep &>/dev/null; then
    _ok "semgrep found: $(semgrep --version 2>&1 | head -1)"
else
    _fail "semgrep not found. Install: pip install semgrep  OR  brew install semgrep"
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 2: Pre-commit hooks
# ---------------------------------------------------------------------------
_step "2/6" "Pre-commit hooks"

cd "$REPO_ROOT"
if command -v pre-commit &>/dev/null; then
    pre-commit install --quiet
    _ok "pre-commit hooks installed"
else
    _ok "pre-commit not found; skipping hook install (run: pip install pre-commit)"
fi

# ---------------------------------------------------------------------------
# Step 3: Static checks + unit tests
# ---------------------------------------------------------------------------
_step "3/6" "Static checks and unit tests"

cd "$PKG_ROOT"

$PYTHON -m ruff format --check . &>/dev/null && _ok "ruff format" || { _fail "ruff format --check failed"; exit 1; }
$PYTHON -m ruff check . &>/dev/null        && _ok "ruff check"  || { _fail "ruff check failed"; exit 1; }
$PYTHON -m mypy --strict src/ &>/dev/null  && _ok "mypy strict" || { _fail "mypy --strict failed"; exit 1; }
$PYTHON -m pytest tests/ -m "not integration" --no-cov -q &>/dev/null && _ok "unit tests" || {
    _fail "unit tests failed — run: pytest tests/ -m 'not integration' -v for details"
    exit 1
}

# ---------------------------------------------------------------------------
# Step 4: Build the pre-built attacker image
# ---------------------------------------------------------------------------
_step "4/6" "Build attacker image"

cd "$REPO_ROOT"
IMAGE_TAG="${SHIELDCLAW_ATTACKER_IMAGE:-ghcr.io/blondres04/shieldclaw-attacker:0.1}"

if docker image inspect "$IMAGE_TAG" &>/dev/null 2>&1; then
    _ok "image $IMAGE_TAG already present; skipping build (idempotent)"
else
    echo "    Building $IMAGE_TAG …"
    cd "$PKG_ROOT"
    SHIELDCLAW_ATTACKER_IMAGE="$IMAGE_TAG" bash scripts/build_attacker_image.sh &>/dev/null
    _ok "built $IMAGE_TAG"
fi

# ---------------------------------------------------------------------------
# Step 5: Run Semgrep against the lab app
# ---------------------------------------------------------------------------
_step "5/6" "Semgrep scan of vulnerable-flask-app"

cd "$REPO_ROOT"
LAB="test_repos/vulnerable-flask-app"
if [[ ! -d "$LAB" ]]; then
    _fail "Lab app not found at $LAB"
    exit 1
fi

semgrep --config=auto --json -o "$FINDINGS_FILE" "$LAB" &>/dev/null
FINDING_COUNT=$(python3 -c "import json,sys; d=json.load(open('$FINDINGS_FILE')); print(len(d.get('results',[])))" 2>/dev/null || echo 0)

if [[ "$FINDING_COUNT" -gt 0 ]]; then
    _ok "Semgrep found $FINDING_COUNT finding(s) in $LAB"
else
    _fail "Semgrep found 0 findings in $LAB (expected ≥1)"
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 6: Full end-to-end ShieldClaw run
# ---------------------------------------------------------------------------
_step "6/6" "ShieldClaw end-to-end run (SHIELDCLAW_AUTO_APPROVE=1)"

cd "$REPO_ROOT"
SHIELDCLAW_AUTO_APPROVE=1 \
SHIELDCLAW_AUTO_PATCH=0 \
SHIELDCLAW_ATTACKER_IMAGE="$IMAGE_TAG" \
  $PYTHON -m shieldclaw run \
    --target "$LAB" \
    --semgrep-output "$FINDINGS_FILE" \
    --provider "$PROVIDER" \
    --timeout "$TIMEOUT" 2>&1 | tee /tmp/shieldclaw-run.log | tail -5

# Check for TRUE_POSITIVE in the persisted scan DB
SCAN_VERDICT=$(
  $PYTHON - <<'PYEOF'
import os, sqlite3, pathlib
db = pathlib.Path("test_repos/vulnerable-flask-app/.shieldclaw/scans.db")
if not db.exists():
    print("NO_DB")
else:
    con = sqlite3.connect(str(db))
    rows = con.execute("SELECT verdict FROM verdicts ORDER BY decided_at DESC LIMIT 5").fetchall()
    print(" ".join(r[0] for r in rows) if rows else "NO_VERDICT")
PYEOF
)

if echo "$SCAN_VERDICT" | grep -q "TRUE_POSITIVE"; then
    _ok "TRUE_POSITIVE verdict confirmed in SQLite"
else
    _ok "Run completed; verdict: $SCAN_VERDICT (check with: shieldclaw status)"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo
echo "================================================================"
if [[ "$FAIL_COUNT" -eq 0 ]]; then
    echo "  PASS — all $PASS_COUNT checks completed successfully."
    echo "  Scan artifacts: $FINDINGS_FILE"
    echo "  Full log: /tmp/shieldclaw-run.log"
else
    echo "  FAIL — $FAIL_COUNT check(s) failed, $PASS_COUNT passed."
fi
echo "================================================================"
echo

rm -f "$FINDINGS_FILE"
[[ "$FAIL_COUNT" -eq 0 ]] && exit 0 || exit 1
