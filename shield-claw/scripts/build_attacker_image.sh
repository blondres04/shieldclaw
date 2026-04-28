#!/usr/bin/env bash
# Build the ShieldClaw pre-built attacker image.
#
# Usage:
#   scripts/build_attacker_image.sh
#
# Override the image tag via SHIELDCLAW_ATTACKER_IMAGE:
#   SHIELDCLAW_ATTACKER_IMAGE=myregistry/attacker:dev scripts/build_attacker_image.sh
#
# After building, push to GHCR:
#   docker push ghcr.io/<user>/shieldclaw-attacker:0.1
#
# The image eliminates outbound PyPI access at detonation time — requests and
# urllib3 are installed during the build, not at runtime.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_ROOT="$SCRIPT_DIR/.."

TAG="${SHIELDCLAW_ATTACKER_IMAGE:-ghcr.io/blondres04/shieldclaw-attacker:0.1}"

echo "==> Building attacker image: $TAG"
docker build -f "$PKG_ROOT/docker/attacker.Dockerfile" -t "$TAG" "$PKG_ROOT"
echo "==> Built $TAG"
echo ""
echo "To push: docker push $TAG"
echo "To test: echo 'import requests; print(requests.__version__); import sys; sys.exit(0)' | docker run --rm -i '$TAG'"
