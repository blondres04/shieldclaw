# ShieldClaw attacker image — pre-bakes requests + urllib3 so detonation
# requires NO outbound internet access and NO pip-at-runtime step.
#
# Build:
#   docker build -f docker/attacker.Dockerfile -t ghcr.io/<user>/shieldclaw-attacker:0.1 .
#
# The ENTRYPOINT reads a Python exploit script from stdin and executes it.
# This matches the existing subprocess.run(... input=payload.raw_code) interface.

FROM python:3.11-slim

# Install dependencies at build time to eliminate outbound PyPI access at detonation.
RUN pip install --no-cache-dir "requests==2.32.*" "urllib3==2.2.*" \
    && useradd -m -u 1000 attacker

USER 1000:1000

WORKDIR /tmp

# Read exploit source from stdin and execute it.
ENTRYPOINT ["python", "-c", "import sys; exec(compile(sys.stdin.read(), '<exploit>', 'exec'))"]
