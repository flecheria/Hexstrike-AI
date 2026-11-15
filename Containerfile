# =============================================================================
# HexStrike AI v6.0 - Configurable Security Server & Tools Container (Podman)
# =============================================================================
# Build with default profile (Network, Reconnaissance & Scanning subset):
#   podman build -t hexstrike-ai:latest -f Containerfile .
#
# Build with a specific profile (minimal, recon_network_scan, web_security,
# auth_password, binary_forensics, cloud_security, full, or manifest):
#   podman build --build-arg TOOL_PROFILE=minimal -t hexstrike-ai:minimal -f Containerfile .
#
# Build with additional or excluded tools:
#   podman build --build-arg TOOL_PROFILE=recon_network_scan \
#                --build-arg EXTRA_TOOLS="hydra,john,trivy" \
#                --build-arg EXCLUDE_TOOLS="amass" \
#                -t hexstrike-ai:custom -f Containerfile .
# =============================================================================

ARG BASE_IMAGE=docker.io/library/python:3.11-slim-bookworm
FROM ${BASE_IMAGE}

LABEL org.opencontainers.image.title="HexStrike AI Server" \
      org.opencontainers.image.description="AI-Powered Cybersecurity Automation & Multi-Domain Investigation Platform" \
      org.opencontainers.image.version="6.0.0"

# Build-time configuration for tool installation
ARG TOOL_PROFILE=recon_network_scan
ARG EXTRA_TOOLS=""
ARG EXCLUDE_TOOLS=""

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HEXSTRIKE_HOST=0.0.0.0 \
    HEXSTRIKE_PORT=8888 \
    HEXSTRIKE_TOOL_PROFILE=${TOOL_PROFILE} \
    HEXSTRIKE_DATA_DIR=/data \
    HEXSTRIKE_RESULTS_DIR=/data/results \
    HEXSTRIKE_FILES_DIR=/data/files \
    HEXSTRIKE_ENVS_DIR=/data/envs \
    HEXSTRIKE_LOG_FILE=/data/logs/hexstrike.log \
    HEXSTRIKE_TOOLS_MANIFEST=/app/config/tools_manifest.json \
    HEXSTRIKE_INSTALLED_TOOLS_STATE=/app/config/installed_tools.json \
    PATH="/usr/local/bin:/root/.local/bin:${PATH}"

WORKDIR /app

# Install base system utilities required for tool installation & network diagnostics
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        wget \
        git \
        unzip \
        tar \
        xz-utils \
        perl \
        iproute2 \
        iputils-ping \
        procps \
        libpcap0.8 && \
    rm -rf /var/lib/apt/lists/*

# Install core Python framework dependencies first (cached layer)
COPY docker/requirements-container.txt /app/docker/requirements-container.txt
RUN python3 -m pip install --no-cache-dir -r /app/docker/requirements-container.txt

# Copy tool manifest and installer script, then install the configured tool subset
COPY config/tools_manifest.json /app/config/tools_manifest.json
COPY docker/install_tools.py /app/docker/install_tools.py
RUN chmod +x /app/docker/install_tools.py && \
    python3 /app/docker/install_tools.py \
        --manifest /app/config/tools_manifest.json \
        --state-output /app/config/installed_tools.json \
        --profile "${TOOL_PROFILE}" \
        --extra-tools "${EXTRA_TOOLS}" \
        --exclude-tools "${EXCLUDE_TOOLS}"

# Copy application source code and entrypoint
COPY src/ /app/src/
COPY hexstrike_server.py hexstrike_mcp.py requirements.txt environment.yml /app/
COPY docker/entrypoint.sh /app/docker/entrypoint.sh

RUN chmod +x /app/docker/entrypoint.sh /app/hexstrike_server.py /app/hexstrike_mcp.py && \
    mkdir -p /data/results /data/files /data/envs /data/logs /data/wordlists

# Persistent volume for scan results, generated files, logs, and Python virtual environments
VOLUME ["/data"]

EXPOSE 8888

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -fsS http://127.0.0.1:${HEXSTRIKE_PORT:-8888}/health || exit 1

ENTRYPOINT ["/app/docker/entrypoint.sh"]
