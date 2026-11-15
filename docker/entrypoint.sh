#!/usr/bin/env bash
set -euo pipefail

# Initialize persistent volume directory structure under HEXSTRIKE_DATA_DIR (/data by default)
DATA_DIR="${HEXSTRIKE_DATA_DIR:-/data}"
mkdir -p \
  "${HEXSTRIKE_RESULTS_DIR:-${DATA_DIR}/results}" \
  "${HEXSTRIKE_FILES_DIR:-${DATA_DIR}/files}" \
  "${HEXSTRIKE_ENVS_DIR:-${DATA_DIR}/envs}" \
  "${DATA_DIR}/logs" \
  "${DATA_DIR}/wordlists"

# Optional runtime installation of extra tools if RUNTIME_EXTRA_TOOLS is set
if [[ -n "${RUNTIME_EXTRA_TOOLS:-}" ]]; then
  echo "[HexStrike-Entrypoint] Installing runtime extra tools: ${RUNTIME_EXTRA_TOOLS}"
  python3 /app/docker/install_tools.py \
    --profile "${HEXSTRIKE_TOOL_PROFILE:-recon_network_scan}" \
    --extra-tools "${RUNTIME_EXTRA_TOOLS}"
else
  # Refresh installed_tools.json so MCP and /api/tools/available have accurate runtime state
  python3 /app/docker/install_tools.py \
    --profile "${HEXSTRIKE_TOOL_PROFILE:-recon_network_scan}" \
    --verify-only || true
fi

# If custom command args are passed, execute them; otherwise start the FastAPI server
if [[ $# -gt 0 ]]; then
  exec "$@"
fi

DEBUG_FLAG=""
if [[ "${HEXSTRIKE_DEBUG:-false}" == "true" ]]; then
  DEBUG_FLAG="--debug"
fi

exec python3 /app/hexstrike_server.py \
  --host "${HEXSTRIKE_HOST:-0.0.0.0}" \
  --port "${HEXSTRIKE_PORT:-8888}" \
  ${DEBUG_FLAG}
