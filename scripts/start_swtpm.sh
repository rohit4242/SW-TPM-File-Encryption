#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TPM_STATE_DIR="$PROJECT_ROOT/.tpm-state"
PID_FILE="$TPM_STATE_DIR/swtpm.pid"

mkdir -p "$TPM_STATE_DIR"

if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
  echo "SW-TPM is already running with PID $(cat "$PID_FILE")."
  echo "Use this TCTI: export TPM2TOOLS_TCTI=swtpm:host=127.0.0.1,port=2321"
  exit 0
fi

if [[ -f "$PID_FILE" ]]; then
  rm -f "$PID_FILE"
fi

swtpm socket \
  --tpm2 \
  --tpmstate dir="$TPM_STATE_DIR" \
  --ctrl type=tcp,port=2322 \
  --server type=tcp,port=2321 \
  --flags startup-clear \
  --daemon \
  --pid file="$PID_FILE"

export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=2321"
echo "SW-TPM started."
echo "PID file: $PID_FILE"
echo "Use this TCTI: export TPM2TOOLS_TCTI=swtpm:host=127.0.0.1,port=2321"
