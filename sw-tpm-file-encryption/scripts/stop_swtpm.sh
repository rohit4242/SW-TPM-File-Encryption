#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TPM_STATE_DIR="$PROJECT_ROOT/.tpm-state"
PID_FILE="$TPM_STATE_DIR/swtpm.pid"

if [[ ! -f "$PID_FILE" ]]; then
  echo "No SW-TPM PID file found."
  exit 0
fi

PID="$(cat "$PID_FILE")"
if kill -0 "$PID" 2>/dev/null; then
  kill "$PID"
  echo "Stopped SW-TPM with PID $PID."
else
  echo "SW-TPM PID $PID is not running."
fi

rm -f "$PID_FILE"
