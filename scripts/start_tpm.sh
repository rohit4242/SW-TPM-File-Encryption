#!/usr/bin/env bash
# Start the SW-TPM emulator (swtpm) as a background daemon.
# TPM state is kept in .tpm-state/ so sealed keys survive restarts.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

STATE_DIR=".tpm-state"
PID_FILE="$STATE_DIR/swtpm.pid"
mkdir -p "$STATE_DIR"

if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
  echo "SW-TPM is already running (PID $(cat "$PID_FILE"))."
  exit 0
fi
rm -f "$PID_FILE"

swtpm socket \
  --tpm2 \
  --tpmstate dir="$STATE_DIR" \
  --server type=tcp,port=2321 \
  --ctrl type=tcp,port=2322 \
  --flags startup-clear \
  --daemon \
  --pid file="$PID_FILE"

echo "SW-TPM started on 127.0.0.1:2321 (PID $(cat "$PID_FILE"))."
