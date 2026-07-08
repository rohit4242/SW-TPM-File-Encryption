#!/usr/bin/env bash
# Stop the SW-TPM emulator started by start_tpm.sh.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

PID_FILE=".tpm-state/swtpm.pid"

if [[ ! -f "$PID_FILE" ]]; then
  echo "SW-TPM is not running (no PID file)."
  exit 0
fi

PID="$(cat "$PID_FILE")"
if kill -0 "$PID" 2>/dev/null; then
  kill "$PID"
  echo "SW-TPM stopped (PID $PID)."
else
  echo "SW-TPM was not running."
fi
rm -f "$PID_FILE"
