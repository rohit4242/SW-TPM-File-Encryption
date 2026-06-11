#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TPM_STATE_DIR="$PROJECT_ROOT/.tpm-state"
PID_FILE="$TPM_STATE_DIR/swtpm.pid"
FAPI_CONFIG="$TPM_STATE_DIR/fapi-config.json"
FAPI_USER_DIR="$TPM_STATE_DIR/fapi-user"
FAPI_SYSTEM_DIR="$TPM_STATE_DIR/fapi-system"
FAPI_LOG_DIR="$TPM_STATE_DIR/eventlog"

mkdir -p "$TPM_STATE_DIR" "$FAPI_USER_DIR" "$FAPI_SYSTEM_DIR" "$FAPI_LOG_DIR"

cat > "$FAPI_CONFIG" <<EOF
{
  "profile_name": "P_ECCP256SHA256",
  "profile_dir": "/etc/tpm2-tss/fapi-profiles/",
  "user_dir": "$FAPI_USER_DIR",
  "system_dir": "$FAPI_SYSTEM_DIR",
  "tcti": "swtpm:host=127.0.0.1,port=2321",
  "system_pcrs": [],
  "log_dir": "$FAPI_LOG_DIR",
  "ek_cert_less": "yes"
}
EOF

if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
  echo "SW-TPM is already running with PID $(cat "$PID_FILE")."
  echo "Use this TCTI: export TPM2TOOLS_TCTI=swtpm:host=127.0.0.1,port=2321"
  echo "Use this FAPI config: export TSS2_FAPICONF=$FAPI_CONFIG"
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
echo "Use this FAPI config: export TSS2_FAPICONF=$FAPI_CONFIG"
