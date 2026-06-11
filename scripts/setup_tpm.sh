#!/usr/bin/env bash
set -euo pipefail

export TPM2TOOLS_TCTI="${TPM2TOOLS_TCTI:-swtpm:host=127.0.0.1,port=2321}"

echo "Checking TPM connection with TCTI: $TPM2TOOLS_TCTI"
tpm2_getrandom 8 --hex
echo
echo "Checking Python CLI..."
python -m src.main --help >/dev/null
echo "TPM is reachable."
