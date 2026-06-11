#!/usr/bin/env bash
set -euo pipefail

export TPM2TOOLS_TCTI="${TPM2TOOLS_TCTI:-swtpm:host=127.0.0.1,port=2321}"
export TSS2_FAPICONF="${TSS2_FAPICONF:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/.tpm-state/fapi-config.json}"

echo "Checking TPM connection with TCTI: $TPM2TOOLS_TCTI"
tpm2_getrandom 8 --hex
echo "Checking Python FAPI configuration: $TSS2_FAPICONF"
python -m src.main --help >/dev/null
echo "TPM is reachable."
