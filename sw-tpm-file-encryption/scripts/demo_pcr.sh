#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

export TPM2TOOLS_TCTI="${TPM2TOOLS_TCTI:-swtpm:host=127.0.0.1,port=2321}"
export TSS2_FAPICONF="${TSS2_FAPICONF:-$PROJECT_ROOT/.tpm-state/fapi-config.json}"
INPUT_FILE="examples/sample.txt"
ENCRYPTED_FILE="outputs/sample.txt.enc"
DECRYPTED_FILE="outputs/sample.txt.dec"
PCR_INDEX="16"

if [[ "${1:-}" == "--clean" ]]; then
  rm -f outputs/sample.txt.enc outputs/sample.txt.enc.json outputs/sample.txt.enc.pub outputs/sample.txt.enc.priv outputs/sample.txt.dec outputs/pcr_after_change.dec
fi

mkdir -p outputs

echo "Checking TPM..."
tpm2_getrandom 8 --hex

echo
echo "Encrypting sample file with PCR policy on PCR $PCR_INDEX..."
python -m src.main encrypt "$INPUT_FILE" --policy pcr --pcrs "$PCR_INDEX" --output "$ENCRYPTED_FILE"

echo
echo "Decrypting while PCR value still matches..."
python -m src.main decrypt "$ENCRYPTED_FILE" --pcrs "$PCR_INDEX" --output "$DECRYPTED_FILE"
cmp "$INPUT_FILE" "$DECRYPTED_FILE"
echo "Files match before PCR change."

echo
echo "Extending PCR $PCR_INDEX..."
python -m src.main extend-pcr "$PCR_INDEX" --data "changed-demo-state"

echo
echo "Trying decrypt after PCR change. This should fail:"
if python -m src.main decrypt "$ENCRYPTED_FILE" --pcrs "$PCR_INDEX" --output outputs/pcr_after_change.dec; then
  echo "Unexpected success after PCR changed."
  exit 1
else
  echo "PCR mismatch failed as expected."
fi
