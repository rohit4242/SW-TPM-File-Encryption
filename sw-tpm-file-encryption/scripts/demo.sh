#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

export TPM2TOOLS_TCTI="${TPM2TOOLS_TCTI:-swtpm:host=127.0.0.1,port=2321}"
export TSS2_FAPICONF="${TSS2_FAPICONF:-$PROJECT_ROOT/.tpm-state/fapi-config.json}"
AUTH_VALUE="demo-password"
INPUT_FILE="examples/sample.txt"
ENCRYPTED_FILE="outputs/sample.txt.enc"
DECRYPTED_FILE="outputs/sample.txt.dec"

if [[ "${1:-}" == "--clean" ]]; then
  rm -f outputs/sample.txt.enc outputs/sample.txt.enc.json outputs/sample.txt.enc.pub outputs/sample.txt.enc.priv outputs/sample.txt.dec outputs/wrong.dec
fi

mkdir -p outputs

echo "Checking TPM..."
tpm2_getrandom 8 --hex

echo
echo "Encrypting sample file..."
python -m src.main encrypt "$INPUT_FILE" --policy password --auth "$AUTH_VALUE" --output "$ENCRYPTED_FILE"

echo
echo "Decrypting with correct auth..."
python -m src.main decrypt "$ENCRYPTED_FILE" --auth "$AUTH_VALUE" --output "$DECRYPTED_FILE"

echo
echo "Comparing original and decrypted files..."
cmp "$INPUT_FILE" "$DECRYPTED_FILE"
echo "Files match."

echo
echo "Trying wrong auth. This should fail:"
if python -m src.main decrypt "$ENCRYPTED_FILE" --auth wrong-password --output outputs/wrong.dec; then
  echo "Unexpected success with wrong auth."
  exit 1
else
  echo "Wrong auth failed as expected."
fi
