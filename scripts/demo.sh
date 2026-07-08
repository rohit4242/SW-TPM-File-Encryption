#!/usr/bin/env bash
# End-to-end demo of both SW-TPM policies.
#
# Part 1 - password policy: encrypt, decrypt, and show that a wrong
#          password is rejected by the TPM.
# Part 2 - PCR policy: encrypt bound to PCR 16, decrypt, extend the PCR
#          (simulated system change), and show that decryption now fails.
#
# Requires: SW-TPM running (scripts/start_tpm.sh) and the venv activated.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

INPUT="examples/sample.txt"
mkdir -p outputs
rm -f outputs/sample.txt.* outputs/pcr-demo.*

echo "============================================"
echo " Part 1: password policy"
echo "============================================"
python -m src.main encrypt "$INPUT" --policy password --auth demo-password

echo
echo "-- Decrypting with the correct password..."
python -m src.main decrypt outputs/sample.txt.enc --auth demo-password
cmp "$INPUT" outputs/sample.txt.dec
echo "-- Original and decrypted files match."

echo
echo "-- Decrypting with a WRONG password (must fail)..."
if python -m src.main decrypt outputs/sample.txt.enc --auth wrong-password; then
  echo "ERROR: wrong password was accepted!" && exit 1
fi
echo "-- Wrong password was rejected by the TPM, as expected."

echo
echo "============================================"
echo " Part 2: PCR policy (PCR 16)"
echo "============================================"
python -m src.main encrypt "$INPUT" --policy pcr --pcrs 16 --output outputs/pcr-demo.enc

echo
echo "-- Decrypting while the PCR is unchanged..."
python -m src.main decrypt outputs/pcr-demo.enc
cmp "$INPUT" outputs/pcr-demo.dec
echo "-- Original and decrypted files match."

echo
echo "-- Extending PCR 16 to simulate a system change..."
python -m src.main extend-pcr 16 --data changed-system-state

echo
echo "-- Decrypting after the PCR change (must fail)..."
if python -m src.main decrypt outputs/pcr-demo.enc; then
  echo "ERROR: decryption succeeded after PCR change!" && exit 1
fi
echo "-- Unsealing was blocked by the TPM, as expected."

echo
echo "Demo finished successfully."
