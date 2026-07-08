#!/usr/bin/env bash
# One-time setup on Ubuntu / WSL2 / Kali:
# installs the SW-TPM emulator, the TSS libraries, and a Python
# virtual environment with tpm2-pytss and cryptography.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

echo "==> Installing system packages (swtpm, tpm2-tss, build tools)..."
sudo apt update
sudo apt install -y \
  swtpm \
  libtss2-dev \
  python3 \
  python3-venv \
  python3-dev \
  build-essential \
  pkg-config

echo "==> Creating Python virtual environment..."
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

echo
echo "Setup complete."
echo "Activate the environment with: source .venv/bin/activate"
echo "Then start the SW-TPM with:    bash scripts/start_tpm.sh"
