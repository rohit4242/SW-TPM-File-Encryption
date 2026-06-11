#!/usr/bin/env bash
set -euo pipefail

sudo apt update
sudo apt install -y \
  python3 \
  python3-pip \
  python3-venv \
  swtpm \
  tpm2-tools \
  tpm2-abrmd \
  libtss2-dev \
  libtss2-fapi-dev \
  libtss2-tctildr-dev

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

echo "Ubuntu dependencies installed."
echo "Activate the virtual environment with: source .venv/bin/activate"
