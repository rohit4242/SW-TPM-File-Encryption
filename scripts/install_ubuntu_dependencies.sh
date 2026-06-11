#!/usr/bin/env bash
set -euo pipefail

install_if_available() {
  local package="$1"
  if apt-cache show "$package" >/dev/null 2>&1; then
    sudo apt install -y "$package"
  else
    echo "Skipping unavailable optional package: $package"
  fi
}

sudo apt update

sudo apt install -y \
  python3 \
  python3-pip \
  python3-venv \
  swtpm \
  tpm2-tools \
  libtss2-dev

install_if_available python3-cryptography
install_if_available python3-pytest
install_if_available libtss2-tctildr-dev
install_if_available libtss2-tctildr0
install_if_available libtss2-tctildr0t64
install_if_available libtss2-tcti-swtpm0
install_if_available libtss2-tcti-swtpm0t64

python3 -m venv --system-site-packages .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install "cryptography>=42.0.0" "pytest>=8.0.0"

echo "Ubuntu dependencies installed."
echo "Activate the virtual environment with: source .venv/bin/activate"
