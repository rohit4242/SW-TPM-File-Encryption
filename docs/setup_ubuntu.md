# Ubuntu Setup

Run these commands from the project folder:

```bash
bash scripts/install_ubuntu_dependencies.sh
source .venv/bin/activate
bash scripts/start_swtpm.sh
export TPM2TOOLS_TCTI=swtpm:host=127.0.0.1,port=2321
export TSS2_FAPICONF="$PWD/.tpm-state/fapi-config.json"
bash scripts/setup_tpm.sh
```
