# Ubuntu Setup

Run these commands from the project folder:

```bash
bash scripts/install_ubuntu_dependencies.sh
source .venv/bin/activate
bash scripts/start_swtpm.sh
export TPM2TOOLS_TCTI=swtpm:host=127.0.0.1,port=2321
bash scripts/setup_tpm.sh
```

On Kali Linux, the installer skips Ubuntu-only TPM development package names such as `libtss2-fapi-dev` and uses Kali's available `libtss2-dev` package plus optional runtime packages.
