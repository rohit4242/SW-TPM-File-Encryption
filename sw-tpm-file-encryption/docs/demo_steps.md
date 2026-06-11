# Demo Steps

```bash
source .venv/bin/activate
bash scripts/start_swtpm.sh
export TPM2TOOLS_TCTI=swtpm:host=127.0.0.1,port=2321
export TSS2_FAPICONF="$PWD/.tpm-state/fapi-config.json"
bash scripts/demo.sh --clean
bash scripts/demo_pcr.sh --clean
```

The password demo verifies correct auth and wrong-auth failure. The PCR demo verifies decrypt success before a PCR change and decrypt failure after PCR extension.
