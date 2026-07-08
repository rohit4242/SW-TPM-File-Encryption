# SW-TPM File Encryption

Course project for **Embedded Security** (Selected Topics of Embedded Software Development I):

**Encryption of files using different SW-TPM policies (Python).**

Files are encrypted with AES-256-GCM. The random AES key is sealed inside a software TPM (`swtpm`) through the official Python bindings **tpm2-pytss**. The TPM only releases the key when the chosen policy is satisfied:

- **password policy** – the TPM requires the correct password on unseal.
- **PCR policy** – the TPM requires the selected PCR (Platform Configuration Register) values to be unchanged since encryption. Extending a PCR (a simulated system change) blocks the key.

## How It Works

1. Python generates a random 256-bit AES key and encrypts the file with AES-GCM (`src/crypto.py`).
2. The AES key is sealed as a TPM keyedhash object under an RSA primary key (`src/tpm.py`, ESAPI calls `CreatePrimary` + `Create`).
   - password policy: the object carries the auth value (`userWithAuth` attribute).
   - PCR policy: the object carries a `PolicyPCR` digest computed in a trial session; only a policy session with matching PCRs can unseal it.
3. Decryption loads the sealed object (`Load`) and unseals the key (`Unseal`); the TPM itself enforces the policy. Python then decrypts the file.

The TPM protects the key and enforces the policy; it never sees the file content.

## Folder Structure

```text
src/         main.py (CLI) - crypto.py (AES-GCM) - tpm.py (tpm2-pytss backend)
scripts/     setup.sh - start_tpm.sh - stop_tpm.sh - demo.sh
examples/    sample.txt demo input
outputs/     generated files (ciphertext, metadata, sealed key blobs)
report/      scientific report (report.md)
```

For every encrypted file, three companion files are written next to it:

```text
outputs/sample.txt.enc        AES-GCM ciphertext
outputs/sample.txt.enc.json   metadata (nonce, policy, PCR selection)
outputs/sample.txt.enc.pub    sealed AES key, public part
outputs/sample.txt.enc.priv   sealed AES key, private part (encrypted by the TPM)
```

The metadata never contains the AES key or the password. All four files are needed for decryption.

## Quick Start

Supported platforms: Ubuntu 22.04+, Ubuntu on WSL2, Kali Linux.

```bash
bash scripts/setup.sh            # first time only: install packages + venv
source .venv/bin/activate
bash scripts/start_tpm.sh        # start the SW-TPM emulator
```

Encrypt and decrypt the sample file with a password:

```bash
python -m src.main encrypt examples/sample.txt --policy password --auth mypass
python -m src.main decrypt outputs/sample.txt.enc --auth mypass
cmp examples/sample.txt outputs/sample.txt.dec    # no output = files match
```

A wrong password is rejected by the TPM itself:

```bash
python -m src.main decrypt outputs/sample.txt.enc --auth wrongpass
# Error: TPM authorization failed. Check the --auth value.
```

Stop the emulator later with `bash scripts/stop_tpm.sh`.

## PCR Policy

PCR 16 is a convenient demo PCR because it can be extended freely:

```bash
python -m src.main encrypt examples/sample.txt --policy pcr --pcrs 16
python -m src.main decrypt outputs/sample.txt.enc            # works: PCR unchanged
python -m src.main extend-pcr 16 --data changed-state        # simulate a system change
python -m src.main decrypt outputs/sample.txt.enc
# Error: TPM policy check failed. The current PCR values do not match the sealed policy.
```

Multiple PCRs are supported: `--pcrs 7,16`.

## Command Reference

```text
python -m src.main [--tcti TCTI] COMMAND ...
```

| Command | Arguments | Description |
| --- | --- | --- |
| `encrypt INPUT` | `--policy {password,pcr}`, `--auth VALUE`, `--pcrs LIST`, `--output PATH` | Encrypt a file and seal its AES key in the SW-TPM. Default output: `outputs/INPUT.enc` |
| `decrypt FILE.enc` | `--auth VALUE` (password policy), `--output PATH` | Unseal the AES key and decrypt. Default output: `outputs/FILE.dec` |
| `extend-pcr INDEX` | `--data TEXT` | Extend one PCR to demonstrate the PCR policy failing |

`--tcti` defaults to `swtpm:host=127.0.0.1,port=2321` and only needs changing if the SW-TPM runs elsewhere.

## Demo

One script runs both policies end to end, including the expected failure cases:

```bash
bash scripts/demo.sh
```

## Troubleshooting

- **Cannot connect to SW-TPM**: start it with `bash scripts/start_tpm.sh`.
- **`ModuleNotFoundError: tpm2_pytss`**: activate the venv (`source .venv/bin/activate`) or rerun `bash scripts/setup.sh`.
- **Old encrypted files fail to decrypt**: files sealed before a SW-TPM state reset (deleting `.tpm-state/`) can never be unsealed again. Re-encrypt them.

## Security Notes

- AES-GCM provides confidentiality and tamper detection for the file content.
- The AES key exists in plaintext only inside the TPM and briefly in process memory.
- Both policies are enforced by the TPM itself, not by Python checks.
- This is a course demonstration, not production key-management software.
