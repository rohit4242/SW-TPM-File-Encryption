# SW-TPM File Encryption

Course project for Embedded System Security:

**Encryption of files using different SW-TPM policies with Python.**

The project encrypts files with AES-256-GCM in Python and protects the AES file key with a software TPM through `tpm2-tools`. The code is intentionally small and demo-friendly so the flow is easy to explain during evaluation.

## Architecture

1. Python generates a random 256-bit AES key.
2. Python encrypts the file with AES-GCM.
3. `tpm2-tools` asks SW-TPM to seal the AES key as a TPM object.
4. Decryption unseals the AES key only after the selected policy check succeeds.
5. Python decrypts the file with the unsealed AES key.

The TPM is used for key protection and policy checks, not for bulk file encryption.

## Folder Structure

```text
sw-tpm-file-encryption/
  src/                       Python source files
  scripts/                   Ubuntu setup and demo scripts
  examples/sample.txt        Input file for demo
  outputs/                   Generated encrypted/decrypted artifacts
  tests/                     Unit tests
  docs/                      Short companion documentation
```

Generated demo files go under `outputs/`:

```text
outputs/sample.txt.enc
outputs/sample.txt.enc.json
outputs/sample.txt.enc.pub
outputs/sample.txt.enc.priv
outputs/sample.txt.dec
```

## Requirements

Target platform:

- Ubuntu Linux
- Ubuntu on WSL2
- Kali Linux rolling

System packages:

- `swtpm`
- `tpm2-tools`
- `tpm2-tss` libraries
- Python 3.10 or newer

Python packages:

- `cryptography`
- `pytest`

## Setup on Ubuntu or WSL2

From inside this project folder:

```bash
bash scripts/install_ubuntu_dependencies.sh
source .venv/bin/activate
```

The install script also supports Kali Linux. Kali does not currently provide separate `libtss2-fapi-dev` and `libtss2-tctildr-dev` packages, so the script installs `libtss2-dev` and then installs distro-specific optional TPM runtime packages only when they are available.

Start SW-TPM:

```bash
bash scripts/start_swtpm.sh
export TPM2TOOLS_TCTI=swtpm:host=127.0.0.1,port=2321
```

Check TPM connectivity:

```bash
bash scripts/setup_tpm.sh
```

Stop SW-TPM when finished:

```bash
bash scripts/stop_swtpm.sh
```

## Basic Commands

Show CLI help:

```bash
python -m src.main --help
python -m src.main encrypt --help
python -m src.main decrypt --help
```

Encrypt with password/auth policy:

```bash
python -m src.main encrypt examples/sample.txt --policy password --auth mypass
```

Decrypt with password/auth policy:

```bash
python -m src.main decrypt outputs/sample.txt.enc --auth mypass
```

Compare original and decrypted files:

```bash
cmp examples/sample.txt outputs/sample.txt.dec
```

No output from `cmp` means the files match.

## Password Policy Demo

Run:

```bash
bash scripts/demo.sh --clean
```

The demo:

1. Checks TPM connectivity.
2. Encrypts `examples/sample.txt`.
3. Decrypts with the correct auth value.
4. Compares original and decrypted files.
5. Attempts decrypt with the wrong auth value and expects failure.

## PCR Policy Demo

Run:

```bash
bash scripts/demo_pcr.sh --clean
```

The PCR demo uses PCR 16 by default because it is convenient for software-demo experiments.

The demo:

1. Encrypts `examples/sample.txt` with `--policy pcr --pcrs 16`.
2. Stores the encryption-time PCR value in metadata.
3. Decrypts successfully while PCR 16 still matches.
4. Extends PCR 16 with new demo data.
5. Attempts decrypt again and expects failure because the PCR value changed.

Manual PCR commands:

```bash
python -m src.main encrypt examples/sample.txt --policy pcr --pcrs 16
python -m src.main decrypt outputs/sample.txt.enc --pcrs 16
python -m src.main extend-pcr 16 --data changed-demo-state
python -m src.main decrypt outputs/sample.txt.enc --pcrs 16
```

## Metadata

For `outputs/sample.txt.enc`, metadata is written to:

```text
outputs/sample.txt.enc.json
```

The metadata stores:

- format version
- original filename
- algorithm name
- AES-GCM nonce
- selected policy
- TPM key path
- TPM public/private blob filenames
- PCR selection and PCR values for PCR policy

It does not store the AES key or password.

## Run Tests

After installing dependencies:

```bash
python -m unittest discover -s tests -v
```

You can also run:

```bash
python -m pytest
```

## Troubleshooting

### SW-TPM is not running

Run:

```bash
bash scripts/start_swtpm.sh
export TPM2TOOLS_TCTI=swtpm:host=127.0.0.1,port=2321
bash scripts/setup_tpm.sh
```

### `Missing Python package 'cryptography'`

Run:

```bash
source .venv/bin/activate
python -m pip install -r requirements.txt
```

### Missing TPM command

If you see an error such as `Missing command 'tpm2_createprimary'`, install the TPM tools:

```bash
bash scripts/install_ubuntu_dependencies.sh
```

### Wrong auth value

For password policy, wrong `--auth` should fail. This demonstrates that SW-TPM refuses to unseal the protected AES key.

### PCR mismatch

For PCR policy, decrypt fails if the current PCR value is different from the value stored during encryption.

### Repeated demo runs

Use the `--clean` flag:

```bash
bash scripts/demo.sh --clean
bash scripts/demo_pcr.sh --clean
```

## Security Notes

- AES-GCM protects file confidentiality and detects tampering.
- The AES key is not stored in plaintext metadata.
- SW-TPM protects the AES key and participates in auth/PCR policy checks.
- This is a course project and demonstration, not production key-management software.
