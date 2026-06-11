# SW-TPM File Encryption

Course project for Embedded System Security:

**Encryption of files using different SW-TPM policies with Python.**

Files are encrypted with AES-256-GCM in Python. The random AES key is sealed inside a software TPM (`swtpm`) using `tpm2-tools`, protected by either a password policy or a PCR policy. The TPM only releases the key when the policy check succeeds.

## How It Works

1. Python generates a random 256-bit AES key.
2. Python encrypts the file with AES-GCM.
3. The AES key is sealed as a TPM object (`tpm2_create`):
   - **password policy**: the object requires the auth value on unseal.
   - **PCR policy**: the object is bound to the current PCR values with `tpm2_policypcr`. The TPM itself refuses to unseal if a PCR changed.
4. Decryption unseals the AES key from the TPM and decrypts the file.

The TPM protects the key and enforces the policy; it does not do bulk file encryption.

## Folder Structure

```text
src/                Python source (CLI, crypto, metadata, TPM backend)
scripts/            Setup, SW-TPM start/stop, and demo scripts
examples/sample.txt Demo input file
outputs/            Generated artifacts
tests/              Unit tests
```

For every encrypted file, three companion files are written next to it:

```text
outputs/sample.txt.enc        AES-GCM ciphertext
outputs/sample.txt.enc.json   Metadata (nonce, policy, PCR selection)
outputs/sample.txt.enc.pub    TPM sealed object, public part
outputs/sample.txt.enc.priv   TPM sealed object, private part
```

The metadata never contains the AES key or the password.

## Quick Start

Supported platforms: Ubuntu, Ubuntu on WSL2, Kali Linux.

First time, from the project folder:

```bash
bash scripts/install_ubuntu_dependencies.sh
source .venv/bin/activate
bash scripts/start_swtpm.sh
export TPM2TOOLS_TCTI=swtpm:host=127.0.0.1,port=2321
```

(Stop SW-TPM later with `bash scripts/stop_swtpm.sh`.)

Encrypt and decrypt the sample file with a password:

```bash
python -m src.main encrypt examples/sample.txt --policy password --auth mypass
python -m src.main decrypt outputs/sample.txt.enc --auth mypass
cmp examples/sample.txt outputs/sample.txt.dec   # no output = files match
```

Expected output:

```text
Encrypted:  examples/sample.txt -> outputs/sample.txt.enc
Metadata:   outputs/sample.txt.enc.json
Sealed key: outputs/sample.txt.enc.pub + outputs/sample.txt.enc.priv

Decrypted: outputs/sample.txt.enc -> outputs/sample.txt.dec
```

A wrong password is rejected by the TPM:

```bash
python -m src.main decrypt outputs/sample.txt.enc --auth wrongpass
# Error: TPM authorization failed. Check the --auth value.
```

## Usage Examples

### Password policy

```bash
python -m src.main encrypt examples/sample.txt --policy password --auth mypass
python -m src.main decrypt outputs/sample.txt.enc --auth mypass
```

### PCR policy

PCR 16 is a convenient demo PCR because it can be extended freely:

```bash
python -m src.main encrypt examples/sample.txt --policy pcr --pcrs 16
python -m src.main decrypt outputs/sample.txt.enc                    # works: PCR unchanged
python -m src.main extend-pcr 16 --data changed-state                # simulate a system change
python -m src.main decrypt outputs/sample.txt.enc
# Error: TPM policy check failed. The current PCR values do not match the sealed policy.
```

Multiple PCRs are also supported: `--pcrs 7,16`.

### Encrypting your own files

```bash
python -m src.main encrypt /path/to/report.pdf --policy password --auth secret123
python -m src.main decrypt outputs/report.pdf.enc --auth secret123 --output report-restored.pdf
```

Keep the `.enc`, `.json`, `.pub`, and `.priv` files together; all four are needed for decryption.

## Command Reference

```text
python -m src.main [--tcti TCTI] COMMAND ...
```

| Command | Arguments | Description |
| --- | --- | --- |
| `encrypt INPUT` | `--policy {password,pcr}`, `--auth VALUE`, `--pcrs LIST`, `--output PATH` | Encrypt a file and seal its AES key in SW-TPM. Default output: `outputs/INPUT.enc`. |
| `decrypt FILE.enc` | `--auth VALUE` (password policy), `--pcrs LIST` (optional check), `--output PATH` | Unseal the AES key and decrypt. Default output: `outputs/FILE.dec`. |
| `extend-pcr INDEX` | `--data TEXT` | Extend one PCR to demonstrate the PCR policy failing. |

`--tcti` defaults to `swtpm:host=127.0.0.1,port=2321`; it only needs changing if SW-TPM runs elsewhere.

## Metadata Example

`outputs/sample.txt.enc.json` for a PCR-policy file:

```json
{
  "algorithm": "AES-256-GCM",
  "format_version": 1,
  "nonce_b64": "q1Yl8mGgZbXjW8Qx",
  "original_filename": "sample.txt",
  "pcrs": [16],
  "policy": "pcr"
}
```

It stores only what decryption needs (nonce, policy, PCR selection) — never the AES key or the password.

## Demos

```bash
bash scripts/demo.sh --clean       # password policy: encrypt, decrypt, wrong-auth failure
bash scripts/demo_pcr.sh --clean   # PCR policy: encrypt, decrypt, extend PCR, expected failure
```

## Tests

```bash
python -m pytest
```

## Troubleshooting

- **SW-TPM is not running**: `bash scripts/start_swtpm.sh` and export the TCTI shown above.
- **`Missing command 'tpm2_...'`**: run `bash scripts/install_ubuntu_dependencies.sh`.
- **TPM is in dictionary-attack lockout**: earlier wrong-password attempts locked the TPM. Run `tpm2_clearlockout` and retry. Newly sealed objects use the `noda` attribute, so they no longer trigger the lockout.
- **`out of memory for object contexts`**: run `tpm2_flushcontext -t`. The Python backend also flushes transient objects around every TPM operation.
- **Old encrypted files fail to decrypt**: files sealed before a SW-TPM state reset (deleting `.tpm-state/`) can never be unsealed again. Re-encrypt them.

## Security Notes

- AES-GCM provides confidentiality and tamper detection for the file content.
- The AES key exists in plaintext only inside the TPM and briefly in process memory.
- The PCR policy is enforced by the TPM itself, not by Python checks.
- This is a course demonstration, not production key-management software.
