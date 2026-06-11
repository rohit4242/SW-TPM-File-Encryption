# Project Design

This project uses hybrid encryption:

- Python encrypts file bytes with AES-256-GCM.
- `tpm2-tools` asks SW-TPM to seal the AES key as a TPM object.
- The CLI releases the key only after the selected policy check succeeds.

Implemented policies:

- Password/auth policy.
- PCR policy using SW-TPM PCR reads/extends for the demo state check.

Stretch goal:

- Policy OR with multiple approved states.
