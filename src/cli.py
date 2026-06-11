import argparse
import base64
from pathlib import Path

from .crypto import ALGORITHM_NAME, decrypt_bytes, encrypt_bytes, generate_aes_key
from .errors import AppError
from .metadata import EncryptionMetadata, load_metadata, save_metadata
from .policies import PolicyName, parse_pcrs, validate_policy_inputs
from .tpm import DEFAULT_TCTI, TpmKeyStore, blob_paths

OUTPUT_DIR = Path("outputs")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Encrypt files with AES-GCM and protect AES keys using SW-TPM policies."
    )
    parser.add_argument("--tcti", default=DEFAULT_TCTI, help="TPM TCTI string for SW-TPM.")
    subcommands = parser.add_subparsers(dest="command", required=True)

    encrypt = subcommands.add_parser("encrypt", help="Encrypt a file and seal its AES key in SW-TPM.")
    encrypt.add_argument("input_file", type=Path)
    encrypt.add_argument("--policy", default=PolicyName.PASSWORD.value, choices=[item.value for item in PolicyName])
    encrypt.add_argument("--auth", help="Auth value required by the password policy.")
    encrypt.add_argument("--pcrs", help="Comma-separated PCR indexes for PCR policy, for example: 7 or 7,16.")
    encrypt.add_argument("--output", type=Path, help="Encrypted output path. Defaults to outputs/INPUT.enc.")

    decrypt = subcommands.add_parser("decrypt", help="Decrypt a file after unsealing its AES key.")
    decrypt.add_argument("encrypted_file", type=Path)
    decrypt.add_argument("--auth", help="Auth value required by the password policy.")
    decrypt.add_argument("--pcrs", help="Optional PCR indexes. Must match the metadata for PCR policy.")
    decrypt.add_argument("--output", type=Path, help="Plaintext output path. Defaults to outputs/INPUT.dec.")

    extend_pcr = subcommands.add_parser("extend-pcr", help="Extend one TPM PCR for the PCR policy demo.")
    extend_pcr.add_argument("pcr", type=int, help="PCR index to extend, usually 16 for a demo PCR.")
    extend_pcr.add_argument("--data", default="sw-tpm-file-encryption-demo", help="Text data used for PCR extend.")

    return parser


def run(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "encrypt":
            encrypt_file(args)
        elif args.command == "decrypt":
            decrypt_file(args)
        elif args.command == "extend-pcr":
            extend_pcr(args)
    except AppError as exc:
        parser.exit(status=1, message=f"Error: {exc}\n")
    return 0


def encrypt_file(args: argparse.Namespace) -> None:
    input_file = args.input_file
    if not input_file.is_file():
        raise AppError(f"Input file does not exist: {input_file}")

    policy = validate_policy_inputs(args.policy, args.auth, args.pcrs)
    selected_pcrs = parse_pcrs(args.pcrs) if policy == PolicyName.PCR else None
    output_file = args.output or default_encrypt_output(input_file)
    metadata_file = build_metadata_path(output_file)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    plaintext = input_file.read_bytes()
    aes_key = generate_aes_key()
    encrypted = encrypt_bytes(plaintext, aes_key)

    tpm_store = TpmKeyStore(tcti=args.tcti)
    tpm_store.seal_key(aes_key, output_file, auth=args.auth, pcrs=selected_pcrs)

    output_file.write_bytes(encrypted.ciphertext)
    metadata = EncryptionMetadata(
        original_filename=input_file.name,
        algorithm=ALGORITHM_NAME,
        nonce_b64=base64.b64encode(encrypted.nonce).decode("ascii"),
        policy=policy.value,
        pcrs=selected_pcrs,
    )
    save_metadata(metadata_file, metadata)

    public_blob, private_blob = blob_paths(output_file)
    print(f"Encrypted:  {input_file} -> {output_file}")
    print(f"Metadata:   {metadata_file}")
    print(f"Sealed key: {public_blob} + {private_blob}")


def decrypt_file(args: argparse.Namespace) -> None:
    encrypted_file = args.encrypted_file
    metadata_file = build_metadata_path(encrypted_file)
    if not encrypted_file.is_file():
        raise AppError(f"Encrypted file does not exist: {encrypted_file}")
    if not metadata_file.is_file():
        raise AppError(f"Metadata file does not exist: {metadata_file}")

    metadata = load_metadata(metadata_file)
    tpm_store = TpmKeyStore(tcti=args.tcti)

    if metadata.policy == PolicyName.PCR.value:
        if not metadata.pcrs:
            raise AppError("Metadata does not contain a PCR selection for the PCR policy.")
        if args.pcrs and parse_pcrs(args.pcrs) != metadata.pcrs:
            raise AppError(f"PCR selection mismatch. Metadata requires {metadata.pcrs}.")
        aes_key = tpm_store.unseal_key(encrypted_file, pcrs=metadata.pcrs)
    else:
        if not args.auth:
            raise AppError("Password policy requires --auth.")
        aes_key = tpm_store.unseal_key(encrypted_file, auth=args.auth)

    nonce = base64.b64decode(metadata.nonce_b64)
    plaintext = decrypt_bytes(encrypted_file.read_bytes(), aes_key, nonce)

    output_file = args.output or default_decrypt_output(encrypted_file)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_bytes(plaintext)
    print(f"Decrypted: {encrypted_file} -> {output_file}")


def extend_pcr(args: argparse.Namespace) -> None:
    if args.pcr < 0 or args.pcr > 23:
        raise AppError("PCR indexes must be between 0 and 23.")

    tpm_store = TpmKeyStore(tcti=args.tcti)
    new_value = tpm_store.extend_pcr(args.pcr, args.data.encode("utf-8"))
    print(f"Extended PCR {args.pcr}. New value: {new_value}")


def default_encrypt_output(input_file: Path) -> Path:
    return OUTPUT_DIR / f"{input_file.name}.enc"


def default_decrypt_output(encrypted_file: Path) -> Path:
    name = encrypted_file.name
    if name.endswith(".enc"):
        return OUTPUT_DIR / f"{name[:-4]}.dec"
    return OUTPUT_DIR / f"{name}.dec"


def build_metadata_path(encrypted_file: Path) -> Path:
    return encrypted_file.with_name(encrypted_file.name + ".json")
