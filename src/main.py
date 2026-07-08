"""Command line interface.

Commands:
    encrypt     Encrypt a file with AES-256-GCM and seal the key in the SW-TPM.
    decrypt     Unseal the key from the SW-TPM and decrypt the file.
    extend-pcr  Extend one PCR to demonstrate the PCR policy failing.

For every encrypted file, three companion files are written next to it:
    <file>.enc.json   metadata (nonce, policy, PCR selection - never the key)
    <file>.enc.pub    sealed key, public part
    <file>.enc.priv   sealed key, private part (encrypted by the TPM)
"""

import argparse
import base64
import hashlib
import json
from pathlib import Path

from . import crypto
from .tpm import DEFAULT_TCTI, TpmError, TpmKeyStore, blob_paths

OUTPUT_DIR = Path("outputs")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m src.main",
        description="Encrypt files with AES-256-GCM and protect the AES key with SW-TPM policies.",
    )
    parser.add_argument("--tcti", default=DEFAULT_TCTI, help="TCTI connection string for the SW-TPM.")
    commands = parser.add_subparsers(dest="command", required=True)

    encrypt = commands.add_parser("encrypt", help="Encrypt a file and seal its AES key in the SW-TPM.")
    encrypt.add_argument("input_file", type=Path)
    encrypt.add_argument("--policy", default="password", choices=["password", "pcr"])
    encrypt.add_argument("--auth", help="Password required by the password policy.")
    encrypt.add_argument("--pcrs", help="Comma-separated PCR indexes for the PCR policy, e.g. 16 or 7,16.")
    encrypt.add_argument("--output", type=Path, help="Encrypted output path. Default: outputs/INPUT.enc")

    decrypt = commands.add_parser("decrypt", help="Unseal the AES key from the SW-TPM and decrypt a file.")
    decrypt.add_argument("encrypted_file", type=Path)
    decrypt.add_argument("--auth", help="Password required by the password policy.")
    decrypt.add_argument("--output", type=Path, help="Plaintext output path. Default: outputs/INPUT.dec")

    extend = commands.add_parser("extend-pcr", help="Extend one PCR to simulate a system change.")
    extend.add_argument("pcr", type=int, help="PCR index to extend; 16 is a free demo PCR.")
    extend.add_argument("--data", default="demo-change", help="Text whose SHA-256 digest extends the PCR.")

    return parser


def run(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handlers = {"encrypt": encrypt_file, "decrypt": decrypt_file, "extend-pcr": extend_pcr}
    try:
        handlers[args.command](args)
    except (TpmError, ValueError) as exc:
        parser.exit(status=1, message=f"Error: {exc}\n")
    return 0


def encrypt_file(args: argparse.Namespace) -> None:
    if not args.input_file.is_file():
        raise ValueError(f"Input file does not exist: {args.input_file}")
    pcrs = parse_pcrs(args.pcrs) if args.policy == "pcr" else None
    if args.policy == "password" and not args.auth:
        raise ValueError("Password policy requires --auth.")
    if args.policy == "pcr" and not pcrs:
        raise ValueError("PCR policy requires --pcrs.")

    output_file = args.output or OUTPUT_DIR / f"{args.input_file.name}.enc"
    output_file.parent.mkdir(parents=True, exist_ok=True)

    key = crypto.generate_key()
    nonce, ciphertext = crypto.encrypt(args.input_file.read_bytes(), key)

    TpmKeyStore(args.tcti).seal_key(key, output_file, auth=args.auth, pcrs=pcrs)
    output_file.write_bytes(ciphertext)
    save_metadata(
        metadata_path(output_file),
        {
            "algorithm": crypto.ALGORITHM,
            "nonce_b64": base64.b64encode(nonce).decode("ascii"),
            "original_filename": args.input_file.name,
            "policy": args.policy,
            "pcrs": pcrs,
        },
    )

    public_blob, private_blob = blob_paths(output_file)
    print(f"Encrypted:  {args.input_file} -> {output_file}")
    print(f"Metadata:   {metadata_path(output_file)}")
    print(f"Sealed key: {public_blob} + {private_blob}")


def decrypt_file(args: argparse.Namespace) -> None:
    if not args.encrypted_file.is_file():
        raise ValueError(f"Encrypted file does not exist: {args.encrypted_file}")
    metadata = load_metadata(metadata_path(args.encrypted_file))

    if metadata["policy"] == "password" and not args.auth:
        raise ValueError("Password policy requires --auth.")
    key = TpmKeyStore(args.tcti).unseal_key(args.encrypted_file, auth=args.auth, pcrs=metadata["pcrs"])

    nonce = base64.b64decode(metadata["nonce_b64"])
    plaintext = crypto.decrypt(args.encrypted_file.read_bytes(), key, nonce)

    output_file = args.output or OUTPUT_DIR / f"{args.encrypted_file.name.removesuffix('.enc')}.dec"
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_bytes(plaintext)
    print(f"Decrypted: {args.encrypted_file} -> {output_file}")


def extend_pcr(args: argparse.Namespace) -> None:
    if not 0 <= args.pcr <= 23:
        raise ValueError("PCR indexes must be between 0 and 23.")
    digest = hashlib.sha256(args.data.encode("utf-8")).digest()
    new_value = TpmKeyStore(args.tcti).extend_pcr(args.pcr, digest)
    print(f"Extended PCR {args.pcr}. New value: {new_value}")


def parse_pcrs(pcrs: str | None) -> list[int]:
    """Parse '7,16' into [7, 16], validating the PCR indexes."""
    try:
        values = [int(item) for item in (pcrs or "").split(",") if item.strip()]
    except ValueError:
        raise ValueError("PCR indexes must be integers, e.g. --pcrs 16 or --pcrs 7,16.") from None
    if not values:
        raise ValueError("PCR policy requires at least one PCR index, e.g. --pcrs 16.")
    if len(values) != len(set(values)):
        raise ValueError("PCR indexes must not contain duplicates.")
    if any(not 0 <= value <= 23 for value in values):
        raise ValueError("PCR indexes must be between 0 and 23.")
    return values


def metadata_path(encrypted_file: Path) -> Path:
    return Path(f"{encrypted_file}.json")


def save_metadata(path: Path, metadata: dict) -> None:
    path.write_text(json.dumps(metadata, indent=2, sort_keys=True), encoding="utf-8")


def load_metadata(path: Path) -> dict:
    if not path.is_file():
        raise ValueError(f"Metadata file does not exist: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    raise SystemExit(run())
