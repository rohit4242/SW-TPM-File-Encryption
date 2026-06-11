import json
from dataclasses import asdict, dataclass
from pathlib import Path

FORMAT_VERSION = 1
REQUIRED_FIELDS = {
    "format_version",
    "original_filename",
    "algorithm",
    "nonce_b64",
    "policy",
    "tpm_public_blob",
    "tpm_private_blob",
}


@dataclass(frozen=True)
class EncryptionMetadata:
    original_filename: str
    algorithm: str
    nonce_b64: str
    policy: str
    tpm_public_blob: str
    tpm_private_blob: str
    format_version: int = FORMAT_VERSION
    tpm_key_path: str | None = None
    pcrs: list[int] | None = None
    pcr_values: dict[str, str] | None = None


def save_metadata(path: Path, metadata: EncryptionMetadata) -> None:
    data = asdict(metadata)
    if data["pcrs"] is None:
        data.pop("pcrs")
    if data["pcr_values"] is None:
        data.pop("pcr_values")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def load_metadata(path: Path) -> EncryptionMetadata:
    data = json.loads(path.read_text(encoding="utf-8"))
    _validate_metadata_dict(data)
    return EncryptionMetadata(
        format_version=data["format_version"],
        original_filename=data["original_filename"],
        algorithm=data["algorithm"],
        nonce_b64=data["nonce_b64"],
        policy=data["policy"],
        tpm_public_blob=data["tpm_public_blob"],
        tpm_private_blob=data["tpm_private_blob"],
        tpm_key_path=data.get("tpm_key_path"),
        pcrs=data.get("pcrs"),
        pcr_values=data.get("pcr_values"),
    )


def _validate_metadata_dict(data: dict) -> None:
    missing = sorted(REQUIRED_FIELDS - data.keys())
    if missing:
        raise ValueError(f"missing required metadata field: {missing[0]}")
    if data["format_version"] != FORMAT_VERSION:
        raise ValueError(f"unsupported metadata format version: {data['format_version']}")
