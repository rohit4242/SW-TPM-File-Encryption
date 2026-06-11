import json
from dataclasses import asdict, dataclass
from pathlib import Path

from .errors import AppError

FORMAT_VERSION = 1
REQUIRED_FIELDS = {"format_version", "original_filename", "algorithm", "nonce_b64", "policy"}


@dataclass(frozen=True)
class EncryptionMetadata:
    original_filename: str
    algorithm: str
    nonce_b64: str
    policy: str
    pcrs: list[int] | None = None
    format_version: int = FORMAT_VERSION


def save_metadata(path: Path, metadata: EncryptionMetadata) -> None:
    data = asdict(metadata)
    if data["pcrs"] is None:
        data.pop("pcrs")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def load_metadata(path: Path) -> EncryptionMetadata:
    data = json.loads(path.read_text(encoding="utf-8"))
    missing = sorted(REQUIRED_FIELDS - data.keys())
    if missing:
        raise AppError(f"Missing required metadata field: {missing[0]}")
    if data["format_version"] != FORMAT_VERSION:
        raise AppError(f"Unsupported metadata format version: {data['format_version']}")
    return EncryptionMetadata(
        original_filename=data["original_filename"],
        algorithm=data["algorithm"],
        nonce_b64=data["nonce_b64"],
        policy=data["policy"],
        pcrs=data.get("pcrs"),
        format_version=data["format_version"],
    )
