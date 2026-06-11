from dataclasses import dataclass
from os import urandom

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ModuleNotFoundError as exc:  # pragma: no cover - exercised before deps are installed.
    AESGCM = None
    InvalidTag = None
    _IMPORT_ERROR = exc
else:
    _IMPORT_ERROR = None

AES_KEY_SIZE = 32
AES_GCM_NONCE_SIZE = 12
ALGORITHM_NAME = "AES-256-GCM"


@dataclass(frozen=True)
class EncryptedBytes:
    nonce: bytes
    ciphertext: bytes


def _require_cryptography() -> None:
    if AESGCM is None:
        raise RuntimeError(
            "Missing Python package 'cryptography'. Install dependencies with "
            "`python -m pip install -r requirements.txt`."
        ) from _IMPORT_ERROR


def generate_aes_key() -> bytes:
    return urandom(AES_KEY_SIZE)


def encrypt_bytes(plaintext: bytes, key: bytes) -> EncryptedBytes:
    _require_cryptography()
    _validate_key(key)
    nonce = urandom(AES_GCM_NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return EncryptedBytes(nonce=nonce, ciphertext=ciphertext)


def decrypt_bytes(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    _require_cryptography()
    _validate_key(key)
    if len(nonce) != AES_GCM_NONCE_SIZE:
        raise ValueError("AES-GCM nonce must be 12 bytes")
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, None)
    except InvalidTag as exc:
        raise ValueError("AES-GCM authentication failed") from exc


def _validate_key(key: bytes) -> None:
    if len(key) != AES_KEY_SIZE:
        raise ValueError("AES-256 key must be 32 bytes")
