from dataclasses import dataclass
from os import urandom

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import AppError

AES_KEY_SIZE = 32
AES_GCM_NONCE_SIZE = 12
ALGORITHM_NAME = "AES-256-GCM"


@dataclass(frozen=True)
class EncryptedBytes:
    nonce: bytes
    ciphertext: bytes


def generate_aes_key() -> bytes:
    return urandom(AES_KEY_SIZE)


def encrypt_bytes(plaintext: bytes, key: bytes) -> EncryptedBytes:
    _validate_key(key)
    nonce = urandom(AES_GCM_NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return EncryptedBytes(nonce=nonce, ciphertext=ciphertext)


def decrypt_bytes(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    _validate_key(key)
    if len(nonce) != AES_GCM_NONCE_SIZE:
        raise AppError("AES-GCM nonce must be 12 bytes.")
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, None)
    except InvalidTag as exc:
        raise AppError("AES-GCM authentication failed. The file or key is corrupted.") from exc


def _validate_key(key: bytes) -> None:
    if len(key) != AES_KEY_SIZE:
        raise AppError("AES-256 key must be 32 bytes.")
