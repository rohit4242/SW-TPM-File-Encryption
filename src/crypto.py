"""File encryption with AES-256-GCM.

AES-GCM is an authenticated cipher: decryption fails loudly if the
ciphertext was tampered with or the wrong key is used. The TPM does not
encrypt the file itself; it only protects the AES key (see `src/tpm.py`).
"""

from os import urandom

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_SIZE = 32  # AES-256
NONCE_SIZE = 12  # recommended nonce size for GCM
ALGORITHM = "AES-256-GCM"


def generate_key() -> bytes:
    """Return a fresh random 256-bit AES key."""
    return urandom(KEY_SIZE)


def encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """Encrypt `plaintext` and return (nonce, ciphertext)."""
    _check_key(key)
    nonce = urandom(NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce, ciphertext


def decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    """Decrypt `ciphertext`; raises ValueError if the key or data is wrong."""
    _check_key(key)
    if len(nonce) != NONCE_SIZE:
        raise ValueError("AES-GCM nonce must be 12 bytes.")
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, None)
    except InvalidTag as exc:
        raise ValueError("AES-GCM authentication failed. The file or key is corrupted.") from exc

def _check_key(key: bytes) -> None:
    if len(key) != KEY_SIZE:
        raise ValueError("AES-256 key must be 32 bytes.")

