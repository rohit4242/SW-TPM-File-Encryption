class AppError(Exception):
    """Base error shown as a clean CLI message."""


class CryptoError(AppError):
    """Raised when file encryption or decryption fails."""


class MetadataError(AppError):
    """Raised when encrypted-file metadata is invalid."""


class TpmError(AppError):
    """Raised when SW-TPM key sealing or unsealing fails."""
