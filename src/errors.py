class AppError(Exception):
    """Base error shown as a clean CLI message."""


class TpmError(AppError):
    """Raised when SW-TPM key sealing or unsealing fails."""
