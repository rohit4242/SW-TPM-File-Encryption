from dataclasses import dataclass
from hashlib import sha256
from os import environ
from pathlib import Path

from .errors import TpmError
from .policies import auth_callback

DEFAULT_TCTI = "swtpm:host=127.0.0.1,port=2321"
DEFAULT_FAPI_BASE_PATH = "/HS/SRK/sw_tpm_file_encryption"


@dataclass(frozen=True)
class SealedKeyInfo:
    fapi_path: str
    public_blob_path: Path
    private_blob_path: Path
    policy_blob_path: Path | None = None


class TpmKeyStore:
    def __init__(self, tcti: str = DEFAULT_TCTI, base_path: str = DEFAULT_FAPI_BASE_PATH):
        self.tcti = tcti
        self.base_path = base_path.rstrip("/")

    def seal_key(self, key: bytes, auth: str, output_prefix: Path) -> SealedKeyInfo:
        fapi = self._open_fapi()
        fapi_path = self._unique_fapi_path(output_prefix, key)
        public_blob_path = output_prefix.with_suffix(output_prefix.suffix + ".pub")
        private_blob_path = output_prefix.with_suffix(output_prefix.suffix + ".priv")
        policy_blob_path = output_prefix.with_suffix(output_prefix.suffix + ".policy.json")

        try:
            self._provision_if_needed(fapi)
            fapi.set_auth_callback(auth_callback, auth)
            fapi.create_seal(fapi_path, data=key, auth_value=auth, exists_ok=False)
            public_blob, private_blob, policy = fapi.get_tpm_blobs(fapi_path)
            public_blob_path.write_bytes(public_blob.marshal())
            private_blob_path.write_bytes(private_blob.marshal())
            if policy:
                policy_blob_path.write_text(str(policy), encoding="utf-8")
            else:
                policy_blob_path = None
        except Exception as exc:
            raise TpmError(f"Failed to seal AES key in SW-TPM: {exc}") from exc
        finally:
            self._close_fapi(fapi)

        return SealedKeyInfo(
            fapi_path=fapi_path,
            public_blob_path=public_blob_path,
            private_blob_path=private_blob_path,
            policy_blob_path=policy_blob_path,
        )

    def unseal_key(self, fapi_path: str, auth: str) -> bytes:
        fapi = self._open_fapi()
        try:
            fapi.set_auth_callback(auth_callback, auth)
            return fapi.unseal(fapi_path)
        except Exception as exc:
            raise TpmError(f"Failed to unseal AES key from SW-TPM: {exc}") from exc
        finally:
            self._close_fapi(fapi)

    def read_pcrs(self, pcrs: list[int]) -> dict[str, str]:
        """Read selected TPM PCR values as lowercase hexadecimal strings."""
        fapi = self._open_fapi()
        try:
            values = {}
            for pcr in pcrs:
                pcr_value, _event_log = fapi.pcr_read(pcr)
                values[str(pcr)] = bytes(pcr_value).hex()
            return values
        except Exception as exc:
            raise TpmError(f"Failed to read PCR values from SW-TPM: {exc}") from exc
        finally:
            self._close_fapi(fapi)

    def extend_pcr(self, pcr: int, data: bytes) -> str:
        """Extend one PCR and return the new PCR value as hexadecimal text."""
        fapi = self._open_fapi()
        try:
            pcr_value, _event_log = fapi.pcr_extend(pcr, data)
            return bytes(pcr_value).hex()
        except Exception as exc:
            raise TpmError(f"Failed to extend PCR {pcr}: {exc}") from exc
        finally:
            self._close_fapi(fapi)

    def _open_fapi(self):
        try:
            from tpm2_pytss import FAPI
        except ModuleNotFoundError as exc:
            raise TpmError(
                "Missing Python package 'tpm2-pytss'. Install it on Ubuntu with "
                "`python -m pip install -r requirements.txt` after installing TPM system libraries."
            ) from exc

        try:
            if self.tcti == DEFAULT_TCTI:
                return FAPI()
            return FAPI(self.tcti)
        except Exception as exc:
            fapi_config = environ.get("TSS2_FAPICONF", "not set")
            raise TpmError(
                f"Could not connect to SW-TPM using TCTI '{self.tcti}'. "
                f"TSS2_FAPICONF is {fapi_config}. "
                "Start the emulator with scripts/start_swtpm.sh and export the variables it prints."
            ) from exc

    @staticmethod
    def _provision_if_needed(fapi) -> None:
        try:
            fapi.provision(is_provisioned_ok=True)
        except TypeError:
            try:
                fapi.provision()
            except Exception:
                pass

    @staticmethod
    def _close_fapi(fapi) -> None:
        try:
            fapi.close()
        except Exception:
            pass

    def _unique_fapi_path(self, output_prefix: Path, key: bytes) -> str:
        digest = sha256(str(output_prefix.resolve()).encode("utf-8") + key).hexdigest()[:16]
        safe_name = "".join(ch if ch.isalnum() else "_" for ch in output_prefix.name)
        return f"{self.base_path}/{safe_name}_{digest}"
