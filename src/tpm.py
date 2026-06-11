from dataclasses import dataclass
from hashlib import sha256
from os import environ
from pathlib import Path
import re
import subprocess
import tempfile

from .errors import TpmError

DEFAULT_TCTI = "swtpm:host=127.0.0.1,port=2321"
DEFAULT_FAPI_BASE_PATH = "tpm2-tools/sealed-keys"


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
        fapi_path = self._unique_fapi_path(output_prefix, key)
        public_blob_path = output_prefix.with_suffix(output_prefix.suffix + ".pub")
        private_blob_path = output_prefix.with_suffix(output_prefix.suffix + ".priv")

        with tempfile.TemporaryDirectory() as directory:
            temp_dir = Path(directory)
            primary_context = temp_dir / "primary.ctx"
            key_input = temp_dir / "aes.key"
            key_input.write_bytes(key)

            self._run(["tpm2_createprimary", "-Q", "-C", "o", "-G", "rsa", "-c", str(primary_context)])
            self._run(
                [
                    "tpm2_create",
                    "-Q",
                    "-C",
                    str(primary_context),
                    "-u",
                    str(public_blob_path),
                    "-r",
                    str(private_blob_path),
                    "-i",
                    str(key_input),
                    "-p",
                    auth,
                ]
            )

        return SealedKeyInfo(
            fapi_path=fapi_path,
            public_blob_path=public_blob_path,
            private_blob_path=private_blob_path,
        )

    def unseal_key(self, fapi_path: str, auth: str) -> bytes:
        public_blob_path, private_blob_path = self._paths_from_fapi_path(fapi_path)
        if not public_blob_path.is_file() or not private_blob_path.is_file():
            raise TpmError("TPM sealed object blobs are missing beside the encrypted file.")

        with tempfile.TemporaryDirectory() as directory:
            temp_dir = Path(directory)
            primary_context = temp_dir / "primary.ctx"
            sealed_context = temp_dir / "sealed.ctx"
            unsealed_output = temp_dir / "aes.key"

            self._run(["tpm2_createprimary", "-Q", "-C", "o", "-G", "rsa", "-c", str(primary_context)])
            self._run(
                [
                    "tpm2_load",
                    "-Q",
                    "-C",
                    str(primary_context),
                    "-u",
                    str(public_blob_path),
                    "-r",
                    str(private_blob_path),
                    "-c",
                    str(sealed_context),
                ]
            )
            self._run(["tpm2_unseal", "-Q", "-c", str(sealed_context), "-p", auth, "-o", str(unsealed_output)])
            return unsealed_output.read_bytes()

    def read_pcrs(self, pcrs: list[int]) -> dict[str, str]:
        """Read selected TPM PCR values as lowercase hexadecimal strings."""
        values = {}
        for pcr in pcrs:
            result = self._run(["tpm2_pcrread", f"sha256:{pcr}"])
            match = re.search(rf"\b{pcr}:\s*0x([0-9a-fA-F]+)", result.stdout)
            if not match:
                raise TpmError(f"Could not parse PCR {pcr} from tpm2_pcrread output.")
            values[str(pcr)] = match.group(1).lower()
        return values

    def extend_pcr(self, pcr: int, data: bytes) -> str:
        """Extend one PCR and return the new PCR value as hexadecimal text."""
        digest = sha256(data).hexdigest()
        self._run(["tpm2_pcrextend", f"{pcr}:sha256={digest}"])
        return self.read_pcrs([pcr])[str(pcr)]

    def _unique_fapi_path(self, output_prefix: Path, key: bytes) -> str:
        digest = sha256(str(output_prefix.resolve()).encode("utf-8") + key).hexdigest()[:16]
        safe_name = "".join(ch if ch.isalnum() else "_" for ch in output_prefix.name)
        public_blob_path = output_prefix.with_suffix(output_prefix.suffix + ".pub")
        private_blob_path = output_prefix.with_suffix(output_prefix.suffix + ".priv")
        return f"{self.base_path}:{public_blob_path}:{private_blob_path}:{safe_name}_{digest}"

    def _paths_from_fapi_path(self, fapi_path: str) -> tuple[Path, Path]:
        parts = fapi_path.split(":")
        if len(parts) < 4 or parts[0] != self.base_path:
            raise TpmError("Unsupported TPM key path in metadata.")
        return Path(parts[1]), Path(parts[2])

    def _run(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        env = environ.copy()
        env["TPM2TOOLS_TCTI"] = self.tcti
        try:
            return subprocess.run(command, check=True, capture_output=True, text=True, env=env)
        except FileNotFoundError as exc:
            raise TpmError(
                f"Missing command '{command[0]}'. Install TPM tools with scripts/install_ubuntu_dependencies.sh."
            ) from exc
        except subprocess.CalledProcessError as exc:
            details = (exc.stderr or exc.stdout or "").strip()
            if "authorization" in details.lower() or "auth" in details.lower():
                raise TpmError("TPM authorization failed. Check the --auth value.") from exc
            raise TpmError(f"TPM command failed: {' '.join(command)}\n{details}") from exc
