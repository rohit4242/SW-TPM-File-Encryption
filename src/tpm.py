from hashlib import sha256
from os import environ
from pathlib import Path
import re
import subprocess
import tempfile

from .errors import TpmError

DEFAULT_TCTI = "swtpm:host=127.0.0.1,port=2321"

# noda keeps demo objects out of the TPM dictionary-attack lockout logic.
PASSWORD_SEAL_ATTRIBUTES = "fixedtpm|fixedparent|userwithauth|noda"
# Without userwithauth the sealed key can only be released through the PCR policy.
PCR_SEAL_ATTRIBUTES = "fixedtpm|fixedparent|noda"


def blob_paths(file_prefix: Path) -> tuple[Path, Path]:
    """Return the sealed-object blob paths stored beside the encrypted file."""
    public = file_prefix.with_suffix(file_prefix.suffix + ".pub")
    private = file_prefix.with_suffix(file_prefix.suffix + ".priv")
    return public, private


class TpmKeyStore:
    """Seal and unseal small keys in SW-TPM using tpm2-tools."""

    def __init__(self, tcti: str = DEFAULT_TCTI):
        self.tcti = tcti

    def seal_key(self, key: bytes, output_prefix: Path, auth: str | None = None, pcrs: list[int] | None = None) -> None:
        """Seal `key` into <output_prefix>.pub/.priv with a password or PCR policy."""
        public_blob_path, private_blob_path = blob_paths(output_prefix)

        self._flush_transient_contexts(ignore_errors=True)
        with tempfile.TemporaryDirectory() as directory:
            try:
                temp_dir = Path(directory)
                primary_context = temp_dir / "primary.ctx"
                key_input = temp_dir / "aes.key"
                key_input.write_bytes(key)

                self._run(["tpm2_createprimary", "-Q", "-C", "o", "-G", "rsa", "-c", str(primary_context)])

                command = [
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
                ]
                if pcrs:
                    policy_digest = temp_dir / "pcr.policy"
                    self._create_pcr_policy_digest(temp_dir, pcrs, policy_digest)
                    command += ["-L", str(policy_digest), "-a", PCR_SEAL_ATTRIBUTES]
                else:
                    if not auth:
                        raise TpmError("Password policy requires an auth value.")
                    command += ["-p", auth, "-a", PASSWORD_SEAL_ATTRIBUTES]
                self._run(command)
            finally:
                self._flush_transient_contexts(ignore_errors=True)

    def unseal_key(self, encrypted_file: Path, auth: str | None = None, pcrs: list[int] | None = None) -> bytes:
        """Unseal the key stored beside `encrypted_file`, enforcing its policy in the TPM."""
        public_blob_path, private_blob_path = blob_paths(encrypted_file)
        if not public_blob_path.is_file() or not private_blob_path.is_file():
            raise TpmError("TPM sealed object blobs are missing beside the encrypted file.")

        self._flush_transient_contexts(ignore_errors=True)
        with tempfile.TemporaryDirectory() as directory:
            try:
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
                # SW-TPM holds only 3 transient objects; free the slots taken by
                # createprimary/load so unseal can context-load sealed.ctx again.
                self._flush_transient_contexts()
                if pcrs:
                    self._unseal_with_pcr_policy(temp_dir, sealed_context, pcrs, unsealed_output)
                else:
                    self._run(
                        ["tpm2_unseal", "-Q", "-c", str(sealed_context), "-p", auth or "", "-o", str(unsealed_output)]
                    )
                return unsealed_output.read_bytes()
            finally:
                self._flush_transient_contexts(ignore_errors=True)

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

    def _create_pcr_policy_digest(self, temp_dir: Path, pcrs: list[int], policy_digest: Path) -> None:
        """Compute the PCR policy digest with a trial session."""
        session = temp_dir / "trial-session.ctx"
        self._run(["tpm2_startauthsession", "-Q", "-S", str(session)])
        try:
            self._run(["tpm2_policypcr", "-Q", "-S", str(session), "-l", _pcr_selection(pcrs), "-L", str(policy_digest)])
        finally:
            self._flush_session(session)

    def _unseal_with_pcr_policy(self, temp_dir: Path, sealed_context: Path, pcrs: list[int], output: Path) -> None:
        """Unseal with a real policy session so the TPM checks the current PCR values."""
        session = temp_dir / "policy-session.ctx"
        self._run(["tpm2_startauthsession", "-Q", "--policy-session", "-S", str(session)])
        try:
            self._run(["tpm2_policypcr", "-Q", "-S", str(session), "-l", _pcr_selection(pcrs)])
            self._run(["tpm2_unseal", "-Q", "-c", str(sealed_context), "-p", f"session:{session}", "-o", str(output)])
        finally:
            self._flush_session(session)

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
            raise _translate_tpm_failure(command, exc) from exc

    def _flush_transient_contexts(self, ignore_errors: bool = False) -> None:
        try:
            self._run(["tpm2_flushcontext", "-t"])
        except TpmError:
            if not ignore_errors:
                raise

    def _flush_session(self, session: Path) -> None:
        if session.is_file():
            try:
                self._run(["tpm2_flushcontext", str(session)])
            except TpmError:
                pass


def _pcr_selection(pcrs: list[int]) -> str:
    return "sha256:" + ",".join(str(pcr) for pcr in pcrs)


def _translate_tpm_failure(command: list[str], exc: subprocess.CalledProcessError) -> TpmError:
    """Map raw tpm2-tools errors to clear messages without hiding unrelated failures."""
    details = (exc.stderr or exc.stdout or "").strip()
    lowered = details.lower()
    if "0x98e" in lowered or "hmac check failed" in lowered:
        return TpmError("TPM authorization failed. Check the --auth value.")
    if "lockout" in lowered:
        return TpmError("TPM is in dictionary-attack lockout. Run 'tpm2_clearlockout' and try again.")
    if "0x99d" in lowered or "policy check failed" in lowered:
        return TpmError("TPM policy check failed. The current PCR values do not match the sealed policy.")
    return TpmError(f"TPM command failed: {' '.join(command)}\n{details}")
