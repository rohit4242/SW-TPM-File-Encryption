"""Secure key storage in a software TPM, using the tpm2-pytss (ESAPI) bindings.

The AES file-encryption key is "sealed" into the TPM: it is wrapped by a
primary storage key that never leaves the TPM. The sealed object carries a
release policy that the TPM itself enforces on unseal:

* password policy: the object stores an auth value (``userWithAuth``).
  The TPM only unseals the key when the same password is presented.
* PCR policy: the object stores a PolicyPCR digest. The TPM only unseals
  the key while the selected PCRs still hold the values they had at seal
  time. Extending a PCR (a simulated system change) blocks the key forever.

The sealed object is stored on disk as two blobs next to the encrypted file:
``<file>.pub`` (public part) and ``<file>.priv`` (private part, encrypted by
the TPM). The blobs are useless without the TPM that created them.
"""

from pathlib import Path

from tpm2_pytss import ESAPI, TSS2_Exception
from tpm2_pytss.constants import ESYS_TR, TPM2_ALG, TPM2_SE, TPMA_OBJECT
from tpm2_pytss.types import (
    TPM2B_AUTH,
    TPM2B_DIGEST,
    TPM2B_PRIVATE,
    TPM2B_PUBLIC,
    TPM2B_SENSITIVE_CREATE,
    TPM2B_SENSITIVE_DATA,
    TPML_DIGEST_VALUES,
    TPML_PCR_SELECTION,
    TPMS_SENSITIVE_CREATE,
    TPMT_HA,
    TPMT_PUBLIC,
    TPMT_SYM_DEF,
    TPMU_HA,
)

DEFAULT_TCTI = "swtpm:host=127.0.0.1,port=2321"

# RSA-2048 storage key under the owner hierarchy, same template tpm2-tools uses.
PRIMARY_KEY_TEMPLATE = "rsa2048:aes128cfb"

# noda keeps demo objects out of the TPM dictionary-attack lockout logic.
BASE_SEAL_ATTRIBUTES = TPMA_OBJECT.FIXEDTPM | TPMA_OBJECT.FIXEDPARENT | TPMA_OBJECT.NODA


class TpmError(Exception):
    """A TPM operation failed; the message is safe to show to the user."""


def blob_paths(file_path: Path) -> tuple[Path, Path]:
    """Return the sealed-object blob paths stored beside the encrypted file."""
    return Path(f"{file_path}.pub"), Path(f"{file_path}.priv")


class TpmKeyStore:
    """Seal and unseal small keys in the SW-TPM through tpm2-pytss ESAPI."""

    def __init__(self, tcti: str = DEFAULT_TCTI):
        self.tcti = tcti

    def seal_key(self, key: bytes, file_path: Path, auth: str | None = None, pcrs: list[int] | None = None) -> None:
        """Seal `key` into <file_path>.pub/.priv with a password or PCR policy."""
        public_blob, private_blob = blob_paths(file_path)

        with self._connect() as esys:
            primary = self._create_primary(esys)
            try:
                if pcrs:
                    policy_digest = self._compute_pcr_policy_digest(esys, pcrs)
                    template = _sealed_object_template(policy_digest, with_user_auth=False)
                    sensitive = _sealed_object_sensitive(key, auth=None)
                else:
                    if not auth:
                        raise TpmError("Password policy requires an auth value.")
                    template = _sealed_object_template(b"", with_user_auth=True)
                    sensitive = _sealed_object_sensitive(key, auth=auth)

                private, public, _, _, _ = self._call(esys.create, primary, sensitive, template)
                public_blob.write_bytes(public.marshal())
                private_blob.write_bytes(private.marshal())
            finally:
                esys.flush_context(primary)

    def unseal_key(self, file_path: Path, auth: str | None = None, pcrs: list[int] | None = None) -> bytes:
        """Unseal the key stored beside `file_path`; the TPM enforces its policy."""
        public_blob, private_blob = blob_paths(file_path)
        if not public_blob.is_file() or not private_blob.is_file():
            raise TpmError("TPM sealed object blobs (.pub/.priv) are missing beside the encrypted file.")

        public, _ = TPM2B_PUBLIC.unmarshal(public_blob.read_bytes())
        private, _ = TPM2B_PRIVATE.unmarshal(private_blob.read_bytes())

        with self._connect() as esys:
            primary = self._create_primary(esys)
            try:
                sealed = self._call(esys.load, primary, private, public)
                try:
                    if pcrs:
                        data = self._unseal_with_pcr_policy(esys, sealed, pcrs)
                    else:
                        esys.tr_set_auth(sealed, auth or "")
                        data = self._call(esys.unseal, sealed)
                    return bytes(data)
                finally:
                    esys.flush_context(sealed)
            finally:
                esys.flush_context(primary)

    def read_pcrs(self, pcrs: list[int]) -> dict[int, str]:
        """Read the selected SHA-256 PCR values as lowercase hex strings."""
        with self._connect() as esys:
            values: dict[int, str] = {}
            for pcr in pcrs:
                _, _, digests = esys.pcr_read(_pcr_selection([pcr]))
                values[pcr] = bytes(digests[0]).hex()
            return values

    def extend_pcr(self, pcr: int, digest: bytes) -> str:
        """Extend one PCR with a SHA-256 digest and return the new PCR value."""
        digests = TPML_DIGEST_VALUES(
            [TPMT_HA(hashAlg=TPM2_ALG.SHA256, digest=TPMU_HA(sha256=digest))]
        )
        with self._connect() as esys:
            self._call(esys.pcr_extend, ESYS_TR(pcr), digests)
        return self.read_pcrs([pcr])[pcr]

    def _connect(self) -> ESAPI:
        """Open an ESAPI connection to the SW-TPM."""
        try:
            return ESAPI(self.tcti)
        except (TSS2_Exception, RuntimeError) as exc:
            raise TpmError(
                f"Cannot connect to SW-TPM via '{self.tcti}'. Start it with: bash scripts/start_tpm.sh"
            ) from exc

    def _create_primary(self, esys: ESAPI) -> ESYS_TR:
        """Create the primary storage key that parents every sealed object."""
        primary, _, _, _, _ = self._call(
            esys.create_primary, TPM2B_SENSITIVE_CREATE(), PRIMARY_KEY_TEMPLATE
        )
        return primary

    def _compute_pcr_policy_digest(self, esys: ESAPI, pcrs: list[int]) -> bytes:
        """Compute the PolicyPCR digest for the current PCR values (trial session)."""
        session = self._start_session(esys, TPM2_SE.TRIAL)
        try:
            self._call(esys.policy_pcr, session, TPM2B_DIGEST(), _pcr_selection(pcrs))
            return bytes(self._call(esys.policy_get_digest, session))
        finally:
            esys.flush_context(session)

    def _unseal_with_pcr_policy(self, esys: ESAPI, sealed: ESYS_TR, pcrs: list[int]) -> TPM2B_SENSITIVE_DATA:
        """Unseal in a real policy session, so the TPM checks the current PCRs."""
        session = self._start_session(esys, TPM2_SE.POLICY)
        try:
            self._call(esys.policy_pcr, session, TPM2B_DIGEST(), _pcr_selection(pcrs))
            return self._call(esys.unseal, sealed, session1=session)
        finally:
            esys.flush_context(session)

    def _start_session(self, esys: ESAPI, session_type: TPM2_SE) -> ESYS_TR:
        return self._call(
            esys.start_auth_session,
            tpm_key=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            session_type=session_type,
            symmetric=TPMT_SYM_DEF(algorithm=TPM2_ALG.NULL),
            auth_hash=TPM2_ALG.SHA256,
        )

    def _call(self, function, *args, **kwargs):
        """Run one ESAPI call and translate TPM errors into readable messages."""
        try:
            return function(*args, **kwargs)
        except TSS2_Exception as exc:
            raise _translate_tpm_failure(exc) from exc


def _sealed_object_template(auth_policy: bytes, with_user_auth: bool) -> TPM2B_PUBLIC:
    """Build the public template of the sealed (keyedhash) object."""
    attributes = BASE_SEAL_ATTRIBUTES
    if with_user_auth:
        # Password policy: the TPM compares the presented auth value on unseal.
        attributes |= TPMA_OBJECT.USERWITHAUTH
    # Without userWithAuth, satisfying authPolicy (PolicyPCR) is the only way in.
    public_area = TPMT_PUBLIC(
        type=TPM2_ALG.KEYEDHASH,
        nameAlg=TPM2_ALG.SHA256,
        objectAttributes=attributes,
        authPolicy=auth_policy,
    )
    public_area.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG.NULL
    return TPM2B_PUBLIC(public_area)


def _sealed_object_sensitive(key: bytes, auth: str | None) -> TPM2B_SENSITIVE_CREATE:
    """Build the sensitive part of the sealed object: the key and its auth value."""
    return TPM2B_SENSITIVE_CREATE(
        TPMS_SENSITIVE_CREATE(
            userAuth=TPM2B_AUTH(auth or ""),
            data=TPM2B_SENSITIVE_DATA(key),
        )
    )


def _pcr_selection(pcrs: list[int]) -> TPML_PCR_SELECTION:
    return TPML_PCR_SELECTION.parse("sha256:" + ",".join(str(pcr) for pcr in pcrs))


def _translate_tpm_failure(exc: TSS2_Exception) -> TpmError:
    """Map raw TSS2 error messages to short, clear messages."""
    details = str(exc).lower()
    if "hmac check failed" in details or ("authorization" in details and "failed" in details):
        return TpmError("TPM authorization failed. Check the --auth value.")
    if "policy" in details and ("fail" in details or "check" in details):
        return TpmError("TPM policy check failed. The current PCR values do not match the sealed policy.")
    if "lockout" in details:
        return TpmError("TPM is in dictionary-attack lockout. Restart the SW-TPM or wait, then try again.")
    return TpmError(f"TPM operation failed: {exc}")
