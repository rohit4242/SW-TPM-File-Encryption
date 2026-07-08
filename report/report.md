# Encryption of Files Using Different SW-TPM Policies

**Scientific Report**


|                        |                                                                        |
| ---------------------- | ---------------------------------------------------------------------- |
| **Lecture**            | Selected Topics of Embedded Software Development I – Embedded Security |
| **Degree program**     | Master of Applied Computer Science                                     |
| **Semester**           | Summer Semester 2026                                                   |
| **Date of submission** | *[fill in date]*                                                       |
| **Contributor**        | *[fill in name]*, matriculation number *[fill in number]*              |


\newpage

## Table of Contents

1. [Introduction](#1-introduction)
2. [Background](#2-background)
  1. [The Trusted Platform Module](#21-the-trusted-platform-module)
  2. [Software TPM and the TPM Software Stack](#22-software-tpm-and-the-tpm-software-stack)
  3. [Sealing, Policies, and Platform Configuration Registers](#23-sealing-policies-and-platform-configuration-registers)
  4. [Authenticated File Encryption with AES-GCM](#24-authenticated-file-encryption-with-aes-gcm)
3. [Implementation](#3-implementation)
  1. [System Architecture](#31-system-architecture)
  2. [Encryption and Decryption Workflow](#32-encryption-and-decryption-workflow)
  3. [Password Policy](#33-password-policy)
  4. [PCR Policy](#34-pcr-policy)
  5. [File Format](#35-file-format)
4. [Evaluation](#4-evaluation)
  1. [Test Environment](#41-test-environment)
  2. [Results](#42-results)
  3. [Discussion](#43-discussion)
5. [Conclusion](#5-conclusion)
6. [References](#references)

\newpage

## 1 Introduction

Protecting cryptographic keys is one of the central problems of applied security: an encrypted file is only as secure as the key that decrypts it. If the key is stored in a plain file next to the ciphertext, an attacker who copies the disk obtains both. A Trusted Platform Module (TPM) addresses this problem in hardware. It is a dedicated security chip, standardized by the Trusted Computing Group (TCG), that offers secure key storage, cryptographic operations, and platform integrity measurement [1]. Keys protected by a TPM never leave the chip in plaintext, and the TPM can bind their release to conditions such as a password or an unmodified platform state. Well-known applications include disk encryption (e.g., BitLocker) and secure boot [2].

The goal of this project is to demonstrate these concepts with a file encryption tool written in Python. Because development against physical TPM hardware is inconvenient and potentially destructive, a software TPM (SW-TPM) is used instead: the `swtpm` emulator, which implements the complete TPM 2.0 command set in software [3]. The tool encrypts arbitrary files with the Advanced Encryption Standard in Galois/Counter Mode (AES-GCM) and seals the randomly generated encryption key inside the SW-TPM. Two different release policies are implemented and compared:

1. a **password policy**, where the TPM releases the key only after the correct password is presented, and
2. a **PCR policy**, where the TPM releases the key only while selected Platform Configuration Registers (PCRs) still hold the values they had at encryption time.

All TPM interaction is implemented with `tpm2-pytss`, the official Python bindings for the TCG TPM 2.0 software stack [4]. The remainder of this report introduces the necessary background (Section 2), describes the implementation (Section 3), evaluates the two policies including their expected failure behavior (Section 4), and concludes with a summary and possible extensions (Section 5).

## 2 Background



### 2.1 The Trusted Platform Module

A TPM is a passive security controller specified by the TCG. The current version of the specification, TPM 2.0, defines a chip that provides a hardware random number generator, cryptographic key generation and use, and a small amount of shielded storage [1]. Its defining property is that private key material created inside the TPM can be used, but not extracted: cryptographic operations happen inside the chip, and the host system only sees inputs and outputs. TPM 2.0 further introduces a flexible authorization model, called enhanced authorization, in which access to an object can be bound to passwords, platform state, time, or logical combinations of such conditions [2].

TPM objects are organized in hierarchies. This project uses the *owner* (storage) hierarchy: a primary storage key is derived deterministically from a seed inside the TPM, and application keys are created as children of this primary key. A child object is exported from the TPM only in wrapped (encrypted) form, so the exported blobs are useless without the TPM that created them [2].

### 2.2 Software TPM and the TPM Software Stack

A software TPM is a program that implements the TPM 2.0 command set without dedicated hardware. This project uses `swtpm` [3], which builds on `libtpms`, a library that provides the actual TPM 2.0 command processing [5]. `swtpm` exposes the emulated TPM over a TCP socket and persists its internal state in a directory, so sealed objects survive restarts of the emulator. SW-TPMs behave identically to hardware TPMs at the command level, which makes them well suited for development, testing, and virtual machines; they do not, however, offer physical tamper resistance.

Applications communicate with a TPM through the TCG TPM 2.0 Software Stack (TSS 2.0), implemented by the `tpm2-tss` project [6]. The stack layer used here is the Enhanced System Application Programming Interface (ESAPI), which offers one function per TPM command plus session management. The transport below the stack is abstracted by the TPM Command Transmission Interface (TCTI); the string `swtpm:host=127.0.0.1,port=2321` selects the socket connection to the emulator. Finally, `tpm2-pytss` wraps the C libraries of `tpm2-tss` and makes the complete ESAPI available in Python [4].

### 2.3 Sealing, Policies, and Platform Configuration Registers

*Sealing* stores a small secret — here the AES file key — inside a TPM object of type `keyedhash`. The TPM encrypts the object with its parent storage key and returns two blobs, a public and a private part, which the application stores on disk. To *unseal*, the blobs are loaded back into the TPM, which decrypts them internally and reveals the secret only if the object's authorization is satisfied [2]. Two authorization mechanisms are used in this project:

- **Password authorization.** The object carries an authorization value and the attribute `userWithAuth`. On unseal, the TPM compares the presented password with the stored value; the comparison happens inside the TPM.
- **Policy authorization.** The object carries a policy digest in its `authPolicy` field. To unseal, the caller must run a *policy session* in which TPM policy commands recompute exactly this digest. The command `PolicyPCR` includes the current values of selected PCRs in the computation, which binds the object to the platform state.

PCRs are special TPM registers that hold cryptographic hash values. They cannot be written directly; they can only be *extended*: the new value is the hash of the old value concatenated with the supplied measurement. During a measured boot, each boot component extends a PCR before passing control on, so the final PCR values summarize the entire boot chain [2]. If any component changes, the PCR values change, the `PolicyPCR` digest no longer matches, and the TPM refuses to unseal — this is the mechanism behind TPM-backed disk encryption. In this project, PCR 16, a resettable debug PCR, is extended manually to simulate such a platform change.

### 2.4 Authenticated File Encryption with AES-GCM

A TPM is not designed for bulk data encryption; its role is key protection. The files themselves are therefore encrypted in Python with AES using a 256-bit key in Galois/Counter Mode (GCM), an authenticated encryption mode standardized by the National Institute of Standards and Technology (NIST) [7]. GCM produces, in addition to the ciphertext, an authentication tag: decryption fails detectably if the ciphertext was modified or a wrong key is used. Each encryption uses a fresh random 96-bit nonce, which is stored openly in the metadata; a nonce is not secret, it must only never repeat for the same key. Since every file is encrypted with a newly generated key, this condition holds by construction. The implementation uses the `cryptography` library [8].

## 3 Implementation



### 3.1 System Architecture

Figure 1 shows the architecture. The Python application consists of three modules: `main.py` (command line interface and metadata handling), `crypto.py` (AES-GCM encryption and decryption), and `tpm.py` (key sealing and unsealing through `tpm2-pytss`). The application talks to the `swtpm` emulator through the ESAPI of `tpm2-tss`, connected via the socket TCTI.

Figure 1: System architecture of the file encryption tool.

The project deliberately keeps the code base small: three source modules, one setup script, start and stop scripts for the emulator, and one demonstration script that exercises both policies end to end.

### 3.2 Encryption and Decryption Workflow

Encryption proceeds in four steps. First, a random 256-bit AES key is generated. Second, the file content is encrypted with AES-GCM. Third, the AES key is sealed into the SW-TPM: a primary storage key is created in the owner hierarchy (`CreatePrimary`, RSA-2048), and the key is stored as a child `keyedhash` object (`Create`) whose authorization depends on the chosen policy. The returned public and private blobs are written next to the ciphertext. Fourth, a small JSON (JavaScript Object Notation) metadata file is written; it contains the nonce, the policy type, and the PCR selection, but never the key or the password.

Decryption reverses these steps: the blobs are loaded into the TPM (`Load`), the key is unsealed (`Unseal`) — which succeeds only if the policy is satisfied — and the ciphertext is decrypted and authenticated with AES-GCM. Listing 1 shows the complete decryption logic of the command line interface.

```python
# Listing 1: decryption workflow (excerpt from src/main.py)
metadata = load_metadata(metadata_path(args.encrypted_file))
key = TpmKeyStore(args.tcti).unseal_key(
    args.encrypted_file, auth=args.auth, pcrs=metadata["pcrs"]
)
nonce = base64.b64decode(metadata["nonce_b64"])
plaintext = crypto.decrypt(args.encrypted_file.read_bytes(), key, nonce)
```



### 3.3 Password Policy

For the password policy, the sealed object is created with the attribute `userWithAuth` and the user's password as its authorization value. Both are part of the sensitive creation data passed to the TPM command `Create`. On unseal, the application sets the password on the object handle (`TR_SetAuth`) and calls `Unseal` in a password session. The TPM performs the comparison internally and answers a wrong password with the error code `TPM_RC_AUTH_FAIL`, which the application translates into a readable message. The object is additionally created with the attributes `fixedTPM` and `fixedParent`, so it can never be duplicated to another TPM, and `noDA`, which excludes the demonstration object from the dictionary-attack lockout logic.

### 3.4 PCR Policy

For the PCR policy, the expected policy digest must be known at creation time. It is computed with a *trial session*: a session of type `TPM2_SE.TRIAL` is started, `PolicyPCR` is executed for the selected PCRs (SHA-256 bank), and the resulting digest is read back with `PolicyGetDigest`. This digest is stored in the `authPolicy` field of the sealed object, and the attribute `userWithAuth` is deliberately cleared — satisfying the PCR policy is then the only way to unseal the key. Listing 2 shows the corresponding code.

```python
# Listing 2: computing the PolicyPCR digest (excerpt from src/tpm.py)
session = esys.start_auth_session(
    tpm_key=ESYS_TR.NONE, bind=ESYS_TR.NONE,
    session_type=TPM2_SE.TRIAL,
    symmetric=TPMT_SYM_DEF(algorithm=TPM2_ALG.NULL),
    auth_hash=TPM2_ALG.SHA256,
)
esys.policy_pcr(session, TPM2B_DIGEST(), pcr_selection)
digest = esys.policy_get_digest(session)
```

On unseal, the same commands run in a *real* policy session (`TPM2_SE.POLICY`). This time `PolicyPCR` incorporates the current PCR values into the session digest. `Unseal` is then called with this session; the TPM compares the session digest with the stored `authPolicy` and refuses with `TPM_RC_POLICY_FAIL` if any selected PCR has changed. The policy check is therefore enforced entirely inside the TPM — the Python code never compares PCR values itself.

### 3.5 File Format

Encrypting `sample.txt` produces four files (Table 1). All four are required for decryption; the metadata contains no secret material.


| File                  | Content                                                                 |
| --------------------- | ----------------------------------------------------------------------- |
| `sample.txt.enc`      | AES-GCM ciphertext including the authentication tag                     |
| `sample.txt.enc.json` | metadata: algorithm, nonce (Base64), policy type, PCR selection         |
| `sample.txt.enc.pub`  | sealed key object, public part (marshaled `TPM2B_PUBLIC`)               |
| `sample.txt.enc.priv` | sealed key object, private part, encrypted by the TPM (`TPM2B_PRIVATE`) |


*Table 1: files produced when encrypting* `sample.txt`*.*

## 4 Evaluation



### 4.1 Test Environment

The implementation was tested on Ubuntu 22.04 (running under the Windows Subsystem for Linux, WSL2) with Python 3.10, `swtpm` 0.6.3, `tpm2-tss` 3.2, and `tpm2-pytss` 2.x. The demonstration script `scripts/demo.sh` runs both policies end to end, including the intended failure cases.

### 4.2 Results

**Password policy.** A file encrypted with `--policy password --auth demo-password` decrypts correctly with the same password; the byte-for-byte comparison (`cmp`) of the original and decrypted files confirms integrity. Presenting a wrong password does not decrypt the file; instead the TPM returns an authorization failure:

```text
Error: TPM authorization failed. Check the --auth value.
```

**PCR policy.** A file encrypted with `--policy pcr --pcrs 16` decrypts correctly as long as PCR 16 is unchanged. After the register is extended once (`extend-pcr 16`), simulating a modification of the platform state, the same decryption command fails:

```text
Error: TPM policy check failed. The current PCR values do not match
the sealed policy.
```

Both negative results are produced by the TPM itself (error codes `TPM_RC_AUTH_FAIL` and `TPM_RC_POLICY_FAIL`), not by checks in the Python application. Table 2 summarizes the test cases.


| #   | Test case                             | Expected result    | Observed |
| --- | ------------------------------------- | ------------------ | -------- |
| 1   | Encrypt and decrypt, correct password | files identical    | pass     |
| 2   | Decrypt with wrong password           | TPM rejects unseal | pass     |
| 3   | Encrypt and decrypt, PCR unchanged    | files identical    | pass     |
| 4   | Decrypt after PCR extend              | TPM rejects unseal | pass     |
| 5   | Decrypt with tampered ciphertext      | AES-GCM rejects    | pass     |


*Table 2: evaluation results of the demonstration runs.*

### 4.3 Discussion

The evaluation confirms the intended division of labor: symmetric bulk encryption is fast in software, while the security-critical operation — releasing the key — is delegated to the TPM. The two policies illustrate two distinct protection goals. The password policy binds the key to knowledge; it resembles classic password-based encryption, but with the important difference that the password check and the key storage are inside the TPM, so no password hash or key file exists on disk that could be attacked offline. The PCR policy binds the key to platform state without any user secret; it models the mechanism used by TPM-backed disk encryption, where the key is released only into an unmodified boot environment.

Two limitations should be noted. First, an SW-TPM provides no physical security: its state directory is an ordinary directory on disk, so the emulator is a faithful functional model but not a hardware trust anchor. Second, sealing binds the key to one specific TPM (`fixedTPM`); if the TPM state is deleted, all sealed keys are irrevocably lost, which in practice requires a key backup or recovery strategy.

## 5 Conclusion

This project implemented file encryption with TPM-protected keys in Python. A complete SW-TPM environment was set up from the `swtpm` emulator and the `tpm2-tss` software stack, and all TPM operations were implemented through the `tpm2-pytss` ESAPI bindings. Files are encrypted with AES-256-GCM, and the encryption key is sealed in the TPM under two alternative policies: a password policy based on TPM object authorization and a PCR policy based on `PolicyPCR` enhanced authorization. The evaluation showed that both policies behave as specified — in particular, that wrong passwords and modified PCR values are rejected by the TPM itself rather than by application code.

The design could be extended in several directions: a `PolicyOR` construction could combine the password and PCR conditions to add a recovery path, as done in production disk encryption; the tool could run unchanged against a hardware TPM by switching the TCTI to the device interface; and real boot measurements could replace the manually extended debug PCR.

## References

[1] Trusted Computing Group, *Trusted Platform Module Library Specification, Family "2.0", Level 00, Revision 01.59*, Trusted Computing Group, 2019. [Online]. Available: [https://trustedcomputinggroup.org/resource/tpm-library-specification/](https://trustedcomputinggroup.org/resource/tpm-library-specification/)

[2] W. Arthur, D. Challener, and K. Goldman, *A Practical Guide to TPM 2.0: Using the New Trusted Platform Module in the New Age of Security*. Berkeley, CA, USA: Apress, 2015.

[3] S. Berger, "swtpm: Software TPM emulator," GitHub repository, 2025. [Online]. Available: [https://github.com/stefanberger/swtpm](https://github.com/stefanberger/swtpm)

[4] tpm2-software community, "tpm2-pytss: Python bindings for the TPM 2.0 TSS," GitHub repository, 2025. [Online]. Available: [https://github.com/tpm2-software/tpm2-pytss](https://github.com/tpm2-software/tpm2-pytss)

[5] S. Berger, "libtpms: Library providing TPM functionality," GitHub repository, 2025. [Online]. Available: [https://github.com/stefanberger/libtpms](https://github.com/stefanberger/libtpms)

[6] tpm2-software community, "tpm2-tss: TCG TPM 2.0 Software Stack," GitHub repository, 2025. [Online]. Available: [https://github.com/tpm2-software/tpm2-tss](https://github.com/tpm2-software/tpm2-tss)

[7] M. Dworkin, *Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC*, NIST Special Publication 800-38D, National Institute of Standards and Technology, 2007.

[8] Python Cryptographic Authority, "pyca/cryptography," documentation, 2025. [Online]. Available: [https://cryptography.io/](https://cryptography.io/)