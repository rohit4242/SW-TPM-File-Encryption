import unittest

from src.crypto import decrypt_bytes, encrypt_bytes, generate_aes_key
from src.errors import AppError


class CryptoTests(unittest.TestCase):
    def test_aes_gcm_round_trip_restores_plaintext(self):
        key = generate_aes_key()
        plaintext = b"Embedded security TPM demo data"

        encrypted = encrypt_bytes(plaintext, key)
        decrypted = decrypt_bytes(encrypted.ciphertext, key, encrypted.nonce)

        self.assertEqual(decrypted, plaintext)
        self.assertNotEqual(encrypted.ciphertext, plaintext)
        self.assertEqual(len(key), 32)
        self.assertEqual(len(encrypted.nonce), 12)

    def test_aes_gcm_rejects_modified_ciphertext(self):
        key = generate_aes_key()
        encrypted = encrypt_bytes(b"do not modify me", key)
        modified = encrypted.ciphertext[:-1] + bytes([encrypted.ciphertext[-1] ^ 1])

        with self.assertRaisesRegex(AppError, "authentication failed"):
            decrypt_bytes(modified, key, encrypted.nonce)


if __name__ == "__main__":
    unittest.main()
