import json
import unittest

from src.metadata import EncryptionMetadata, load_metadata, save_metadata


class MetadataTests(unittest.TestCase):
    def test_metadata_round_trip_preserves_values(self):
        with self.subTest("metadata"):
            from tempfile import TemporaryDirectory
            from pathlib import Path

            with TemporaryDirectory() as directory:
                metadata_path = Path(directory) / "sample.txt.enc.json"
                metadata = EncryptionMetadata(
                    original_filename="sample.txt",
                    algorithm="AES-256-GCM",
                    nonce_b64="MTIzNDU2Nzg5MDEy",
                    policy="password",
                    tpm_public_blob="sample.txt.enc.pub",
                    tpm_private_blob="sample.txt.enc.priv",
                )

                save_metadata(metadata_path, metadata)
                loaded = load_metadata(metadata_path)

                self.assertEqual(loaded, metadata)

    def test_metadata_round_trip_preserves_pcr_values(self):
        from tempfile import TemporaryDirectory
        from pathlib import Path

        with TemporaryDirectory() as directory:
            metadata_path = Path(directory) / "sample.txt.enc.json"
            metadata = EncryptionMetadata(
                original_filename="sample.txt",
                algorithm="AES-256-GCM",
                nonce_b64="MTIzNDU2Nzg5MDEy",
                policy="pcr",
                tpm_public_blob="sample.txt.enc.pub",
                tpm_private_blob="sample.txt.enc.priv",
                tpm_key_path="/HS/SRK/sw_tpm_file_encryption/sample",
                pcrs=[7, 16],
            )

            save_metadata(metadata_path, metadata)
            loaded = load_metadata(metadata_path)

            self.assertEqual(loaded, metadata)

    def test_metadata_rejects_missing_required_fields(self):
        from tempfile import TemporaryDirectory
        from pathlib import Path

        with TemporaryDirectory() as directory:
            metadata_path = Path(directory) / "broken.json"
            metadata_path.write_text(json.dumps({"algorithm": "AES-256-GCM"}), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "missing required metadata field"):
                load_metadata(metadata_path)


if __name__ == "__main__":
    unittest.main()
