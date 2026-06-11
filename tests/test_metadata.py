import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from src.errors import AppError
from src.metadata import EncryptionMetadata, load_metadata, save_metadata


class MetadataTests(unittest.TestCase):
    def test_password_metadata_round_trip(self):
        with TemporaryDirectory() as directory:
            metadata_path = Path(directory) / "sample.txt.enc.json"
            metadata = EncryptionMetadata(
                original_filename="sample.txt",
                algorithm="AES-256-GCM",
                nonce_b64="MTIzNDU2Nzg5MDEy",
                policy="password",
            )

            save_metadata(metadata_path, metadata)
            loaded = load_metadata(metadata_path)

            self.assertEqual(loaded, metadata)

    def test_pcr_metadata_round_trip(self):
        with TemporaryDirectory() as directory:
            metadata_path = Path(directory) / "sample.txt.enc.json"
            metadata = EncryptionMetadata(
                original_filename="sample.txt",
                algorithm="AES-256-GCM",
                nonce_b64="MTIzNDU2Nzg5MDEy",
                policy="pcr",
                pcrs=[7, 16],
            )

            save_metadata(metadata_path, metadata)
            loaded = load_metadata(metadata_path)

            self.assertEqual(loaded, metadata)

    def test_metadata_rejects_missing_required_fields(self):
        with TemporaryDirectory() as directory:
            metadata_path = Path(directory) / "broken.json"
            metadata_path.write_text(json.dumps({"algorithm": "AES-256-GCM"}), encoding="utf-8")

            with self.assertRaisesRegex(AppError, "Missing required metadata field"):
                load_metadata(metadata_path)


if __name__ == "__main__":
    unittest.main()
