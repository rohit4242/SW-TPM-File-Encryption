import unittest
from pathlib import Path

from src.cli import build_metadata_path, default_decrypt_output, default_encrypt_output


class CliPathTests(unittest.TestCase):
    def test_encrypt_output_defaults_to_outputs_folder(self):
        output = default_encrypt_output(Path("examples/sample.txt"))

        self.assertEqual(output, Path("outputs/sample.txt.enc"))

    def test_decrypt_output_defaults_to_outputs_folder(self):
        output = default_decrypt_output(Path("outputs/sample.txt.enc"))

        self.assertEqual(output, Path("outputs/sample.txt.dec"))

    def test_metadata_path_sits_beside_encrypted_file(self):
        metadata_path = build_metadata_path(Path("outputs/sample.txt.enc"))

        self.assertEqual(metadata_path, Path("outputs/sample.txt.enc.json"))


if __name__ == "__main__":
    unittest.main()
