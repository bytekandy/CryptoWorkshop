"""Automated security tests for the Secure Examination-Paper Exchange demo."""

from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from crypto_utils import (
    AuthenticationError,
    SecureExchangeError,
    SessionKeyDecryptionError,
    SignatureVerificationError,
    canonical_json,
    decrypt_package,
    encrypt_file,
    generate_keypair,
    load_private_key,
    load_public_key,
    write_package_document,
)

TEST_PASSPHRASE = "test-passphrase-for-automated-tests"


class SecureExamExchangeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="secure-exam-tests-")
        cls.root = Path(cls.temporary.name)
        cls.sender_dir = cls.root / "sender"
        cls.recipient_dir = cls.root / "recipient"
        cls.wrong_recipient_dir = cls.root / "wrong_recipient"
        cls.wrong_sender_dir = cls.root / "wrong_sender"
        for directory in (cls.sender_dir, cls.recipient_dir, cls.wrong_recipient_dir, cls.wrong_sender_dir):
            generate_keypair(directory, TEST_PASSPHRASE)

        cls.input_path = cls.root / "exam_paper.txt"
        cls.input_bytes = (
            b"DEMO ONLY - NOT A REAL EXAM\n"
            b"Course: Introductory Computing\n"
            b"Question 1: Explain the difference between confidentiality and integrity.\n"
        )
        cls.input_path.write_bytes(cls.input_bytes)
        cls.sender_private = cls.sender_dir / "private_key.pem"
        cls.sender_public = cls.sender_dir / "public_key.pem"
        cls.recipient_private = cls.recipient_dir / "private_key.pem"
        cls.recipient_public = cls.recipient_dir / "public_key.pem"
        cls.wrong_recipient_private = cls.wrong_recipient_dir / "private_key.pem"
        cls.wrong_sender_public = cls.wrong_sender_dir / "public_key.pem"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def setUp(self) -> None:
        self.case_dir = Path(tempfile.mkdtemp(prefix="case-", dir=self.root))

    def make_package(self, name: str = "package.json") -> Path:
        package_path = self.case_dir / name
        encrypt_file(
            self.input_path,
            package_path,
            self.sender_private,
            self.recipient_public,
            TEST_PASSPHRASE,
        )
        return package_path

    @staticmethod
    def read_package(path: Path) -> dict:
        return json.loads(path.read_text(encoding="utf-8"))

    @staticmethod
    def change_base64_first_byte(encoded: str) -> str:
        decoded = bytearray(base64.b64decode(encoded, validate=True))
        if not decoded:
            raise AssertionError("Expected non-empty binary field")
        decoded[0] ^= 0x01
        return base64.b64encode(decoded).decode("ascii")

    def attempt_decrypt(self, package: Path, output: Path, **overrides) -> None:
        options = {
            "package_path": package,
            "output_path": output,
            "recipient_private_key_path": self.recipient_private,
            "trusted_sender_public_key_path": self.sender_public,
            "recipient_passphrase": TEST_PASSPHRASE,
        }
        options.update(overrides)
        decrypt_package(**options)

    def test_01_authorized_recipient_recovers_original_file(self) -> None:
        package = self.make_package()
        output = self.case_dir / "recovered.txt"
        decrypt_package(package, output, self.recipient_private, self.sender_public, TEST_PASSPHRASE)
        self.assertEqual(output.read_bytes(), self.input_bytes)

    def test_02_ciphertext_modification_is_rejected(self) -> None:
        package = self.make_package()
        document = self.read_package(package)
        document["ciphertext"] = self.change_base64_first_byte(document["ciphertext"])
        tampered = self.case_dir / "tampered_ciphertext.json"
        tampered.write_text(json.dumps(document), encoding="utf-8")
        output = self.case_dir / "should_not_exist_ciphertext.txt"
        with self.assertRaises(SignatureVerificationError):
            self.attempt_decrypt(tampered, output)
        self.assertFalse(output.exists())

    def test_03_metadata_modification_is_rejected(self) -> None:
        package = self.make_package()
        document = self.read_package(package)
        document["metadata"]["filename"] = "changed_name.txt"
        tampered = self.case_dir / "tampered_metadata.json"
        tampered.write_text(json.dumps(document), encoding="utf-8")
        output = self.case_dir / "should_not_exist_metadata.txt"
        with self.assertRaises(SignatureVerificationError):
            self.attempt_decrypt(tampered, output)
        self.assertFalse(output.exists())

    def test_04_signature_modification_is_rejected(self) -> None:
        package = self.make_package()
        document = self.read_package(package)
        document["signature"] = self.change_base64_first_byte(document["signature"])
        tampered = self.case_dir / "tampered_signature.json"
        tampered.write_text(json.dumps(document), encoding="utf-8")
        output = self.case_dir / "should_not_exist_signature.txt"
        with self.assertRaises(SignatureVerificationError):
            self.attempt_decrypt(tampered, output)
        self.assertFalse(output.exists())

    def test_05_wrong_recipient_private_key_is_rejected(self) -> None:
        package = self.make_package()
        output = self.case_dir / "should_not_exist_wrong_recipient.txt"
        with self.assertRaises(SessionKeyDecryptionError):
            self.attempt_decrypt(
                package,
                output,
                recipient_private_key_path=self.wrong_recipient_private,
            )
        self.assertFalse(output.exists())

    def test_06_wrong_sender_public_key_is_rejected(self) -> None:
        package = self.make_package()
        output = self.case_dir / "should_not_exist_wrong_sender.txt"
        with self.assertRaises(SignatureVerificationError):
            self.attempt_decrypt(
                package,
                output,
                trusted_sender_public_key_path=self.wrong_sender_public,
            )
        self.assertFalse(output.exists())

    def test_07_encrypting_same_file_twice_produces_different_packages(self) -> None:
        first = self.make_package("first.json")
        second = self.make_package("second.json")
        self.assertNotEqual(first.read_bytes(), second.read_bytes())
        first_output = self.case_dir / "first_recovered.txt"
        second_output = self.case_dir / "second_recovered.txt"
        self.attempt_decrypt(first, first_output)
        self.attempt_decrypt(second, second_output)
        self.assertEqual(first_output.read_bytes(), self.input_bytes)
        self.assertEqual(second_output.read_bytes(), self.input_bytes)

    def test_08_gcm_tag_is_checked_even_if_package_signature_is_valid(self) -> None:
        package_path = self.make_package()
        document = self.read_package(package_path)
        document["tag"] = self.change_base64_first_byte(document["tag"])
        unsigned = {key: value for key, value in document.items() if key != "signature"}
        sender_private_key = load_private_key(self.sender_private, TEST_PASSPHRASE)
        signature = sender_private_key.sign(
            canonical_json(unsigned),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        document["signature"] = base64.b64encode(signature).decode("ascii")
        malformed_but_signed = self.case_dir / "bad_gcm_tag_but_signed.json"
        malformed_but_signed.write_text(json.dumps(document), encoding="utf-8")
        output = self.case_dir / "should_not_exist_bad_tag.txt"
        with self.assertRaises(AuthenticationError):
            self.attempt_decrypt(malformed_but_signed, output)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
