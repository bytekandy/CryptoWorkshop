"""Command-line interface for the Secure Examination-Paper Exchange workshop."""

from __future__ import annotations

import argparse
import getpass
import shutil
import sys
from pathlib import Path

from crypto_utils import (
    SecureExchangeError,
    decrypt_package,
    encrypt_file,
    generate_keypair,
)

ROOT = Path(__file__).resolve().parent


def project_path(path: Path) -> Path:
    """Resolve relative CLI paths from the project directory, not an arbitrary CWD."""
    path = Path(path).expanduser()
    return path.resolve() if path.is_absolute() else (ROOT / path).resolve()


def ask_new_passphrase(role: str) -> str:
    while True:
        first = getpass.getpass(f"Create a passphrase for the {role} private key (12+ characters): ")
        second = getpass.getpass("Re-enter passphrase: ")
        if first != second:
            print("Passphrases did not match. Try again.", file=sys.stderr)
            continue
        if len(first) < 12:
            print("Use at least 12 characters.", file=sys.stderr)
            continue
        return first


def ask_existing_passphrase(role: str) -> str:
    return getpass.getpass(f"Passphrase for the {role} private key: ")


def command_setup(args: argparse.Namespace) -> int:
    sender_private = ROOT / "sender" / "private_key.pem"
    recipient_private = ROOT / "recipient" / "private_key.pem"
    if not args.force and (sender_private.exists() or recipient_private.exists()):
        print(
            "Key files already exist. Keeping them unchanged. Use 'setup --force' only if you intend to replace them.",
            file=sys.stderr,
        )
        return 2

    sender_passphrase = ask_new_passphrase("sender")
    recipient_passphrase = ask_new_passphrase("recipient")

    try:
        generate_keypair(ROOT / "sender", sender_passphrase)
        generate_keypair(ROOT / "recipient", recipient_passphrase)

        # These public-key copies simulate a public-key exchange over a trusted channel.
        # In a real deployment, authenticate the fingerprints through an independent channel.
        (ROOT / "trusted_keys").mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / "sender" / "public_key.pem", ROOT / "trusted_keys" / "sender_public_key.pem")
        shutil.copyfile(ROOT / "recipient" / "public_key.pem", ROOT / "sender" / "recipient_public_key.pem")
        for path in (
            ROOT / "trusted_keys" / "sender_public_key.pem",
            ROOT / "sender" / "recipient_public_key.pem",
        ):
            path.chmod(0o644)
    except (OSError, ValueError, SecureExchangeError) as exc:
        print(f"Setup failed: {exc}", file=sys.stderr)
        return 1

    print("Key setup completed.")
    print("Sender private key:       sender/private_key.pem (passphrase-protected)")
    print("Recipient private key:    recipient/private_key.pem (passphrase-protected)")
    print("Sender public key trusted: trusted_keys/sender_public_key.pem")
    print("Recipient public key for sender: sender/recipient_public_key.pem")
    print("Only public keys were copied between roles. Do not share private keys or passphrases.")
    return 0


def command_encrypt(args: argparse.Namespace) -> int:
    sender_passphrase = ask_existing_passphrase("sender")
    try:
        metadata = encrypt_file(
            input_path=project_path(args.input),
            output_package_path=project_path(args.output),
            sender_private_key_path=ROOT / "sender" / "private_key.pem",
            recipient_public_key_path=project_path(args.recipient_public_key),
            sender_passphrase=sender_passphrase,
        )
    except SecureExchangeError as exc:
        print(f"Encryption rejected: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Encryption failed due to a file-system error: {exc}", file=sys.stderr)
        return 1

    print("Encryption and signing completed.")
    print(f"Input file: {project_path(args.input)}")
    print(f"Encrypted package: {project_path(args.output)}")
    print(f"Plaintext bytes: {metadata['plaintext_size']}")
    print("The package contains no plaintext examination content.")
    return 0


def command_decrypt(args: argparse.Namespace) -> int:
    recipient_passphrase = ask_existing_passphrase("recipient")
    try:
        metadata = decrypt_package(
            package_path=project_path(args.input),
            output_path=project_path(args.output),
            recipient_private_key_path=ROOT / "recipient" / "private_key.pem",
            trusted_sender_public_key_path=project_path(args.sender_public_key),
            recipient_passphrase=recipient_passphrase,
        )
    except SecureExchangeError as exc:
        print(f"Package rejected: {exc}", file=sys.stderr)
        print("No new plaintext file was written.", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Decryption could not write the output file: {exc}", file=sys.stderr)
        return 1

    print("Signature verified; session key recovered; AES-GCM authentication succeeded.")
    print(f"Recovered file: {project_path(args.output)}")
    print(f"Original filename in signed metadata: {metadata['filename']}")
    print(f"Recovered bytes: {metadata['plaintext_size']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Encrypt and digitally sign an examination-paper package for a recipient."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    setup_parser = subparsers.add_parser("setup", help="generate sender and recipient RSA key pairs")
    setup_parser.add_argument(
        "--force", action="store_true", help="replace existing keys (old encrypted packages may stop working)"
    )
    setup_parser.set_defaults(func=command_setup)

    encrypt_parser = subparsers.add_parser("encrypt", help="encrypt a file and sign its package")
    encrypt_parser.add_argument("--input", type=Path, default=Path("sender/exam_paper.txt"))
    encrypt_parser.add_argument("--output", type=Path, default=Path("exchange/package_1.json"))
    encrypt_parser.add_argument(
        "--recipient-public-key", type=Path, default=Path("sender/recipient_public_key.pem")
    )
    encrypt_parser.set_defaults(func=command_encrypt)

    decrypt_parser = subparsers.add_parser("decrypt", help="verify and decrypt a package")
    decrypt_parser.add_argument("--input", type=Path, default=Path("exchange/package_1.json"))
    decrypt_parser.add_argument("--output", type=Path, default=Path("recovered/exam_paper.txt"))
    decrypt_parser.add_argument(
        "--sender-public-key", type=Path, default=Path("trusted_keys/sender_public_key.pem")
    )
    decrypt_parser.set_defaults(func=command_decrypt)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("Cancelled.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
