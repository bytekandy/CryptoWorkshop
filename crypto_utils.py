"""Cryptographic operations for the Secure Examination-Paper Exchange project.

This module contains the crypto logic; main.py provides the command-line interface.
"""

from __future__ import annotations

import base64
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RSA_KEY_SIZE = 3072
AES_KEY_SIZE_BYTES = 32  # 256 bits
GCM_NONCE_SIZE_BYTES = 12
GCM_TAG_SIZE_BYTES = 16

CONTENT_CIPHER = "AES-256-GCM"
KEY_ENCRYPTION = "RSA-OAEP-SHA256"
SIGNATURE_ALGORITHM = "RSA-PSS-SHA256"
PACKAGE_VERSION = 1

METADATA_FIELDS = {
    "version",
    "filename",
    "created_utc",
    "plaintext_size",
    "content_encryption",
    "key_encryption",
    "signature_algorithm",
}
PACKAGE_FIELDS = {"metadata", "encrypted_key", "nonce", "ciphertext", "tag", "signature"}
UNSIGNED_PACKAGE_FIELDS = PACKAGE_FIELDS - {"signature"}


class SecureExchangeError(Exception):
    """Base class for expected application/security failures."""


class PackageFormatError(SecureExchangeError):
    """The received package is missing required fields or is malformed."""


class SignatureVerificationError(SecureExchangeError):
    """The package signature does not verify against the trusted sender key."""


class SessionKeyDecryptionError(SecureExchangeError):
    """The recipient private key could not recover the AES session key."""


class AuthenticationError(SecureExchangeError):
    """AES-GCM authentication failed; the plaintext must not be released."""


def canonical_json(value: Any) -> bytes:
    """Create one deterministic byte representation for signing/verifying JSON."""
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise PackageFormatError("Package contains data that cannot be serialized safely.") from exc


def _atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Write via a temporary file so incomplete output is not left at the target path."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    file_descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        os.chmod(temporary_path, mode)
        with os.fdopen(file_descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        try:
            os.chmod(path, mode)
        except OSError:
            # Some filesystems do not support chmod; the contents are still fully written.
            pass
    except Exception:
        try:
            os.close(file_descriptor)
        except OSError:
            pass
        try:
            temporary_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(value: Any, field_name: str) -> bytes:
    if not isinstance(value, str):
        raise PackageFormatError(f"Package field '{field_name}' must be a Base64 string.")
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise PackageFormatError(f"Package field '{field_name}' is not valid Base64.") from exc


def generate_keypair(directory: Path, passphrase: str) -> None:
    """Generate and save an RSA-3072 key pair; encrypt the private PEM with a passphrase."""
    if not isinstance(passphrase, str) or not passphrase:
        raise ValueError("A non-empty passphrase is required to protect each private key.")

    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(directory, 0o700)
    except OSError:
        pass

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode("utf-8")),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    _atomic_write(directory / "private_key.pem", private_pem, mode=0o600)
    _atomic_write(directory / "public_key.pem", public_pem, mode=0o644)


def load_private_key(path: Path, passphrase: str) -> rsa.RSAPrivateKey:
    """Load an encrypted PEM private key from disk."""
    try:
        key = serialization.load_pem_private_key(
            Path(path).read_bytes(), password=passphrase.encode("utf-8")
        )
    except (OSError, ValueError, TypeError) as exc:
        raise SecureExchangeError(
            "Could not load the private key. Check the file and passphrase."
        ) from exc
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < RSA_KEY_SIZE:
        raise SecureExchangeError(f"Expected an RSA private key of at least {RSA_KEY_SIZE} bits.")
    return key


def load_public_key(path: Path) -> rsa.RSAPublicKey:
    """Load a PEM public key and ensure it is a sufficiently large RSA key."""
    try:
        key = serialization.load_pem_public_key(Path(path).read_bytes())
    except (OSError, ValueError, TypeError) as exc:
        raise SecureExchangeError(f"Could not load public key: {path}") from exc
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < RSA_KEY_SIZE:
        raise SecureExchangeError(f"Expected an RSA public key of at least {RSA_KEY_SIZE} bits.")
    return key


def _oaep_padding() -> padding.OAEP:
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def _pss_padding() -> padding.PSS:
    return padding.PSS(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH,
    )


def _validate_metadata(metadata: Any) -> None:
    if not isinstance(metadata, dict) or set(metadata) != METADATA_FIELDS:
        raise PackageFormatError("Metadata fields are missing, unexpected, or malformed.")
    if metadata.get("version") != PACKAGE_VERSION:
        raise PackageFormatError("Unsupported package version.")
    if metadata.get("content_encryption") != CONTENT_CIPHER:
        raise PackageFormatError("Unsupported content-encryption algorithm.")
    if metadata.get("key_encryption") != KEY_ENCRYPTION:
        raise PackageFormatError("Unsupported session-key encryption algorithm.")
    if metadata.get("signature_algorithm") != SIGNATURE_ALGORITHM:
        raise PackageFormatError("Unsupported signature algorithm.")
    filename = metadata.get("filename")
    if (
        not isinstance(filename, str)
        or not filename
        or filename in {".", ".."}
        or "/" in filename
        or "\\" in filename
    ):
        raise PackageFormatError("Metadata contains an unsafe filename.")
    if not isinstance(metadata.get("created_utc"), str):
        raise PackageFormatError("Metadata field 'created_utc' must be a string.")
    size = metadata.get("plaintext_size")
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise PackageFormatError("Metadata field 'plaintext_size' must be a non-negative integer.")


def _read_package(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PackageFormatError("Cannot read package JSON; it may be missing or malformed.") from exc

    if not isinstance(document, dict) or set(document) != PACKAGE_FIELDS:
        raise PackageFormatError("Package fields are missing, unexpected, or malformed.")
    _validate_metadata(document.get("metadata"))
    # Decode all binary fields before verification to reject malformed encodings early.
    _b64decode(document.get("encrypted_key"), "encrypted_key")
    nonce = _b64decode(document.get("nonce"), "nonce")
    _b64decode(document.get("ciphertext"), "ciphertext")
    tag = _b64decode(document.get("tag"), "tag")
    _b64decode(document.get("signature"), "signature")
    if len(nonce) != GCM_NONCE_SIZE_BYTES:
        raise PackageFormatError("AES-GCM nonce must be 12 bytes.")
    if len(tag) != GCM_TAG_SIZE_BYTES:
        raise PackageFormatError("AES-GCM authentication tag must be 16 bytes.")
    return document


def _unsigned_package(package: dict[str, Any]) -> dict[str, Any]:
    return {key: package[key] for key in UNSIGNED_PACKAGE_FIELDS}


def _sign_package(unsigned_package: dict[str, Any], private_key: rsa.RSAPrivateKey) -> str:
    signature = private_key.sign(
        canonical_json(unsigned_package),
        _pss_padding(),
        hashes.SHA256(),
    )
    return _b64encode(signature)


def write_package_document(path: Path, package: dict[str, Any]) -> None:
    """Write a JSON package atomically. Exported for tests and normal package creation."""
    encoded = json.dumps(package, indent=2, ensure_ascii=False, allow_nan=False).encode("utf-8") + b"\n"
    _atomic_write(Path(path), encoded, mode=0o600)


def encrypt_file(
    input_path: Path,
    output_package_path: Path,
    sender_private_key_path: Path,
    recipient_public_key_path: Path,
    sender_passphrase: str,
) -> dict[str, Any]:
    """Encrypt one file, wrap its AES key for the recipient, and sign the package."""
    input_path = Path(input_path)
    output_package_path = Path(output_package_path)
    try:
        plaintext = input_path.read_bytes()
    except OSError as exc:
        raise SecureExchangeError(f"Cannot read input file: {input_path}") from exc

    sender_private_key = load_private_key(sender_private_key_path, sender_passphrase)
    recipient_public_key = load_public_key(recipient_public_key_path)

    session_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(GCM_NONCE_SIZE_BYTES)

    metadata = {
        "version": PACKAGE_VERSION,
        "filename": input_path.name,
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "plaintext_size": len(plaintext),
        "content_encryption": CONTENT_CIPHER,
        "key_encryption": KEY_ENCRYPTION,
        "signature_algorithm": SIGNATURE_ALGORITHM,
    }
    # Authenticate metadata as AES-GCM associated data. It is not encrypted, but changes
    # to it invalidate the GCM tag. The digital signature also covers this metadata.
    associated_data = canonical_json(metadata)
    encrypted_with_tag = AESGCM(session_key).encrypt(nonce, plaintext, associated_data)
    ciphertext, tag = encrypted_with_tag[:-GCM_TAG_SIZE_BYTES], encrypted_with_tag[-GCM_TAG_SIZE_BYTES:]

    encrypted_session_key = recipient_public_key.encrypt(session_key, _oaep_padding())
    unsigned_package = {
        "metadata": metadata,
        "encrypted_key": _b64encode(encrypted_session_key),
        "nonce": _b64encode(nonce),
        "ciphertext": _b64encode(ciphertext),
        "tag": _b64encode(tag),
    }
    package = dict(unsigned_package)
    package["signature"] = _sign_package(unsigned_package, sender_private_key)
    write_package_document(output_package_path, package)
    return metadata


def decrypt_package(
    package_path: Path,
    output_path: Path,
    recipient_private_key_path: Path,
    trusted_sender_public_key_path: Path,
    recipient_passphrase: str,
) -> dict[str, Any]:
    """Verify, decrypt and authenticate a package before writing any plaintext bytes."""
    package = _read_package(Path(package_path))
    # Load and trust the sender's public key first. Do not use the recipient's private
    # key to recover anything until the signature has passed verification.
    trusted_sender_public_key = load_public_key(trusted_sender_public_key_path)

    unsigned_package = _unsigned_package(package)
    signature = _b64decode(package["signature"], "signature")
    try:
        trusted_sender_public_key.verify(
            signature,
            canonical_json(unsigned_package),
            _pss_padding(),
            hashes.SHA256(),
        )
    except InvalidSignature as exc:
        raise SignatureVerificationError(
            "Signature verification failed. The package was modified or the sender key is wrong."
        ) from exc
    except (ValueError, TypeError) as exc:
        raise SignatureVerificationError("Signature could not be verified; package rejected.") from exc

    recipient_private_key = load_private_key(recipient_private_key_path, recipient_passphrase)
    encrypted_session_key = _b64decode(package["encrypted_key"], "encrypted_key")
    try:
        session_key = recipient_private_key.decrypt(encrypted_session_key, _oaep_padding())
    except (ValueError, TypeError) as exc:
        raise SessionKeyDecryptionError(
            "Could not decrypt the session key. The recipient private key may be incorrect."
        ) from exc
    if len(session_key) != AES_KEY_SIZE_BYTES:
        raise SessionKeyDecryptionError("The recovered session key has an invalid length.")

    nonce = _b64decode(package["nonce"], "nonce")
    ciphertext = _b64decode(package["ciphertext"], "ciphertext")
    tag = _b64decode(package["tag"], "tag")
    associated_data = canonical_json(package["metadata"])
    try:
        plaintext = AESGCM(session_key).decrypt(nonce, ciphertext + tag, associated_data)
    except InvalidTag as exc:
        raise AuthenticationError(
            "AES-GCM authentication failed. The encrypted data or metadata is invalid; no plaintext was written."
        ) from exc

    if len(plaintext) != package["metadata"]["plaintext_size"]:
        # Signed metadata should already prevent this, but keep an explicit consistency check.
        raise AuthenticationError("Recovered file size does not match signed metadata; no plaintext was written.")

    # This line is reached only after signature verification and successful GCM authentication.
    _atomic_write(Path(output_path), plaintext, mode=0o600)
    return package["metadata"]
