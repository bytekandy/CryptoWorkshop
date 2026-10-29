# Secure Examination-Paper Exchange (Python)

A workshop demonstration of hybrid encryption, a digital signature, and authenticated decryption. It is a local command-line simulation: the `exchange/` directory represents an untrusted communication channel.

> Use only fictional examination material. This workshop project is a learning demonstration, not a complete institutional key-management system.

## 1. Cryptography used

- **RSA-3072**: separate key pairs are generated for sender and recipient.
- **AES-256-GCM**: encrypts the entire file using a fresh 256-bit session key and a fresh 12-byte nonce for each encryption. Its 16-byte authentication tag is stored separately in the JSON package.
- **RSA-OAEP with SHA-256**: encrypts the small AES session key with the recipient's public key.
- **RSA-PSS with SHA-256**: signs a canonical representation of the package using the sender's private key.
- **Encrypted private-key PEMs**: private keys are stored as PKCS#8 PEM files protected by passphrases. The passphrases are requested using `getpass`; they are not stored in the project.

The package signature covers the metadata, encrypted session key, nonce, ciphertext, and GCM tag. Metadata is also passed to AES-GCM as associated authenticated data (AAD). The receiver verifies the signature before attempting to decrypt the session key, and writes plaintext only after AES-GCM authentication succeeds.

## 2. Install (Arch Linux / other Linux)

Run these commands in this project directory:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

If the `python` command is unavailable, install Python and its virtual-environment support using your distribution's package manager.

## 3. Generate keys and simulate trusted public-key exchange

```bash
python main.py setup
```

Create two different passphrases when prompted. Use at least 12 characters and store them securely. The program creates:

```text
sender/private_key.pem          Sender's encrypted private key
sender/public_key.pem           Sender's public key
recipient/private_key.pem       Recipient's encrypted private key
recipient/public_key.pem        Recipient's public key
trusted_keys/sender_public_key.pem
sender/recipient_public_key.pem
```

The two public-key copies simulate an exchange through a trusted channel. The sender uses the recipient's public key. The recipient verifies with `trusted_keys/sender_public_key.pem`. In a real deployment, confirm public-key fingerprints using an independent trusted channel; simply downloading a public key from the same untrusted channel does not authenticate its owner.

`setup` refuses to overwrite existing private keys. To deliberately replace both keys, run `python main.py setup --force`. Do not do this while you still need to decrypt packages created for the old keys.

## 4. Sender: encrypt and sign

A fictional sample file is provided at `sender/exam_paper.txt`.

```bash
python main.py encrypt --input sender/exam_paper.txt --output exchange/package_1.json
```

Enter the sender private-key passphrase when requested. The output is a JSON package containing metadata, an RSA-OAEP-encrypted AES key, nonce, ciphertext, GCM tag, and RSA-PSS signature. It does not contain the original plaintext.

Encrypt the same file again to demonstrate fresh randomness:

```bash
python main.py encrypt --input sender/exam_paper.txt --output exchange/package_2.json
```

Both packages should decrypt to the same original bytes but should differ from each other.

## 5. Recipient: verify and decrypt

Treat the JSON file in `exchange/` as if it arrived through an untrusted channel:

```bash
python main.py decrypt --input exchange/package_1.json --output recovered/exam_paper.txt
```

Enter the recipient private-key passphrase. The order is:

1. Parse and validate the package structure and algorithm identifiers.
2. Verify the signature using the trusted sender public key.
3. Decrypt the AES session key with the recipient private key and RSA-OAEP/SHA-256.
4. Verify the AES-GCM tag and decrypt using the signed metadata as AAD.
5. Check the recovered size and atomically write the plaintext.

If validation, signature verification, session-key decryption, or GCM authentication fails, the program reports an error and does not write a new plaintext file. Test failures with a new/nonexistent output path so an old successful output cannot be confused with a new result.

## 6. Confirm correct recovery and fresh packages

```bash
cmp sender/exam_paper.txt recovered/exam_paper.txt
sha256sum sender/exam_paper.txt recovered/exam_paper.txt
```

`cmp` prints nothing and returns exit status 0 if the files are identical. The two SHA-256 hashes should match.

Check that separate encryptions produce different packages:

```bash
if cmp -s exchange/package_1.json exchange/package_2.json; then
  echo "Unexpected: packages are identical"
else
  echo "Expected: packages differ"
fi
```

## 7. Run all automated security tests

```bash
python -m unittest discover -s tests -v
```

Tests create temporary key pairs and temporary input/output files; they do not overwrite your working demo keys or the files in `sender/`, `exchange/`, or `recovered/`. They cover:

1. Authorized recipient recovers the original file.
2. Modified ciphertext is rejected by signature verification.
3. Modified metadata is rejected by signature verification.
4. Modified signature is rejected.
5. Incorrect recipient private key cannot recover the session key.
6. Incorrect sender public key cannot validate the signature.
7. Encrypting the same file twice creates different packages, both of which decrypt correctly.
8. GCM tag verification fails even when the altered package is re-signed in the test, demonstrating the second authentication layer.

## 8. How to explain the security properties

- **Confidentiality:** The file is encrypted using AES-256-GCM. The AES key is encrypted for the recipient using the recipient's RSA public key. A person who only obtains the package should not be able to read the paper without the recipient's private key.
- **Integrity:** RSA-PSS detects changes to any signed package field. AES-GCM separately authenticates the ciphertext and metadata used as AAD.
- **Sender authentication:** The recipient verifies the signature using a sender public key that was authenticated through a trusted channel. A signature alone does not prove a real-world identity unless the key-to-person binding is trusted.
- **Failure handling:** The program rejects malformed packages, bad signatures, wrong recipient keys, and failed GCM authentication. Plaintext is written only after all cryptographic checks succeed.

## 9. Important limitations

- The `setup` command copies public keys locally only to simulate a trusted exchange. In a real system, verify key fingerprints or use a managed certificate/public-key infrastructure.
- The sender and recipient passphrases are entered interactively but the strength and secrecy of those passphrases remain the operator's responsibility.
- This demo loads the whole file into memory; very large files would need a carefully designed streaming-encryption format.
- A valid signature does not prevent replay of an older, valid package. A production system should add policy checks such as an expected exam identifier, recipient identity, validity period, and duplicate/replay tracking.
- Packages are protected cryptographically, but you must still protect the computer, backups, and private keys. Do not commit private keys or real examination papers to source control.
