# Secure Examination-Paper Exchange

This project was developed as part of a Cryptography workshop. The aim is to securely transfer an examination paper from a faculty member to an authorised examination coordinator, even if the file passes through an untrusted channel.

The application is written in Python and runs from the command line. For this demonstration, the `exchange/` directory acts as the communication channel. The sender places an encrypted package there, and the recipient retrieves and decrypts it.

**Note:** This is an educational project. Use fictional examination material for testing, not actual confidential examination papers.

## Cryptographic Algorithms Used

The application combines symmetric encryption, public-key cryptography, and digital signatures.

| Algorithm | Purpose |
|---|---|
| RSA-3072 | Generates separate key pairs for the sender and recipient |
| AES-256-GCM | Encrypts the examination paper and authenticates the encrypted data |
| RSA-OAEP with SHA-256 | Encrypts the AES session key using the recipient's public key |
| RSA-PSS with SHA-256 | Signs the encrypted package using the sender's private key |
| Base64 | Encodes binary data so it can be stored in a JSON package |

A new random AES session key and nonce are generated for every encryption. The AES key is encrypted with the recipient's public key, so the recipient can recover it using their private key.

The sender signs the package, including its metadata, encrypted session key, nonce, ciphertext, and authentication tag. The recipient verifies the signature before decrypting the session key and checks the AES-GCM authentication tag before writing the recovered file.

Private keys are stored in passphrase-protected PEM files. The application asks for passphrases when needed rather than storing them in the source code.

## Requirements

- Python 3.10 or newer
- `pip`
- An internet connection for installing the required Python library

You can use Windows, Linux, or macOS. The commands below assume you have opened a terminal in the project directory.

## Installation

Clone the repository and enter the project directory:

```bash
git clone https://github.com/bytekandy/CryptoWorkshop.git
cd CryptoWorkshop
```

### Windows — PowerShell

Create a virtual environment, activate it, and install the dependency:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

If PowerShell blocks virtual-environment activation, you can use the environment's Python executable directly:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

In that case, replace `python` in the remaining commands with `.\.venv\Scripts\python.exe`.

### Windows — Command Prompt

```bat
py -m venv .venv
.venv\Scripts\activate.bat
python -m pip install -r requirements.txt
```

### Linux and macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

The application uses the `cryptography` Python library for its cryptographic operations.

## Running the Application

### 1. Generate the keys

Run:

```bash
python main.py setup
```

The program asks you to create two different passphrases, one for the sender's private key and another for the recipient's private key. Each passphrase must contain at least 12 characters.

The application generates separate RSA key pairs for both participants and saves the keys in their respective directories.

The relevant files are:

```text
sender/
├── private_key.pem
├── public_key.pem
└── recipient_public_key.pem

recipient/
├── private_key.pem
└── public_key.pem

trusted_keys/
└── sender_public_key.pem
```

The sender's public key is copied to `trusted_keys/` for the recipient, while the recipient's public key is copied to `sender/` for encryption.

This simulates the trusted public-key exchange assumed in the workshop problem. In a real deployment, public keys must be authenticated independently, for example by comparing their fingerprints through a trusted channel.

The setup command does not overwrite existing keys by default. Use `python main.py setup --force` only if you intend to replace them. Packages encrypted for the old recipient key may no longer be decryptable after replacing the keys.

### 2. Prepare a sample examination paper

The repository includes a fictional sample file:

```text
samples/exam_paper.example.txt
```

Copy it into the sender's working directory.

**Windows PowerShell:**

```powershell
Copy-Item samples/exam_paper.example.txt sender/exam_paper.txt
```

**Linux and macOS:**

```bash
cp samples/exam_paper.example.txt sender/exam_paper.txt
```

You can edit the copied file to try different input content. Do not use a real confidential examination paper.

### 3. Encrypt and sign the file

Run:

```bash
python main.py encrypt --input sender/exam_paper.txt --output exchange/package_1.json
```

Enter the sender's private-key passphrase when prompted.

The application reads the file, generates a fresh AES session key and nonce, encrypts the file using AES-GCM, and encrypts the session key using the recipient's RSA public key.

It then signs the package using the sender's RSA private key and saves the result as a JSON file in `exchange/`.

The package contains the encrypted data and the information required for verification and decryption, not the original examination text in plaintext.

### 4. Encrypt the same file again

To demonstrate that fresh randomness is used, run:

```bash
python main.py encrypt --input sender/exam_paper.txt --output exchange/package_2.json
```

The two packages should differ even though they were generated from the same input file.

Both packages should still decrypt to the same original contents.

### 5. Verify and decrypt the package

The recipient runs:

```bash
python main.py decrypt --input exchange/package_1.json --output recovered/exam_paper.txt
```

Enter the recipient's private-key passphrase when prompted.

The recipient performs these checks in order:

1. Reads and validates the package structure.
2. Verifies the digital signature using the trusted sender public key.
3. Decrypts the AES session key using the recipient's private key.
4. Authenticates and decrypts the file using AES-GCM.
5. Checks the recovered file size and writes the plaintext only after successful verification.

If a signature, key, package field, or authentication tag is invalid, the application rejects the package without writing newly decrypted plaintext.

For failure tests, use a new output filename or remove any previous output file first. This prevents an old successful result from being mistaken for a new decryption.

## Verifying the Results

After a successful decryption, compare the original and recovered files.

### Windows — PowerShell

```powershell
$original = Get-FileHash sender/exam_paper.txt -Algorithm SHA256
$recovered = Get-FileHash recovered/exam_paper.txt -Algorithm SHA256

$original
$recovered
```

The two SHA-256 hash values should match.

### Linux and macOS

```bash
cmp sender/exam_paper.txt recovered/exam_paper.txt
sha256sum sender/exam_paper.txt recovered/exam_paper.txt
```

If `cmp` produces no output and exits with status `0`, the files are identical.

## Running the Security Tests

Run the automated test suite from the project directory:

```bash
python -m unittest discover -s tests -v
```

The tests use temporary files and temporary RSA keys. They cover the following cases:

1. The authorised recipient successfully recovers the original file.
2. A modified ciphertext is rejected.
3. Modified metadata is rejected.
4. A modified digital signature is rejected.
5. An incorrect recipient private key cannot recover the session key.
6. An incorrect sender public key fails signature verification.
7. Encrypting the same file twice produces different packages that both decrypt correctly.
8. AES-GCM rejects a modified authentication tag even when the test signs the modified package again.

The expected result is that all eight tests pass.

## How the Application Provides Security

**Confidentiality**

AES-256-GCM encrypts the examination paper. RSA-OAEP protects the AES session key so that the intended recipient can recover it using their private key.

**Integrity**

RSA-PSS detects changes to the signed package. AES-GCM also authenticates the encrypted data and associated metadata.

**Sender Authentication**

The recipient verifies the package using the trusted sender public key. A valid signature shows that the package was signed using the corresponding private key. Associating that key with a particular faculty member depends on trusting the public-key exchange.

**Failure Handling**

Malformed packages, invalid signatures, incorrect recipient keys, and failed AES-GCM authentication result in rejection. The application writes plaintext only after the required cryptographic checks succeed.

## Limitations

- The project simulates communication using local folders rather than an actual network connection.
- The public-key exchange is simulated locally. A real system needs a reliable way to verify the identity associated with each public key.
- The program reads the complete file into memory, so it is intended for small demonstration files.
- The application does not implement replay prevention or institutional access-control policies.
- Private keys, passphrases, generated packages, recovered plaintext, and real examination papers must not be committed to a public repository.

## Project Structure

```text
CryptoWorkshop/
├── main.py
├── crypto_utils.py
├── requirements.txt
├── README.md
├── SEQUENCE_DIAGRAM.md
├── test_results.txt
├── samples/
│   └── exam_paper.example.txt
└── tests/
    └── test_crypto.py
```

- `main.py` — command-line interface for setup, encryption, and decryption.
- `crypto_utils.py` — key generation, encryption, signing, verification, and file handling.
- `tests/test_crypto.py` — automated security tests.
- `SEQUENCE_DIAGRAM.md` — sequence diagram showing the communication flow.
- `samples/exam_paper.example.txt` — fictional input for the demonstration.
- `requirements.txt` — Python dependencies.
