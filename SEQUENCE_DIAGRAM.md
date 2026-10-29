# Sequence Diagram — Secure Examination-Paper Exchange

```mermaid
sequenceDiagram
    actor S as Sender / Faculty
    participant E as Exchange Folder (Untrusted)
    actor A as Attacker
    actor R as Recipient / Coordinator

    S->>S: Generate fresh AES-256 session key and nonce
    S->>S: Encrypt paper using AES-GCM and authenticate metadata as AAD
    S->>S: Encrypt AES key with recipient public key using RSA-OAEP/SHA-256
    S->>S: Sign metadata, encrypted key, nonce, ciphertext and tag using RSA-PSS/SHA-256
    S->>E: Store signed encrypted JSON package
    Note over E,A: Package crosses an untrusted channel
    A-->>E: May read, modify or replace package
    E->>R: Deliver package
    R->>R: Validate package format and verify signature with trusted sender public key
    alt Signature invalid
        R-->>R: Reject package; do not decrypt or write plaintext
    else Signature valid
        R->>R: Decrypt session key with recipient private key and RSA-OAEP
        R->>R: Verify GCM tag and decrypt ciphertext using authenticated metadata
        alt GCM authentication fails
            R-->>R: Reject package; write no plaintext
        else GCM authentication succeeds
            R->>R: Verify plaintext size and atomically write recovered file
        end
    end
```

## Sequence summary

1. The sender encrypts the input file with AES-GCM, wraps the AES key for the recipient with RSA-OAEP, and signs all security-relevant package fields using RSA-PSS.
2. The exchange folder represents the untrusted channel. An attacker can alter or replace bytes but cannot make the altered package pass verification without the signing key.
3. The recipient checks the signature before recovering the session key. AES-GCM then independently authenticates the encrypted content and metadata.
4. The program writes plaintext only after signature verification, successful session-key recovery, successful GCM authentication, and a size check.
