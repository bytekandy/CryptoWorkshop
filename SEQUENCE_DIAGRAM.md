# Sequence Diagram - Secure Examination-Paper Exchange

```mermaid
sequenceDiagram
    actor S as Sender / Faculty
    participant E as Untrusted Exchange Folder
    actor A as Attacker
    actor R as Recipient / Coordinator

    S->>S: Generate AES key and nonce
    S->>S: Encrypt paper with AES-GCM
    S->>S: Encrypt AES key with recipient RSA public key
    S->>S: Sign package using RSA-PSS
    S->>E: Save encrypted package
    Note over E,A: Package travels through an untrusted channel
    A-->>E: May read, modify, or replace package
    E->>R: Deliver package
    R->>R: Verify signature with trusted sender public key
    alt Signature is invalid
        R-->>R: Reject package without writing plaintext
    else Signature is valid
        R->>R: Decrypt AES key with recipient private key
        R->>R: Verify GCM tag and decrypt file
        alt GCM authentication fails
            R-->>R: Reject package without writing plaintext
        else GCM authentication succeeds
            R->>R: Write recovered file
        end
    end
```

## Walkthrough

1. The sender encrypts the paper with a fresh AES key and nonce.
2. The sender encrypts that AES key with the recipient's RSA public key.
3. The sender signs the package, including its metadata, encrypted key, nonce, ciphertext, and authentication tag.
4. The package passes through the untrusted exchange folder. An attacker may change it, but cannot make a modified package pass signature verification without the sender's private key.
5. The recipient verifies the signature, recovers the AES key, and checks the GCM authentication tag.
6. The program writes the recovered file only after the checks succeed.
