# ADR 0008: SSH signatures for ciphertext authenticity

- Status: Accepted
- Date: 2026-07-29
- Decision owners: EnvGuardian maintainers

## Context

age encrypts to public recipients. Anyone who can read `recipients.toml` can
therefore construct ciphertext that decrypts for every current recipient.
Successful decryption establishes confidentiality for recipients, not the
identity of the sender.

EnvGuardian needs detached, reviewable provenance for each committed
ciphertext without implementing cryptographic primitives or introducing a
second team trust store.

## Decision

EnvGuardian uses OpenSSH signatures through `ssh-keygen -Y sign` and
`ssh-keygen -Y verify`. It does not implement signing or verification itself.
The signature namespace is `envguardian`.

Each ciphertext has a detached sibling signature. For `.env.age`, the path is
`.env.age.sig`. EnvGuardian signs a versioned, domain-separated canonical
payload containing only public repository metadata:

```text
envguardian-signature-v1
ciphertext_sha256=<byte-length>:<SHA-256 of exact ciphertext bytes>
recipients_fingerprint=<byte-length>:<current public recipient fingerprint>
config_path=<byte-length>:<repository-relative config path>
plaintext_path=<byte-length>:<configured repository-relative plaintext path>
ciphertext_path=<byte-length>:<configured repository-relative ciphertext path>
```

Every value is UTF-8 byte-length-prefixed so a path cannot inject another
field. The additional mapping fields deliberately exceed the minimum requirement to
bind the signature to the complete single-file configuration context. A valid
signature cannot be moved to another ciphertext, recipient set, config file,
plaintext destination, or ciphertext destination.

Verification builds a temporary OpenSSH allowed-signers file from current SSH
recipient keys only. The principal is the recipient name. A signature is valid
only when `ssh-keygen -Y verify` accepts the canonical payload for a current
recipient. age X25519 recipients remain valid encryption recipients but cannot
sign; a sealer must use an SSH identity belonging to a current recipient.

Signing is part of the seal transaction. Replacement ciphertext and signature
bytes are generated before any managed file is modified. Ciphertext,
recipients, signature, and lock are committed as one rollback-capable logical
transaction, with lock written last.

For the v0.1.x migration, a missing signature produces an explicit warning and
does not by itself fail verification or decryption. A present but malformed,
invalid, incorrectly bound, or non-recipient signature fails closed. In v0.2,
a missing signature becomes a failure.

Signature-verification failures use a dedicated error type and CLI exit code.
Missing-signature migration warnings are not represented by that error.

## Consequences

- Existing developer SSH keys and the reviewable recipients file remain the
  trust root; no new key distribution format is introduced.
- Signatures interoperate with OpenSSH and reuse the same operational model as
  required SSH-signed Git commits.
- `ssh-keygen` must be available for sealing with an SSH key and for signature
  verification. Errors name the operation and remediation without including
  secret material.
- Passphrase-protected SSH keys may prompt through `ssh-keygen` according to
  normal OpenSSH behavior.
- Pure age X25519 identities can decrypt but cannot establish authorship. Teams
  need at least one current SSH recipient to seal authenticated ciphertext.
- The signed payload contains ciphertext and recipient derivatives only. It
  contains no plaintext value, hash, length, prefix, or other plaintext
  derivative.

## Alternatives considered

### minisign or signify

Both provide a good detached-signature model, but they introduce a second key
format, trust store, executable, and onboarding path. That duplicates the SSH
keys EnvGuardian and Git already rely on.

### Raw Ed25519 signatures in Go

Rejected. It would require defining key loading, signature encoding,
canonicalization, and trust semantics around a cryptographic primitive. That
violates EnvGuardian's rule to use established public APIs rather than
implement cryptographic mechanisms.

### Sign only the ciphertext bytes

Rejected. A valid detached signature could be copied with its ciphertext and
re-pointed through another config mapping. The canonical payload must bind the
ciphertext to its repository configuration context and recipient set.
