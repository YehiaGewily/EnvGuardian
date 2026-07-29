# ADR 0008: Authenticate ciphertext with detached SSH signatures

- Status: Accepted
- Date: 2026-07-29

## Context

age recipients are public. Anyone can encrypt a malicious dotenv to every
recipient, so successful decryption proves confidentiality but not authorship.

## Decision

Use `ssh-keygen -Y sign/verify` with namespace `envguardian`; do not implement a
signature primitive. Each `*.age` has a detached `*.age.sig`. Sign a versioned,
domain-separated payload binding the exact ciphertext digest, public recipient
fingerprint, config path, plaintext path, and ciphertext path. Length-prefix
every field. Verify against current SSH recipients only.

Signing participates in the planner transaction. A missing or invalid signature
fails verification for v0.2 artifacts with the dedicated signature error and
exit code.

## Consequences

Signatures cannot be copied to another ciphertext, recipient set, config, or
mapping. Native age identities remain valid for decryption but cannot establish
authorship. The signed material contains no plaintext or plaintext derivative.

## Alternatives

Minisign/signify would add a second trust store. Raw Ed25519 would make
EnvGuardian define cryptographic encoding and key semantics. Signing ciphertext
alone would permit re-pointing a valid artifact. All three alternatives are
rejected.
