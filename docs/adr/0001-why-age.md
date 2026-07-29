# ADR 0001: Use age as the encryption boundary

- Status: Accepted
- Date: 2026-07-29

## Context

EnvGuardian needs file encryption for small dotenv payloads without becoming a
cryptographic implementation or inventing a wire format.

## Decision

Use `filippo.io/age` through its public API for encryption and decryption. Keep
all EnvGuardian code above that boundary: recipient management, repository
transactions, authentication, and Git integration.

## Consequences

age supplies confidentiality for listed recipients, not sender authentication,
history erasure, or a runtime secret store. EnvGuardian must provide separate
ciphertext signatures and must never implement curves, ciphers, or KDFs.
