# ADR 0002: Support SSH identities alongside native age identities

- Status: Accepted
- Date: 2026-07-29

## Context

Teams already distribute SSH public keys and protect corresponding private
keys. Requiring another key system would make onboarding and review harder.

## Decision

Accept age X25519 and age-supported SSH recipients for decryption. Use SSH
private keys for OpenSSH ciphertext signatures when authorship is required.
Identity resolution remains explicit and secret-safe; an explicitly invalid
identity is never ignored.

## Consequences

Native age identities can decrypt but cannot sign. Sealing authenticated
ciphertext requires a current SSH recipient and `ssh-keygen`.
