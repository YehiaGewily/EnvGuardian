# ADR 0007: Separate repository integrity from local synchronization

- Status: Accepted
- Date: 2026-07-29

## Context

CI cannot observe an uncommitted developer `.env`, while local workflows need
to know whether that plaintext matches committed ciphertext.

## Decision

`check` verifies repository structure, lock, signature, decryptability, dotenv,
ignore rules, and rotation state. Missing identity is failure unless
`--structural-only` is explicit. `check-local` compares working plaintext with
decrypted ciphertext and has its own missing-file policy.

## Consequences

CI makes no false claim about local state. Hooks and developers use the local
check when synchronization is the question, and every unperformed verification
fails closed unless the caller selected its narrow structural mode.
