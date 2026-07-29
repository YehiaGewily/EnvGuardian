# ADR 0004: Preserve ciphertext when semantics and recipients are unchanged

- Status: Accepted
- Date: 2026-07-29

## Context

age encryption is randomized. Unconditional re-encryption produces meaningless
Git diffs and conflicts. Blindly choosing local plaintext during a recipient
change can instead revert teammates' updates.

## Decision

Decrypt existing ciphertext and compare semantic dotenv key/value content.
Write only when content, recipients, or lock state requires it. A recipient
fingerprint decides whether to write; decrypt-and-compare decides what to write.
Concurrent divergence requires explicit resolution.

## Consequences

Unchanged seals are byte-stable. Existing ciphertext cannot be replaced without
a usable identity except through the loud lost-key `--force` escape hatch.
