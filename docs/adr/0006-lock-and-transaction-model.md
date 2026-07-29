# ADR 0006: Bind lock state to ciphertext and commit through a planner

- Status: Accepted
- Date: 2026-07-29

## Context

Recipient, ciphertext, signature, and lock updates form one logical change.
Partial or reordered writes can leave a repository appearing current when it is
not.

## Decision

Lock v2 stores one entry per configured ciphertext with the public recipient
fingerprint and SHA-256 of exact public ciphertext bytes. Plan every seal and
signature before mutation, retain originals for rollback, write atomically, and
write the complete lock last. The planner remains slice-shaped and is the basis
for multi-file, recipient, revocation, and merge transactions.

## Consequences

Ordinary failures roll back attempted writes. Crash-interrupted changes are
detectable because ciphertext bytes no longer match the committed lock digest.
No plaintext derivative enters the lock.
