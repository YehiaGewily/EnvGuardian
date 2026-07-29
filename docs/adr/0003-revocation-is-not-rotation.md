# ADR 0003: Revocation is not credential rotation

- Status: Accepted
- Date: 2026-07-29

## Context

Removing a recipient and re-encrypting blocks that identity from new
ciphertext, but Git history still contains ciphertext the former recipient can
decrypt. Upstream credentials exposed in those files therefore remain usable.

## Decision

`revoke NAME` transactionally removes the recipient and records every affected
dotenv key name in `.envguardian/rotation.toml`. `rotation status` and
`rotation done KEY` track the external work. The ledger contains key names only,
never values or value derivatives.

## Consequences

Revocation succeeds only when existing ciphertext can be decrypted and the
remaining set is non-empty. Users must rotate pending credentials at their
source; marking a key done asserts that separate action occurred.
