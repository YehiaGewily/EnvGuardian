# Security Policy

## Supported versions

EnvGuardian is pre-1.0. Security fixes land on the latest `0.x` release only.

| Version | Supported |
|---|---|
| latest `0.x` | ✅ |
| older | ❌ |

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Email **yehyaheya@gmail.com** with:

- a description of the issue and its impact,
- steps to reproduce (a proof of concept if you have one),
- affected version(s) and platform.

You can expect an acknowledgement within **72 hours** and a status update within
**7 days**. Once a fix is available we will coordinate a disclosure timeline with
you and credit you in the release notes unless you prefer to remain anonymous.

If you prefer encrypted email, request our public key in your first (unencrypted)
message and we'll reply with it.

## Scope

In scope:

- Recovery of secret **values** by anyone with only repository read access.
- Committing a value-derived artifact (hash, HMAC, length) that acts as an
  offline brute-force oracle for low-entropy secrets.
- Bypassing the pre-commit plaintext guard or the `check` sync verification.
- Identity-resolution or decryption flaws that leak key material.

Out of scope (see the threat model in the [README](README.md)):

- Access by a **current recipient** — anyone in `recipients.toml` can read
  everything by design.
- Decryption of **historical** ciphertext by a **former recipient** — git
  history is immutable; the remedy is rotating the credential at its source, not
  a tool change.
- Compromise of a developer's machine, where the private key and decrypted
  `.env` both live.
