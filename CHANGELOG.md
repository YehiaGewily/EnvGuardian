# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-07-28

First public release.

### Added

- **CLI**: `init`, `encrypt`, `decrypt`, `add-recipient`, `list-recipients`,
  `check`, `install-hooks`, and `diff`.
- **Idempotent sealing** (`internal/crypt`): re-encrypting unchanged content is a
  no-op, so age's randomized output never causes diff churn or merge conflicts.
  A `--force` escape hatch re-encrypts blind when the ciphertext can't be
  verified.
- **Recipient management** (`internal/keys`): `recipients.toml` with age and
  SSH (`ssh-ed25519`/`ssh-rsa`) public keys, validated for duplicate names,
  duplicate keys, and malformed material; GitHub key fetching via
  `github.com/<user>.keys`.
- **Identity resolution**: `--identity` → `$ENVGUARDIAN_IDENTITY` (path or raw
  material) → `~/.config/envguardian/identity.txt` → `~/.ssh/id_ed25519` →
  `~/.ssh/id_rsa`, with passphrase-protected age and encrypted SSH key support
  and a clear error listing every source tried.
- **Recipient-set fingerprint** in `lock.toml` (public data only) so a merge
  that leaves the ciphertext encrypted to the wrong set is caught by `check`.
- **dotenv parser/serializer** (`internal/dotenv`): round-trips comments, blank
  lines, key order, quote style, and line endings; native fuzzing; a
  differential test against `joho/godotenv`.
- **Git integration** (`internal/gitint`): a `.gitignore` guard that refuses to
  encrypt an untracked-but-committable plaintext file (with `--fix`);
  `post-merge`/`post-checkout`/`pre-commit` hooks; and a `diff` textconv driver
  that shows changed key **names** only — never values, lengths, or hashes.
- **Atomic writes** (`internal/atomic`): temp file, fsync, rename, parent-dir
  fsync; plaintext written `0600`.
- Docs: threat model, `.env` conformance table, and the implementation plan.

### Security

- No derivative of any plaintext secret value (hash, HMAC, length) is written to
  any committed file — see [CLAUDE.md](CLAUDE.md) rule 6.

[Unreleased]: https://github.com/YehiaGewily/envguardian/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/YehiaGewily/envguardian/releases/tag/v0.1.0
