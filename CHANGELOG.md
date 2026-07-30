# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-07-30

First supported release candidate. `v0.1.1` was not cut before the v0.2
feature set landed, so the project advances directly from the unsafe v0.1.0
development tag to v0.2.0.

### Added

- Added transactional multi-file configuration on the plural seal planner and
  a shared lock with one authenticated entry per ciphertext.
- Added `revoke`, `rotation status`, and `rotation done` with a versioned,
  key-name-only rotation ledger and explicit Git-history limitations.
- Added a local semantic merge driver with key-name-only conflicts,
  authenticated branch inputs, transactional re-encryption, and re-signing.
- Added ADRs 0001–0008 documenting the cryptographic boundary, identity model,
  transaction rules, verification split, managed paths, and authentication.

### Security

- Marked the project unsupported for real secrets while hardening is in
  progress and published the repository path-traversal advisory.
- Established the tracked remediation plan and permanent engineering rules.
- Confined managed plaintext and ciphertext paths to the repository, including
  cross-platform absolute-path rejection, existing-parent symlink resolution,
  `.git/` exclusion, and mapping collision checks.
- Changed automatic decryption to compare exact committed config, recipients,
  and ciphertext blobs against a local accepted commit. Managed changes now
  require `decrypt --accept-changes`.
- Required decrypted payloads to parse as dotenv before any plaintext write.
- Replaced the recipient-change bypass with a decrypt-and-compare seal planner.
  Recipient changes with divergent local plaintext now fail without writing.
- Added lock format v2 with one entry per ciphertext, the current public
  recipient fingerprint, and a SHA-256 digest of the exact public ciphertext.
- Made recipient addition plan first and commit ciphertext, recipients, and
  lock as one rollback-capable transaction, with the lock written last.
- Made repository `check` require decryption by default, with an explicit
  `--structural-only` mode, and added `check-local` for developer plaintext
  synchronization. Unreadable or malformed rotation ledgers now fail closed.
- Rebuilt pre-commit verification around exact Git-index blobs, including
  staged lock/ciphertext/recipient checks, plaintext rejection, identity
  enforcement for managed changes, partial-staging detection, and safe config
  removal handling.
- Added detached OpenSSH signatures for ciphertext authenticity. The signed
  public payload binds exact ciphertext bytes, recipient fingerprint, config
  path, and file mapping; verification accepts only current SSH recipients.
  Present invalid signatures fail before plaintext writes with exit code 4.
- Included signature writes in seal and recipient transactions, verified exact
  signature blobs in checks and hooks, and made Git snapshot reads fail closed.
  Missing signatures fail closed in v0.2.0.
- Removed malformed dotenv fragments, identity/key material, and untrusted
  subprocess output from diagnostics; added sentinel non-disclosure tests.
- Routed all production writes through the atomic writer, preserved existing
  hook modes, and documented the unresolved Windows ACL limitation.

### Changed

- Removed unavailable Homebrew and prebuilt-binary installation claims.
- Made manual release workflow runs produce snapshot artifacts without
  publishing.
- Corrected parser conformance, package documentation, milestone status, and
  unimplemented command guidance.
- Added strict config/version parsing, made commands discover the repository
  from subdirectories, defined JSON-capable commands, removed the unused
  `--no-color` flag, and made `--verbose` emit secret-safe command progress.
- Added the additive recipient `keys = [...]` schema while retaining legacy
  `key =` reads; explicit duplicate keys are rejected across recipients.
- Added a bounded GitHub HTTP client, oversized-response rejection, and
  validation of every returned Ed25519 key.
- Replaced the one-sided Git textconv prototype with a local-only external diff
  command that compares both decrypted sides and reports added, removed, and
  value-changed key names without emitting plaintext derivatives.
- Hook installation now refuses pre-existing hook files without a valid
  shebang instead of creating a hook Git cannot execute reliably.
- Canonicalized the current directory before rendering relative CLI paths and
  made path-resolution tests compare canonical paths, covering macOS `/var`
  aliases and Windows long-name versus 8.3 path aliases.

## [0.1.0] - 2026-07-28

Unreleased development tag. It was not published as a supported GitHub release
and must not be used for real secrets.

### Prototype functionality

- CLI commands for initialization, encryption, decryption, recipient handling,
  checks, hook installation, and key-name-only diff output.
- An age wrapper with a plaintext comparison path, recipient and identity
  loading, a source-preserving dotenv parser, atomic core file-writing helper,
  and git integration prototypes.
- A public recipient-set fingerprint in `lock.toml`. This prototype lock is not
  per ciphertext and is not bound to ciphertext bytes; it is insufficient for
  repository-integrity proof.
- A build-tagged differential test against `joho/godotenv`. It does not run in
  the normal CI workflow. Python, Node, and Docker differential runners do not
  exist.

### Known limitations

- Repository-controlled plaintext paths can escape the repository or target
  `.git/`, including through automatic hooks.
- Recipient changes can bypass decrypt-and-compare and `--force` permits a blind
  replacement.
- `check` can skip synchronization when no identity or local plaintext exists;
  it is not yet the fail-closed repository check described by the v2 plan.
- Hook and dotfile writes are not all routed through the atomic writer.
- Revocation, rotation commands, sender authentication, a merge driver, and the
  ADR set are unimplemented.

See [SECURITY.md](SECURITY.md) and [docs/PLAN.md](docs/PLAN.md).

[Unreleased]: https://github.com/YehiaGewily/envguardian/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/YehiaGewily/envguardian/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/YehiaGewily/envguardian/tree/v0.1.0
