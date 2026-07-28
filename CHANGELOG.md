# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

### Changed

- Removed unavailable Homebrew and prebuilt-binary installation claims.
- Made manual release workflow runs produce snapshot artifacts without
  publishing.
- Corrected parser conformance, package documentation, milestone status, and
  unimplemented command guidance.
- Limited `v0.1.1` to one file pair per `--config`, added strict config/version
  parsing, made commands discover the repository from subdirectories, defined
  JSON-capable commands, removed the unused `--no-color` flag, and made
  `--verbose` emit secret-safe command progress.
- Added the additive recipient `keys = [...]` schema while retaining legacy
  `key =` reads; v0.1.1 still rejects multiple GitHub Ed25519 keys explicitly.
- Added a bounded GitHub HTTP client, oversized-response rejection, and
  validation of every returned Ed25519 key.

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

[Unreleased]: https://github.com/YehiaGewily/envguardian/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/YehiaGewily/envguardian/tree/v0.1.0
