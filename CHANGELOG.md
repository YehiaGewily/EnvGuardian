# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Upgraded `golang.org/x/crypto` to v0.52.0 to fix GO-2026-5018, a denial of
  service from pathological RSA/DSA parameters. It was reachable through SSH
  recipient and identity parsing, and `recipients.toml` is repository
  controlled. The module minimum is now Go 1.25, which that release requires.
- Release binaries are built with the newest Go 1.27 patch release instead of
  Go 1.25, whose standard library has known vulnerabilities reachable from
  EnvGuardian.

### Added

- `doctor` diagnoses the local setup without decrypting: config and
  recipients validity, `ssh-keygen` availability, gitignored plaintext,
  ciphertext `-text` attributes, hook and driver installation and whether
  their recorded binary still exists, and whether `HEAD` matches the accepted
  commit. It supports `--json` and exits non-zero only for failures.
- `add-file PLAINTEXT` and `remove-file PLAINTEXT` manage file mappings without
  hand-editing `config.toml`. The config change, ciphertext, signature, and
  lock are committed as one transaction.
- Release archives include bash, zsh, fish, and PowerShell completion scripts,
  and the Homebrew cask installs the bash, zsh, and fish ones.
- The user guide documents a dedicated CI recipient for full `check`.

- `--signing-key PATH` (or `ENVGUARDIAN_SIGNING_KEY`) names an SSH public key
  whose private half is held by `ssh-agent`, such as 1Password, Secretive, or
  a hardware token. Sealing signs through the agent with
  `ssh-keygen -Y sign`, so agent-only keys can seal; decryption still uses the
  `--identity` key. The signing key must belong to a current recipient. See
  ADR 0009.

- `check --base REF` compares the snapshot with a trusted base revision. Every
  ciphertext that changed since `REF` must be signed by a recipient already
  listed at `REF`, so a pull request that adds its author as a recipient (or
  swaps a recipient's key) and re-seals with `encrypt --force` fails with exit
  code 4. Recipient changes are reported by name. Resolving or reading `REF`
  failing, or `REF` having no EnvGuardian configuration, is a failure.

- Commands that write managed or plaintext files (`init`, `encrypt`,
  `decrypt`, `add-recipient`, `revoke`, `rotation done`, `install-hooks`,
  `diff --install`, `merge`, and the automatic-decryption hook) take an
  exclusive, non-blocking operating-system lock on `.git/envguardian.lock` (in
  the user cache directory outside Git). A second concurrent command exits 1
  instead of interleaving its transaction. The lock is released when the
  process exits, so a crash never leaves a stale lock. Read-only commands do
  not take it.

### Changed

- Native Go fuzz targets now cover the config, recipients, lock, and
  rotation-ledger parsers and the semantic merge. Config fuzzing asserts that
  every accepted mapping resolves inside the repository and outside `.git/`;
  merge fuzzing asserts the conflict set does not depend on which side is
  ours. CI fuzzes each target on every run.
- Releases publish an SPDX SBOM per archive and a GitHub build-provenance
  attestation for every archive, SBOM, and `checksums.txt`. Verify a download
  with `gh attestation verify FILE --repo YehiaGewily/EnvGuardian`.
- CI tests Go 1.25 (the module minimum) and 1.27, runs `govulncheck`, and
  enforces the 85% package coverage floor on `internal/authenticity`.

### Fixed

- Hooks quote the recorded binary and config paths as literal POSIX shell words,
  as the diff and merge drivers already did, so `$`, backticks, and quotes in a
  path are no longer interpreted by the shell.
- When the binary recorded in a hook has moved, the hook falls back to
  `envguardian` on `PATH` with a reinstall hint. With no binary available,
  `pre-commit` blocks the commit instead of failing with a missing-file error.
- The managed hook block runs in a subshell, so a file checkout no longer skips
  hook content that follows EnvGuardian's block.
- `install-hooks`, `diff --install`, and `merge --install` refuse to record a
  temporary `go run` binary, which Go deletes when the command exits.

- `init` now writes `*.age -text` and `*.age.sig -text` to `.gitattributes`.
  Without them, a teammate cloning with `core.autocrlf=true` (the Git for
  Windows default) received line-converted ciphertext, so `check` reported a
  lock digest and signature mismatch and `decrypt` refused with exit code 4.
  Repositories initialized with v0.2.0 or v0.2.1 should add both lines to
  `.gitattributes` and commit them (`envguardian merge --install` also adds
  them).
- `envguardian version` no longer reports `dev (commit none, built unknown)` for
  binaries built without release ldflags. Fields left at those defaults fall
  back to the version Go embeds in the binary (the module version for
  `go install ...@vX.Y.Z`) and to `vcs.revision` and `vcs.time` when present.
  Release ldflags still take precedence.

### Security

- Plain `decrypt` inside a Git repository no longer bypasses the accepted-commit
  trust check. In v0.2.0 and v0.2.1 it decrypted the working tree without
  consulting trust state, so after the post-checkout or post-merge hook refused
  a branch that added its author to `recipients.toml` and re-sealed the
  ciphertext with `encrypt --force`, plain `decrypt` overwrote local `.env` with
  that branch's values. It now runs the hook's comparison (one shared function)
  and, if config, recipients, any ciphertext, or any signature at `HEAD` differs
  from the accepted commit, refuses before writing plaintext, lists only key and
  recipient names, and exits 1. It also refuses when no accepted commit is
  recorded, so the first decryption in a fresh clone must be
  `decrypt --accept-changes`. It writes plaintext only from committed `HEAD`
  blobs and refuses uncommitted managed changes, except that an uncommitted
  ciphertext that verifies and decrypts to exactly the local plaintext (after
  your own `encrypt`) leaves that file untouched and succeeds. Outside a Git
  repository `decrypt` still reads the files on disk; a `.git` entry or
  `GIT_DIR` that Git cannot open fails closed.
- On Windows, owner-only writes (mode `0600`: decrypted plaintext, local
  auto-decrypt state, and signing temporaries) are now created with a
  protected DACL granting only the current user, applied before any content is
  written. If the DACL cannot be applied or confirmed, the write fails and
  leaves no temporary file. Administrators, SYSTEM, and backup tools can still
  read these files, and files written by older versions keep their old ACL
  until rewritten. Tools that replace `.env` (editor "safe write", copying or
  restoring the file) still produce a file with the directory's inherited ACL.

## [0.2.1] - 2026-08-01

Documentation-only release candidate; the binary behaves like v0.2.0.

### Changed

- Added the GitHub Pages landing page, refreshed branding assets, and updated
  README installation notes for the published release-candidate binaries and
  Homebrew cask.

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

[Unreleased]: https://github.com/YehiaGewily/envguardian/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/YehiaGewily/envguardian/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/YehiaGewily/envguardian/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/YehiaGewily/envguardian/tree/v0.1.0
