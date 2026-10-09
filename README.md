<div align="center">

<picture>
  <source type="image/svg+xml" media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-horizontal-dark.svg">
  <source type="image/svg+xml" srcset="docs/assets/logo-horizontal.svg">
  <img alt="EnvGuardian" src="docs/assets/logo-horizontal.png" width="300">
</picture>

<br><br>

**Commit your team's `.env` to git — encrypted — so cloning the repo is all it takes to have working local config.**

<sub>🌐&nbsp; <a href="https://yehiagewily.github.io/EnvGuardian/">envguardian landing page</a>&nbsp; ·&nbsp; 📖 <a href="docs/USER_GUIDE.md">User Guide</a>&nbsp; ·&nbsp; 🗺️ <a href="docs/PLAN.md">Status &amp; roadmap</a></sub>

A key-management and git-integration layer over [`age`](https://github.com/FiloSottile/age). *Not* a cryptographic implementation.

[![CI](https://github.com/YehiaGewily/EnvGuardian/actions/workflows/ci.yml/badge.svg)](https://github.com/YehiaGewily/EnvGuardian/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/YehiaGewily/envguardian)](https://goreportcard.com/report/github.com/YehiaGewily/envguardian)
[![Go Reference](https://pkg.go.dev/badge/github.com/YehiaGewily/envguardian.svg)](https://pkg.go.dev/github.com/YehiaGewily/envguardian)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

</div>

> [!WARNING]
> **Pre-release software — security hardening is in progress. Do not use EnvGuardian for
> real secrets yet.** Pre-built binaries are attached to the
> [`v0.2.1`](https://github.com/YehiaGewily/EnvGuardian/releases/tag/v0.2.1) release, but it
> is a **release candidate** — unsupported and not yet verified end to end. The `v0.1.0`
> development tag has a known path-traversal vulnerability in
> repository-controlled file mappings — **do not install its automatic git hooks.** See
> [SECURITY.md](SECURITY.md) and the tracked [remediation plan](docs/PLAN.md).

---

## Contents

- [The idea](#the-idea)
- [Quickstart](#quickstart)
- [How it works](#how-it-works)
- [Implementation status](#implementation-status)
- [Threat model](#threat-model)
- [Non-goals](#non-goals)
- [`.env` parsing conformance](#env-parsing-conformance)
- [Documentation](#documentation)
- [Contributing & security](#contributing--security)

## The idea

Local configuration should travel with the repository. EnvGuardian encrypts your `.env` to
every developer's [`age`](https://github.com/FiloSottile/age)/SSH **public** key and commits
the ciphertext, so pulling the repo is all it takes to have working config. Access is a
plaintext, **reviewable** recipients file — adding or removing someone is a normal code review.

Three questions decide everything the tool does:

| Question | Answered by | File |
|---|---|---|
| **Who can decrypt?** | The recipient set (public keys) | `recipients.toml` |
| **What is the secret?** | The encrypted bytes | `<file>.age` |
| **Is it authentic & current?** | A detached signature + a lock | `<file>.age.sig`, `lock.toml` |

## Quickstart

> **Install the release candidate.**
> ```bash
> # macOS / Linux — Homebrew
> brew install --cask yehiagewily/tap/envguardian
>
> # Any platform with Go 1.25+
> go install github.com/YehiaGewily/envguardian/cmd/envguardian@v0.2.1
> ```
> Or run from source without installing — the examples below use `go run ./cmd/envguardian`;
> swap in `envguardian` if you installed it. Pre-built binaries for every OS are on the
> [releases page](https://github.com/YehiaGewily/EnvGuardian/releases/tag/v0.2.1).

**Repo owner — first-time setup:**

```bash
go run ./cmd/envguardian init                        # scaffold config, seed your key, update .gitignore
go run ./cmd/envguardian add-recipient --github alice # authorize a teammate
go run ./cmd/envguardian encrypt                      # .env → .env.age (+ .env.age.sig)

git add .envguardian/ .env.age .env.age.sig          # commit the PUBLIC, encrypted files (never .env)
git commit -m "chore: add encrypted env config"
go run ./cmd/envguardian decrypt --accept-changes    # record that commit as your accepted state
```

**Teammate — after cloning:** the first decryption in a clone is an explicit trust
decision. Review who can decrypt and what you are about to install, then accept it:

```bash
go run ./cmd/envguardian list-recipients             # review recipients.toml
go run ./cmd/envguardian decrypt --accept-changes    # record HEAD as accepted; .env.age → .env (mode 0600)
```

**After that:** inside a Git repository, `decrypt` installs only the commit you last
accepted. Plain `decrypt` restores that snapshot (for example after deleting `.env`). If the
config, recipients, any ciphertext, or any signature at `HEAD` differs from the accepted
commit — after a pull, checkout, or merge, including your own commits — it writes nothing,
lists the changed key and recipient names, and exits 1. Review the change, then accept it
explicitly:

```bash
go run ./cmd/envguardian decrypt --accept-changes
```

📖 Full workflows, every flag, git hooks, diff/merge drivers, and troubleshooting are in the
**[User Guide](docs/USER_GUIDE.md)**.

## How it works

Two independent triggers decide when a re-encrypt (a *seal*) happens:

1. **Must we write?** — Yes if the plaintext content changed, **or** the recipient
   fingerprint changed, **or** no ciphertext exists yet.
2. **What do we write?** — Always the result of *decrypt-comparing* against the existing
   ciphertext.

A recipient change forces a write, but it **never** overwrites the ciphertext blindly with
your local `.env` — that would silently revert a teammate's secrets. Sealing is idempotent:
unchanged content produces no diff (age is randomized, so blind re-encryption would churn
diffs and cause needless merge conflicts).

> **age gives confidentiality, not sender authentication.** `recipients.toml` is public, so
> anyone can craft ciphertext that decrypts for every recipient — successful decryption
> alone proves nothing about *who* wrote it. That is why every ciphertext carries a detached
> SSH signature (`.age.sig`) that is verified against current recipients before any plaintext
> is written.

## Implementation status

The CLI contains `init`, `encrypt`, `decrypt`, `add-recipient`, `revoke`, `rotation`,
`list-recipients`, `check`, `check-local`, `install-hooks`, `diff`, and `merge`. **Their
presence does not mean they are ready to protect real secrets** — the project is still in
release hardening.

<details>
<summary><strong>Expand for the full per-area status</strong></summary>

<br>

- Managed plaintext and ciphertext paths are resolved at config load, confined to the
  repository, checked through existing-parent symlinks, and excluded from `.git/`.
- v0.2 configuration accepts multiple distinct plaintext/ciphertext mappings. Every
  replacement is planned before mutation and the shared lock contains one exact entry per
  configured ciphertext.
- Existing ciphertext is decrypted and semantically compared before any replacement. A
  simultaneous recipient change and divergent local plaintext is rejected instead of
  silently choosing the local file.
- `lock.toml` version 2 has exactly one entry per configured ciphertext and binds the
  recipient fingerprint to that ciphertext's SHA-256 digest. The digest covers
  already-public ciphertext, never plaintext.
- `add-recipient` plans before writing and commits ciphertext, detached signature,
  recipients, and lock as one rollback-capable logical transaction. Missing local plaintext
  is recovered in memory from the existing ciphertext.
- Every new or replaced ciphertext gets a sibling `.sig` made through `ssh-keygen -Y sign`.
  The signature binds the ciphertext digest, recipient fingerprint, config path, and
  complete file mapping. Verification accepts only a current SSH recipient. Sealing
  therefore requires an SSH private-key file; age-only identities can still decrypt.
- `check` verifies committed repository integrity: config and paths, recipients, lock
  digest/fingerprint, ciphertext signature, ciphertext decryption and dotenv validity,
  gitignore state, and the rotation ledger. It requires an identity; `--structural-only` is
  the explicit fork-PR mode when CI secrets are absent. It deliberately does not compare
  uncommitted local plaintext because CI cannot observe a developer's `.env`.
- `check-local` compares the developer's plaintext with decryptable ciphertext and fails on
  a missing plaintext unless `--allow-missing` is explicit.
- Automatic hooks and plain `decrypt` inside a Git repository share one gate: they compare
  `HEAD` with a local accepted commit. Changes to config, recipients, ciphertext, or
  signature require an explicit `decrypt --accept-changes`, and so does a clone with no
  accepted commit. Both read and authenticate committed blobs rather than unreviewed
  working-tree paths; plain `decrypt` also refuses uncommitted managed changes unless leaving
  the local plaintext untouched already matches them. Outside a Git repository, `decrypt`
  reads the files on disk.
- The pre-commit hook verifies config, recipients, lock, ciphertext, and detached signature
  from the Git index, rejects staged plaintext, detects partial staging, and requires an
  identity when managed state changes. Commits touching no managed file run structural
  verification only.
- `diff --install` registers a repository-local, two-sided external Git diff driver. It
  reports `+ KEY`, `- KEY`, and `~ KEY`; comments and reordering are ignored, and values or
  other plaintext derivatives are never emitted.
- User-visible parser, identity, age, SSH, and Git diagnostics omit secret input and
  untrusted upstream output. All production file writes use the atomic writer, and CI
  enforces `crypt`, `config`, `keys`, and `dotenv` at 85% plus 80% whole-repository
  statement coverage.
- `revoke NAME` removes access through the planner and records affected dotenv key names in
  the public rotation ledger. `rotation status` and `rotation done KEY` track external
  credential rotation; re-encryption cannot erase access to ciphertext already present in
  Git history.
- `merge --install` registers local semantic drivers. Git pauses even a clean key-level
  resolution so `merge --continue` can re-encrypt, re-sign, rebuild the complete lock
  transactionally, and stage the generated artifacts.
- age still provides confidentiality, not sender authentication. EnvGuardian's separate
  detached SSH signature establishes ciphertext authorship. The v0.1.x missing-signature
  warning is retired: invalid, non-recipient, and missing signatures all fail closed in v0.2.

</details>

The authoritative status and sequencing live in [docs/PLAN.md](docs/PLAN.md). The old
M0/M1/M2/M3 plan is historical.

## Threat model

> [!IMPORTANT]
> **Windows file permissions.** On Windows, decrypted plaintext and local auto-decrypt state
> are created with a protected, owner-only DACL: one entry for the current user, no inherited
> entries, applied before any content is written. If that DACL cannot be applied or read back
> (for example on FAT/exFAT volumes), the write fails instead of falling back to inherited
> permissions. As with root on Unix, Administrators, SYSTEM, and backup tools can still read
> these files, and plaintext written by older versions keeps its old ACL until EnvGuardian
> rewrites it.

The intended confidentiality property is narrow: repository read access alone does not
reveal plaintext without a recipient identity, assuming age itself is used correctly. See the
full [threat model](docs/threat-model.md), including the automatic-decryption acceptance
boundary and detached-signature trust model.

EnvGuardian does **not** protect against:

- **Current recipients.** Anyone in `recipients.toml` can read everything by design.
- **Former recipients, historically.** Git history retains prior ciphertext. Removing a
  recipient does not rotate the upstream credential.
- **A compromised developer machine.** The private key and decrypted `.env` both live on disk.
- **A malicious contributor.** age does not authenticate the ciphertext sender. A contributor
  can create ciphertext that decrypts for every listed recipient, but cannot create a valid
  EnvGuardian signature without a current recipient's SSH private key. Unsigned v0.1.x
  migration artifacts remain visibly weaker and still depend on explicit review/acceptance.
- **A malicious repository configuration in `v0.1.0`.** Automatic decryption can write
  outside the repository; see the advisory in [SECURITY.md](SECURITY.md).
- **A pull request that adds its author as a recipient.** CI `check` verifies a snapshot
  against that snapshot's own `recipients.toml`. Someone who is not a recipient can add
  their key, run `encrypt --force`, and get a signature that verifies, so `check` passes.
  `check` proves internal consistency and decryptability, not who authored the ciphertext
  or whether the recipient change was authorized: a green `check` on a pull request that
  changes `recipients.toml` proves nothing about who authored the new ciphertext. Human
  review of `.envguardian/recipients.toml` (routed by CODEOWNERS) is the boundary.
  Reviewers should reject pull requests that change recipients and ciphertext together
  unless both changes are confirmed out of band.
- **Plain `decrypt` in `v0.2.0` and `v0.2.1`.** It skipped the accepted-commit check, so it
  installed an unreviewed branch's ciphertext that the hook had refused; see the advisory in
  [SECURITY.md](SECURITY.md).

Before any future supported release, deployments must enforce pull-request reviews, signed
commits, protected `main`, required CI, and review of the security-sensitive paths in
[.github/CODEOWNERS](.github/CODEOWNERS).

## Non-goals

| Not this | Use instead |
|---|---|
| A runtime secrets manager | Vault, AWS Secrets Manager |
| Production secret injection | Your cloud provider's parameter store |
| A server / SaaS | There is no server. |
| Storage for large or binary secrets | Object storage with its own encryption |
| A compliance or audit system | IAM with audit logs |

## `.env` parsing conformance

There is no `.env` standard. EnvGuardian's parser is stricter on ambiguity and preserves
source formatting. CI explicitly runs the pinned `joho/godotenv` differential suite. Python,
Node, and Docker columns are documented reference notes, not CI-verified claims. See
[docs/dotenv-conformance.md](docs/dotenv-conformance.md).

## Documentation

- **[User Guide](docs/USER_GUIDE.md)** — command reference, daily workflows, git hooks,
  diff/merge drivers, and troubleshooting.
- **[Remediation & Architecture Plan](docs/PLAN.md)** — authoritative status, stage map, and
  release verification gates.
- **[Threat Model](docs/threat-model.md)** — security boundaries, automatic-decryption trust
  model, and detached-signature provenance.

## Contributing & security

Read [CONTRIBUTING.md](CONTRIBUTING.md) before changing code. Report security issues using
[SECURITY.md](SECURITY.md), not a public issue. Changes are recorded in
[CHANGELOG.md](CHANGELOG.md).

## License

[MIT](LICENSE)
