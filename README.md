# EnvGuardian

[![CI](https://github.com/YehiaGewily/EnvGuardian/actions/workflows/ci.yml/badge.svg)](https://github.com/YehiaGewily/EnvGuardian/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/YehiaGewily/envguardian)](https://goreportcard.com/report/github.com/YehiaGewily/envguardian)
[![Go Reference](https://pkg.go.dev/badge/github.com/YehiaGewily/envguardian.svg)](https://pkg.go.dev/github.com/YehiaGewily/envguardian)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> [!WARNING]
> **Pre-release software — security hardening is in progress. Do not use
> EnvGuardian for real secrets yet.** The `v0.1.0` development tag has a known
> path-traversal vulnerability in repository-controlled file mappings. Do not
> install its automatic git hooks. See [SECURITY.md](SECURITY.md) and the
> tracked [remediation plan](docs/PLAN.md).

EnvGuardian is intended to let a team commit its `.env` to git encrypted, so
local configuration can travel with the repository. It encrypts with
[`age`](https://github.com/FiloSottile/age) recipients and keeps access in a
plaintext, reviewable recipients file. EnvGuardian is a key-management and
git-integration layer over age, **not** a cryptographic implementation.

The current code is an unsupported prototype. There is no supported release,
Homebrew package, or published binary distribution. Contributors can inspect
the CLI from source:

```bash
go run ./cmd/envguardian version
```

Do not install hooks from `v0.1.0`. The `v0.2.0` release candidate contains
the Stage A path-containment and explicit-acceptance controls, the Stage B
transactional sealing core, the Stage C fail-closed verification paths, Stage D
detached SSH signatures, Stage E secret-safe/atomic hygiene and coverage gates,
and Stage F revocation, rotation, merge, and multi-file work. `v0.1.1` was not
cut before those v0.2 features landed. The project remains unsupported until final
release verification and repository protection are complete.

## Current implementation status

The prototype contains `init`, `encrypt`, `decrypt`, `add-recipient`, `revoke`,
`rotation`, `list-recipients`, `check`, `check-local`, `install-hooks`, `diff`,
and `merge`. Their
presence does not mean they are ready to protect real secrets:

- Managed plaintext and ciphertext paths are resolved at config load, confined
  to the repository, checked through existing-parent symlinks, and excluded
  from `.git/`.
- v0.2 configuration accepts multiple distinct plaintext/ciphertext mappings.
  Every replacement is planned before mutation and the shared lock contains one
  exact entry per configured ciphertext.
- Existing ciphertext is decrypted and semantically compared before any
  replacement. A simultaneous recipient change and divergent local plaintext
  is rejected instead of silently choosing the local file.
- `lock.toml` version 2 has exactly one entry per configured ciphertext and
  binds the recipient fingerprint to that ciphertext's SHA-256 digest. The
  digest covers already-public ciphertext, never plaintext.
- `add-recipient` plans before writing and commits ciphertext, detached
  signature, recipients, and lock as one rollback-capable logical transaction.
  Missing local plaintext is recovered in memory from the existing ciphertext.
- Every new or replaced ciphertext gets a sibling `.sig` made through
  `ssh-keygen -Y sign`. The signature binds the ciphertext digest, recipient
  fingerprint, config path, and complete file mapping. Verification accepts
  only a current SSH recipient. Sealing therefore requires an SSH private-key
  file; age-only identities can still decrypt.
- `check` verifies committed repository integrity: config and paths,
  recipients, lock digest/fingerprint, ciphertext signature, ciphertext
  decryption and dotenv validity, gitignore state, and the rotation ledger. It requires an identity;
  `--structural-only` is the explicit fork-PR mode when CI secrets are absent.
  It deliberately does not compare uncommitted local plaintext because CI
  cannot observe a developer's `.env`.
- `check-local` compares the developer's plaintext with decryptable ciphertext
  and fails on a missing plaintext unless `--allow-missing` is explicit.
- Automatic hooks compare the exact incoming commit with a local accepted
  commit. Changes to config, recipients, ciphertext, or signature require an
  explicit `decrypt --accept-changes`; hook decryption reads and authenticates
  committed blobs rather than unreviewed working-tree paths.
- The pre-commit hook verifies config, recipients, lock, ciphertext, and
  detached signature from the Git index, rejects staged plaintext, detects
  partial staging, and requires an identity when managed state changes. Commits
  touching no managed file run structural verification only.
- `diff --install` registers a repository-local, two-sided external Git diff
  driver. It reports `+ KEY`, `- KEY`, and `~ KEY`; comments and reordering are
  ignored, and values or other plaintext derivatives are never emitted.
- User-visible parser, identity, age, SSH, and Git diagnostics omit secret
  input and untrusted upstream output. All production file writes use the
  atomic writer, and CI enforces `crypt`, `config`, `keys`, and `dotenv` at 85%
  plus 80% whole-repository statement coverage.
- `revoke NAME` removes access through the planner and records affected dotenv
  key names in the public rotation ledger. `rotation status` and `rotation done
  KEY` track external credential rotation; re-encryption cannot erase access to
  ciphertext already present in Git history.
- `merge --install` registers local semantic drivers. Git pauses even a clean
  key-level resolution so `merge --continue` can re-encrypt, re-sign, rebuild
  the complete lock transactionally, and stage the generated artifacts.
- age still provides confidentiality, not sender authentication. EnvGuardian's
  separate detached SSH signature establishes ciphertext authorship. The
  v0.1.x missing-signature warning is retired: invalid, non-recipient, and
  missing signatures all fail closed in v0.2.

The authoritative status and sequencing are in [docs/PLAN.md](docs/PLAN.md).
The old M0/M1/M2/M3 plan is historical; current implementation status is kept
in the tracked remediation plan.

## Threat model

> **Windows permission limitation:** EnvGuardian writes plaintext atomically,
> but Go's `0600` mode has no Windows ACL equivalent. The current development
> build does not install or verify a restrictive DACL, so other local accounts
> may retain access through inherited directory permissions. Do not use
> EnvGuardian for real secrets on Windows until native ACL enforcement lands.

The intended confidentiality property is narrow: repository read access alone
does not reveal plaintext without a recipient identity, assuming age itself is
used correctly. See the full [threat model](docs/threat-model.md), including the
automatic-decryption acceptance boundary and detached-signature trust model.

EnvGuardian does not protect against:

- **Current recipients.** Anyone in `recipients.toml` can read everything by
  design.
- **Former recipients, historically.** Git history retains prior ciphertext.
  Removing a recipient does not rotate the upstream credential.
- **A compromised developer machine.** The private key and decrypted `.env`
  both live on disk.
- **A malicious contributor.** age does not authenticate the ciphertext
  sender. A contributor can create ciphertext that decrypts for every listed
  recipient, but cannot create a valid EnvGuardian signature without a current
  recipient's SSH private key. Unsigned v0.1.x migration artifacts remain
  visibly weaker and still depend on explicit review/acceptance.
- **A malicious repository configuration in `v0.1.0`.** Automatic decryption
  can write outside the repository; see the advisory in
  [SECURITY.md](SECURITY.md).

Before any future supported release, deployments must enforce pull-request
reviews, signed commits, protected `main`, required CI, and review of the
security-sensitive paths in [.github/CODEOWNERS](.github/CODEOWNERS).

## Non-goals

| Not this | Use instead |
|---|---|
| A runtime secrets manager | Vault, AWS Secrets Manager |
| Production secret injection | Your cloud provider's parameter store |
| A server / SaaS | There is no server. |
| Storage for large or binary secrets | Object storage with its own encryption |
| A compliance or audit system | IAM with audit logs |

## `.env` parsing conformance

There is no `.env` standard. EnvGuardian's parser is stricter on ambiguity and
preserves source formatting. CI explicitly runs the pinned `joho/godotenv`
differential suite. Python, Node, and Docker columns are documented reference
notes, not CI-verified claims. See
[docs/dotenv-conformance.md](docs/dotenv-conformance.md).

## Documentation

- **[User Guide](docs/USER_GUIDE.md)**: Comprehensive command reference, daily developer workflows, git hooks, diff/merge drivers, and troubleshooting.
- **[Remediation & Architecture Plan](docs/PLAN.md)**: Authoritative status, stage map, and release verification gates.
- **[Threat Model](docs/threat-model.md)**: Security boundaries, automatic decryption trust model, and detached signature provenance.

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md) before changing code. Report security
issues using [SECURITY.md](SECURITY.md), not a public issue. Changes are recorded
in [CHANGELOG.md](CHANGELOG.md).

## License

[MIT](LICENSE)
