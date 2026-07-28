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

Do not install hooks from `v0.1.0`. Development code for `v0.1.1` now contains
the Stage A path-containment and explicit-acceptance controls and the Stage B
transactional sealing core, but the project remains unsupported until the
remaining release gates are complete.

## Current implementation status

The prototype contains `init`, `encrypt`, `decrypt`, `add-recipient`,
`list-recipients`, `check`, `install-hooks`, and `diff`. Their presence does not
mean they are ready to protect real secrets:

- Managed plaintext and ciphertext paths are resolved at config load, confined
  to the repository, checked through existing-parent symlinks, and excluded
  from `.git/`.
- `v0.1.1` accepts exactly one plaintext/ciphertext pair per `--config`. The
  internal seal/commit API remains slice-shaped for transactional multi-file
  support in `v0.2.0`. A non-default config gets an adjacent config-specific
  lock (`staging.toml` uses `staging.lock.toml`) so separate invocations do not
  overwrite each other's lock entry.
- Existing ciphertext is decrypted and semantically compared before any
  replacement. A simultaneous recipient change and divergent local plaintext
  is rejected instead of silently choosing the local file.
- `lock.toml` version 2 has exactly one entry per configured ciphertext and
  binds the recipient fingerprint to that ciphertext's SHA-256 digest. The
  digest covers already-public ciphertext, never plaintext.
- `add-recipient` plans before writing and commits ciphertext, recipients, and
  lock as one rollback-capable logical transaction. Missing local plaintext is
  recovered in memory from the existing ciphertext.
- `check` cannot prove an absent, uncommitted local `.env` is current. Stage C
  will separate repository checks from `check-local` synchronization checks.
- Automatic hooks compare the exact incoming commit with a local accepted
  commit. Changes to config, recipients, or ciphertext require an explicit
  `decrypt --accept-changes`; hook decryption reads committed blobs rather than
  unreviewed working-tree paths.
- age provides confidentiality, not sender authentication. Ciphertext
  provenance remains unverified until Stage D.
- Revocation, rotation commands, and the merge driver are not implemented.

The authoritative status and sequencing are in [docs/PLAN.md](docs/PLAN.md).
The old M0/M1/M2/M3 plan is historical; M3 is unimplemented.

## Threat model

The intended confidentiality property is narrow: repository read access alone
does not reveal plaintext without a recipient identity, assuming age itself is
used correctly. See the full [threat model](docs/threat-model.md), including the
temporary automatic-decryption acceptance boundary and the remaining Stage D
authenticity gap.

EnvGuardian does not protect against:

- **Current recipients.** Anyone in `recipients.toml` can read everything by
  design.
- **Former recipients, historically.** Git history retains prior ciphertext.
  Removing a recipient does not rotate the upstream credential.
- **A compromised developer machine.** The private key and decrypted `.env`
  both live on disk.
- **A malicious contributor.** age does not authenticate the ciphertext
  sender. A contributor can create ciphertext that decrypts for every listed
  recipient unless a separate provenance mechanism verifies it.
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
preserves source formatting. The current automated differential test compares
only with `joho/godotenv`; it has a build tag and does not run in the normal CI
workflow. The Python, Node, and Docker columns are documented reference notes,
not CI-verified claims. See
[docs/dotenv-conformance.md](docs/dotenv-conformance.md).

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md) before changing code. Report security
issues using [SECURITY.md](SECURITY.md), not a public issue. Changes are recorded
in [CHANGELOG.md](CHANGELOG.md).

## License

[MIT](LICENSE)
