# EnvGuardian

[![CI](https://github.com/YehiaGewily/envguardian/actions/workflows/ci.yml/badge.svg)](https://github.com/YehiaGewily/envguardian/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/YehiaGewily/envguardian/branch/main/graph/badge.svg)](https://codecov.io/gh/YehiaGewily/envguardian)
[![Go Reference](https://pkg.go.dev/badge/github.com/YehiaGewily/envguardian.svg)](https://pkg.go.dev/github.com/YehiaGewily/envguardian)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

EnvGuardian lets a team commit its `.env` to git — encrypted — so cloning or
pulling the repo is all it takes to have working local configuration. It
encrypts your `.env` to every developer's age/SSH public key and commits the
ciphertext; access is a plaintext, reviewable recipients file, so adding a
teammate is a pull request. It is a key-management and git-integration layer
over [`age`](https://github.com/FiloSottile/age) — **not** a cryptographic
implementation.

## Install

**Homebrew**

```bash
brew install YehiaGewily/tap/envguardian
```

**go install**

```bash
go install github.com/YehiaGewily/envguardian/cmd/envguardian@latest
```

**Prebuilt binaries** — download for Linux/macOS/Windows (amd64 + arm64) from the
[releases page](https://github.com/YehiaGewily/envguardian/releases), extract,
and put `envguardian` on your `PATH`.

Requires Go 1.24+ to build from source.

## Quickstart (5 minutes)

```bash
# 1. In your repo, scaffold config, seed yourself as a recipient, fix .gitignore
envguardian init

# 2. Create your .env as usual, then encrypt it
printf 'DATABASE_URL=postgres://localhost/dev\nSTRIPE_KEY=sk_test_123\n' > .env
envguardian encrypt                 # writes .env.age (idempotent — no diff churn)

# 3. Install git hooks: auto-decrypt after pull, block plaintext commits
envguardian install-hooks

# 4. Commit the ciphertext and config
git add .env.age .envguardian .gitignore
git commit -m "add encrypted config"
```

A teammate clones the repo and runs **`envguardian decrypt`** — using an SSH key
they already have — and immediately has a working `.env`. To grant access:

```bash
envguardian add-recipient --github <their-username>   # re-encrypts automatically
git add .envguardian .env.age && git commit -m "grant access to <username>"
```

Other commands: `list-recipients`, `check` (CI verification), `diff` (key-level,
never values). Run `envguardian <cmd> --help` for details.

## CI: verifying sync

`envguardian check` exits non-zero if the repo is out of sync — the ciphertext
doesn't match the plaintext (when decryptable), the recipients file is
malformed, the recipient-set fingerprint in `lock.toml` disagrees with
`recipients.toml`, a plaintext file isn't gitignored, a rotation is pending, or
the config version is unsupported. It reports **every** failure and supports
`--json`.

Store a CI identity's **private key** as a repository secret (e.g. `AGE_KEY`):

```yaml
# .github/workflows/envguardian.yml
name: envguardian
on: [push, pull_request]
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: "1.24" }
      - run: go install github.com/YehiaGewily/envguardian/cmd/envguardian@latest
      - name: Verify secrets are in sync
        env:
          ENVGUARDIAN_IDENTITY: ${{ secrets.AGE_KEY }}
        run: envguardian check
```

`$ENVGUARDIAN_IDENTITY` accepts a path **or** raw key material, so the secret
passes inline. Add the CI key as a recipient first:
`envguardian add-recipient --key age1... --name ci`.

## Threat model

Being explicit about the limits is the point. See
[docs/PLAN.md §2](docs/PLAN.md) for the long form.

**Protects against**

- **Repo read access alone.** A leaked clone, an over-broad org grant, an
  accidentally-public repo, or ciphertext in CI logs yields nothing without a
  recipient's private key.
- **Accidental plaintext commits.** The pre-commit hook blocks them.
- **Silent config drift.** `check` fails in CI when the ciphertext is out of
  sync with the recipients list.

**Does NOT protect against**

- **Current recipients.** Anyone in `recipients.toml` can read everything. By
  design.
- **Former recipients, historically.** Git history retains every prior
  ciphertext, so someone removed today can still decrypt everything they had
  access to yesterday. **The only real remediation is rotating the credentials
  themselves** at their source.
- **A compromised developer machine.** The private key and the decrypted `.env`
  both sit on disk.
- **A malicious pull request** adding an attacker's key to `recipients.toml`.
  Mitigate with a `CODEOWNERS` rule requiring review of that file.

**Assumptions**

- Developers already have and protect an SSH key.
- The repo host enforces branch protection and PR review.
- The plaintext `.env` is gitignored — the tool refuses to encrypt otherwise.

## Non-goals

| Not this | Use instead |
|---|---|
| A runtime secrets manager | Vault, AWS Secrets Manager |
| Production secret injection | Your cloud provider's parameter store |
| A server / SaaS | There is no server. That's the point. |
| Storage for large or binary secrets | Object storage with its own encryption |
| A compliance or audit system | Real IAM with real audit logs |

## `.env` parsing conformance

There is no `.env` standard, and the popular parsers disagree in ways that
silently corrupt values. EnvGuardian follows POSIX-ish semantics and is
**stricter** on ambiguity (duplicate keys, bare keys, and undefined `${VAR}` are
errors, not silent coercions). The full case-by-case table — verified by a
differential test against `joho/godotenv` — is in
[docs/dotenv-conformance.md](docs/dotenv-conformance.md).

| Capability | godotenv | python-dotenv | Node dotenv | Docker `--env-file` | **EnvGuardian** |
|---|:--:|:--:|:--:|:--:|:--:|
| Strips `export ` | ✅ | ✅ | v16+ | ❌ | ✅ |
| Double-quote escapes | `\n\r` only | full | `\n`/`\r` only | ❌ | full |
| `${VAR}` interpolation | ✅ | ✅ | needs plugin | ❌ | ✅ |
| Interp. in single quotes | ❌ | ❌ | ❌ | ❌ | ❌ |
| Multiline quoted values | ✅ | ✅ | v15+ | ❌ | ✅ |
| Inline comment needs space | ✅ | ✅ | ❌ (cuts any `#`) | ❌ | ✅ |
| Bare key `K` (no `=`) | error | unset | ignored | host env | **error** |
| Duplicate key | last wins | last wins | last wins | last wins | **error** |
| Round-trips comments/order | ❌ | ❌ | ❌ | ❌ | ✅ |

## Contributing & security

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). Changes
are tracked in [CHANGELOG.md](CHANGELOG.md).

## License

[MIT](LICENSE)
