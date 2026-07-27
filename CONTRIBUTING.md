# Contributing to EnvGuardian

Thanks for your interest. EnvGuardian has a deliberately small scope (see the
non-goals table in the [README](README.md)); the fastest way to get a change
merged is to fit within it.

## Ground rules

These come from [CLAUDE.md](CLAUDE.md) and are non-negotiable:

1. **Never implement cryptographic primitives.** Use age's public API only. A
   change that touches a curve, cipher, or KDF directly should stop and open an
   issue first.
2. **Never write ciphertext unless the decrypted plaintext actually changed.**
   age is randomized; unconditional re-encryption creates churn and merge
   conflicts. All writes route through the decrypt-compare loop in
   `internal/crypt`.
3. **All file writes are atomic** (temp file + fsync + rename, via
   `internal/atomic`). Plaintext files get mode `0600`.
4. **Never print a secret value** to stdout, stderr, or logs. Diffs and errors
   report key names only.
5. **Never commit a derivative of a secret value** — no hash, HMAC, or length,
   anywhere. Only derivatives of public data (recipient keys) may be committed.

## Development

```bash
make build      # compile with version metadata
make test       # go test -race ./...
make lint       # golangci-lint
make fuzz       # 60s of parser fuzzing
make test-diff  # differential test vs joho/godotenv (needs the dependency)
```

- Go 1.24+.
- Small packages, explicit errors wrapped with `%w`, no global state, no
  `init()` side effects. Errors say what was tried and what to do next.
- Everything lives under `internal/`; the public API surface is intentionally
  zero.

## Tests

- Table-driven tests; native Go fuzzing on the parser; golden files for CLI
  output; integration tests build a real git repo in `t.TempDir()`.
- New parser behavior must be reflected in
  [docs/dotenv-conformance.md](docs/dotenv-conformance.md) and its differential
  test.
- Target: the `dotenv` and `crypt` packages stay above 85% coverage.

## Pull requests

- Keep changes focused; one concern per PR.
- Run `make test lint` before pushing; CI runs the matrix over
  linux/macOS/windows.
- Update `CHANGELOG.md` under `## [Unreleased]`.
- By contributing you agree your work is licensed under the project's
  [MIT license](LICENSE).

## Reporting security issues

Do **not** open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).
