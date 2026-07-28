# Contributing to EnvGuardian

EnvGuardian has a deliberately small scope (see the non-goals in the
[README](README.md)). The rules in this file are the permanent engineering
rules; they do not depend on a local or tool-specific instruction file.

## Ground rules

1. **Never implement cryptographic primitives.** Use age's public API only. A
   change that directly implements or modifies a curve, cipher, or KDF must stop
   for design review.
2. **Confine every automatic plaintext write to the repository, excluding
   `.git/`.** Resolve and validate repository-controlled paths before reading or
   writing them. Symlinks and platform-specific path forms are part of that
   validation.
3. **Never write replacement ciphertext without decrypting and comparing the
   existing ciphertext first.** A recipient fingerprint may decide whether a
   write is needed; it may never decide what plaintext is written. If existing
   ciphertext cannot be verified, fail closed.
4. **Bind lock state to one ciphertext's exact bytes.** A ciphertext digest is
   public-data metadata and may be committed. Lock state is not a global proxy
   for multiple ciphertexts.
5. **Make file writes atomic.** Use a temporary file in the destination
   directory, fsync, and rename. Plaintext destinations use mode `0600`.
6. **Never expose a plaintext derivative.** Do not commit, log, or print secret
   values, hashes, HMACs, lengths, prefixes, or other value-derived metadata.
   Ciphertext digests and recipient-key fingerprints are allowed because their
   inputs are already public.
7. **Treat age as confidentiality, not sender authentication.** Decrypting
   successfully does not establish who created a ciphertext. Do not describe it
   as provenance or authenticity.
8. **Keep documentation true.** A false security, release, installation, or
   feature claim is a release-blocking bug.
9. **Keep the public API surface at zero.** Project packages live under
   `internal/`.

For `v0.1.1`, changes must preserve the single configured plaintext/ciphertext
pair. Multi-file support returns in `v0.2.0` on top of the transactional
planner. The planner API is intentionally slice-shaped, but do not enable more
than one configured pair until crash recovery and multi-file failure testing
are designed for that release.

## Development

```bash
make build      # compile with version metadata
make test       # go test -race ./...
make lint       # golangci-lint
make fuzz       # 60s of parser fuzzing
make test-diff  # build-tagged differential test vs joho/godotenv
```

- Go 1.24+.
- Prefer small packages, explicit errors wrapped with `%w`, no global state,
  and no `init()` side effects.
- Errors must say what was attempted and what the user can do next without
  including secret values or derivatives.

## Tests

- Use table-driven tests and native Go fuzzing for the parser.
- CLI output should use golden files; integration tests should create real git
  repositories under `t.TempDir()`.
- New parser behavior must update
  [docs/dotenv-conformance.md](docs/dotenv-conformance.md) and relevant tests.
- Coverage above 85% for `dotenv` and `crypt` is a release target, not a claim
  about the current prototype.

## Pull requests

- Keep changes focused.
- Run `make test lint` before pushing; CI tests Go 1.24 and 1.25 on Linux,
  macOS, and Windows.
- Update `CHANGELOG.md` under `## [Unreleased]`.
- Sign commits. Protected branches require signed commits and pull-request
  review.
- By contributing, you agree that your work is licensed under the project's
  [MIT license](LICENSE).

## Reporting security issues

Do not open a public issue for a vulnerability. Follow
[SECURITY.md](SECURITY.md).
