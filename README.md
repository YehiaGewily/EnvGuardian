# EnvGuardian

Commit your team's `.env` to git — encrypted — so cloning or pulling the repo
is all it takes to have working local configuration.

EnvGuardian is a key-management and git-integration layer over
[`age`](https://github.com/FiloSottile/age). It encrypts your `.env` to every
developer's public key and commits the ciphertext. Access is a plaintext,
reviewable recipients file: adding a teammate is a pull request.

> **Status:** early development (M2). Working commands: `init`, `encrypt`,
> `decrypt`, `add-recipient`, `list-recipients`, `check`, `install-hooks`,
> `diff`.

## Quick start

```bash
envguardian init                 # scaffold config, seed you as a recipient, fix .gitignore
# create your .env, then:
envguardian encrypt              # writes .env.age (idempotent — no diff churn)
envguardian install-hooks        # auto-decrypt after pull; block plaintext commits
git add .env.age .envguardian && git commit -m "add encrypted config"
```

A teammate clones the repo and runs `envguardian decrypt` — using an SSH key
they already have. To grant access: `envguardian add-recipient --github <user>`,
then commit the updated `recipients.toml` and `.env.age`.

## CI: verifying sync

`envguardian check` verifies the repo is in sync and exits non-zero if not:
the ciphertext matches the plaintext (when decryptable), the recipients file is
well-formed, the recipient-set fingerprint in `lock.toml` matches
`recipients.toml`, plaintext files are gitignored, no rotations are pending, and
the config version is supported. It reports **every** failure, not just the
first, and supports `--json`.

Store a CI identity's **private key** as a repository secret (e.g. `AGE_KEY`),
then:

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
        with:
          go-version: "1.24"
      - run: go install github.com/YehiaGewily/envguardian/cmd/envguardian@latest
      - name: Verify secrets are in sync
        env:
          ENVGUARDIAN_IDENTITY: ${{ secrets.AGE_KEY }}
        run: envguardian check
```

`$ENVGUARDIAN_IDENTITY` accepts either a path or the raw key material, so the
secret can be passed inline as above. Add the CI key as a recipient with
`envguardian add-recipient --key age1... --name ci` so `check` can decrypt.

## Non-goals

| Not this | Use instead |
|---|---|
| A runtime secrets manager | Vault, AWS Secrets Manager |
| Production secret injection | Your cloud provider's parameter store |
| A server / SaaS | There is no server. That's the point. |
| Storage for large or binary secrets | Object storage with its own encryption |
| A compliance or audit system | Real IAM with real audit logs |

## Build

```bash
make build
./envguardian version
```

Requires Go 1.24+.

## License

[MIT](LICENSE)
