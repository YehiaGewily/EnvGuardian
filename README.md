# EnvGuardian

Commit your team's `.env` to git — encrypted — so cloning or pulling the repo
is all it takes to have working local configuration.

EnvGuardian is a key-management and git-integration layer over
[`age`](https://github.com/FiloSottile/age). It encrypts your `.env` to every
developer's public key and commits the ciphertext. Access is a plaintext,
reviewable recipients file: adding a teammate is a pull request.

> **Status:** early skeleton. Only `version` is implemented today.

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
