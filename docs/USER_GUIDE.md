# EnvGuardian — User Guide (v0.2.0)

Commit your team's `.env` to git — **encrypted** — so cloning or pulling the repo is all
it takes to have working local configuration. Access is a small, reviewable file of
per-developer public keys.

EnvGuardian is a **key-management and git-integration layer over
[`filippo.io/age`](https://filippo.io/age)**. It is *not* a cryptographic
implementation, a runtime secrets manager, or a server. It does one job: keep an
encrypted `.env` in git that exactly the right people can open.

---

> ### ⚠️ Read this first — pre-release status
>
> EnvGuardian is **pre-release**. `v0.2.0` is the first *supported* release candidate;
> `v0.1.0` was a development tag with known critical findings — **do not install hooks or
> binaries from `v0.1.0`.**
>
> - **Do not use it for real production secrets yet.** Use throwaway/dev values until the
>   release is finalized and every install path is publicly verified.
> - **Windows is not yet suitable for real secrets.** Plaintext is written with mode
>   `0600` on Unix, but that does **not** install a restrictive Windows ACL — other local
>   users may be able to read the decrypted `.env`.
> - This guide describes the **implemented** behavior of `v0.2.0`. If the README and this
>   guide ever disagree, trust the source and file an issue.

---

## 1. The mental model

Three questions decide everything EnvGuardian does. Keep them straight and the tool is
predictable.

| Question | Answered by | File |
|---|---|---|
| **Who can decrypt?** | The recipient set (public keys) | `recipients.toml` |
| **What is the secret?** | The encrypted bytes | `<file>.age` |
| **Is it authentic & current?** | A detached signature + a lock | `<file>.age.sig`, `lock.toml` |

Two independent triggers decide a re-encrypt (a *seal*):

1. **Must we write?** — Yes if the plaintext content changed, **or** the recipient
   fingerprint changed, **or** no ciphertext exists yet.
2. **What do we write?** — Always the result of *decrypt-comparing* against the existing
   ciphertext.

> A recipient change forces a write, but it **never** licenses blindly overwriting the
> ciphertext with your local `.env` — that would silently revert a teammate's secrets.
> This is why several commands need an identity even when you're "only" editing the
> recipients file.

### Two guarantees — and one important non-guarantee

- ✅ **Confidentiality.** Only holders of a listed key can decrypt.
- ✅ **Provenance** (via `.age.sig`). A present, valid detached SSH signature proves the
  ciphertext was sealed by a *current* recipient for *this exact repository mapping*.
- ❌ **age decryption is _not_ proof of authorship.** `recipients.toml` is public, so
  anyone — even someone with no access to your secrets — can craft a ciphertext that
  decrypts cleanly for every recipient. **Successful decryption alone proves nothing about
  who wrote it.** That is exactly why the signature exists and is verified before any
  plaintext is written.

---

## 2. Files & what git tracks

Everything lives under `.envguardian/`, next to your `.age` files.

| File | Tracked in git? | Purpose |
|---|:---:|---|
| `.envguardian/config.toml` | ✅ Yes | Maps each plaintext file → its ciphertext file. |
| `.envguardian/recipients.toml` | ✅ Yes | Public keys of everyone allowed to decrypt. |
| `.envguardian/lock.toml` | ✅ Yes | Binds the recipient fingerprint to each ciphertext's exact SHA-256 digest. |
| `.envguardian/rotation.toml` | ✅ Yes | Key **names** pending rotation after a revocation (never values). |
| `.env.age` | ✅ Yes | age-encrypted ciphertext of `.env`. |
| `.env.age.sig` | ✅ Yes | Detached SSH signature over the ciphertext binding. |
| `.env` | 🚫 **Gitignored** | Your local plaintext. **Must never be committed.** |
| `.envguardian/auto-decrypt-state.toml` | 🚫 **Gitignored (local)** | Records the last commit you explicitly accepted for auto-decrypt. Local trust state. |

`init` adds `.env` and `auto-decrypt-state.toml` to `.gitignore` for you.

---

## 3. Quickstart

### A. First-time setup (repo owner)

```bash
# 1. Scaffold config, seed recipients with your own key, update .gitignore
envguardian init

# 2. Add teammates by their public key (see §5 for all the ways)
envguardian add-recipient --github alice
envguardian add-recipient --name bob --key "ssh-ed25519 AAAAC3Nza..."

# 3. Encrypt your local .env → .env.age (+ .env.age.sig)
envguardian encrypt

# 4. Commit the PUBLIC, encrypted files (never .env)
git add .envguardian/ .env.age .env.age.sig
git commit -m "chore: add encrypted env config"
```

`init` seeds `recipients.toml` with the public key derived from your identity (default
`~/.ssh/id_ed25519`, or `--identity <path>`), so you can decrypt immediately.

### B. Teammate workflow (clone / pull)

```bash
# Decrypt every ciphertext → local plaintext (mode 0600)
envguardian decrypt
```

If upstream changed `config.toml`, `recipients.toml`, or any ciphertext, EnvGuardian's
hooks won't silently rewrite your local `.env`. After **reviewing** the incoming change,
accept it explicitly:

```bash
envguardian decrypt --accept-changes
```

### C. Changing a secret

```bash
# 1. Edit your local .env
# 2. Re-encrypt (idempotent — no-op if nothing changed)
envguardian encrypt
# 3. Commit the encrypted artifacts
git add .env.age .env.age.sig .envguardian/lock.toml
git commit -m "feat(config): add API_RATE_LIMIT"
```

`encrypt` is **idempotent**: if neither the content nor the recipient set changed, it
prints `unchanged` and rewrites nothing (age is randomized, so re-encrypting blindly would
churn diffs and cause needless merge conflicts — EnvGuardian deliberately avoids that).

---

## 4. Global flags

These persistent flags work on (almost) every command:

| Flag | Meaning |
|---|---|
| `--identity <path>` | Path to the age/SSH identity to decrypt/sign with. Defaults to your usual SSH key; `ENVGUARDIAN_IDENTITY` env var is also honored. |
| `--config <path>` | Path to the EnvGuardian config file (for non-standard layouts). |
| `--json` | Machine-readable JSON output. **Only valid** on `check`, `list-recipients`, `rotation status`, and `rotation done` — it errors elsewhere. |
| `-v`, `--verbose` | Report progress on stderr. Never prints secret values. |

> There is **no `-i` shorthand** for `--identity`. `-v` is the only short flag.

Commands auto-discover the repository root, so they work from any subdirectory.

---

## 5. Managing recipients

### Add a recipient

`add-recipient` re-encrypts to the new set **transactionally** — recipients, ciphertext,
signature, and lock all succeed together or the whole thing rolls back. Provide the key
via **exactly one** of these sources:

```bash
# From a GitHub username (fetches ssh-ed25519 keys from github.com/<user>.keys)
envguardian add-recipient --github alice

# From a public key string (age1... OR ssh-ed25519 ...) — --name required
envguardian add-recipient --name bob --key "ssh-ed25519 AAAAC3Nza..."
envguardian add-recipient --name carol --key "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"

# From an SSH public-key file — --name required
envguardian add-recipient --name dave --ssh ~/keys/dave.pub
```

| Flag | Purpose |
|---|---|
| `--github <user>` | Fetch the recipient's key from GitHub. Uses the username as the default name. |
| `--key <string>` | An `age1…` or `ssh-ed25519 …` public key string. |
| `--ssh <path>` | Path to an SSH public-key **file**. |
| `--name <name>` | Recipient name. Required for `--key`/`--ssh`; defaults to the GitHub username. |

> **Current limitation:** `--github` requires the user to have **exactly one**
> `ssh-ed25519` key on GitHub. If they have several, pick one and pass it via `--key`.
> Multi-key recipients are planned.

Adding a recipient needs an identity so EnvGuardian can decrypt the existing ciphertext
in memory and re-seal it — it will **not** overwrite the ciphertext blindly from your
local `.env`.

### List recipients

```bash
envguardian list-recipients
envguardian list-recipients --json
```

Shows each recipient's name, source, and date added. It does **not** print raw keys in the
table view.

### Revoke a recipient & rotate

```bash
# 1. Remove access for future ciphertext (transactional re-encrypt)
envguardian revoke bob

# 2. See which secret key NAMES were exposed and now need rotating
envguardian rotation status
envguardian rotation status --json

# 3. After rotating each secret AT ITS SOURCE (Stripe, AWS, …), mark it done
envguardian rotation done STRIPE_SECRET_KEY
```

- `revoke` refuses to remove the **last** recipient (that would lock everyone out — add a
  replacement first).
- On revocation, every dotenv **key name** readable by the revoked recipient is added to
  `rotation.toml`. Only *names* are recorded — never values.

> ### 🔑 Revocation is not retroactive
> Re-encrypting removes access from **new** ciphertext only. Anyone with the old key and a
> copy of git history can still decrypt **past** commits. The exposed credentials are
> only truly safe once you **rotate them at the provider** and then run `rotation done`.

---

## 6. Verification & integrity

EnvGuardian **fails closed**: if a check can't actually run (no identity, unreadable
ledger, git error), that's a *failure*, not a skipped "pass".

### `check` — repository integrity (for CI)

```bash
# Full check — needs an identity, actually decrypts to prove ciphertext validity
envguardian check
envguardian check --json

# Structural only — for fork PRs / CI without access to secrets
envguardian check --structural-only
```

`check` verifies: config version & safe paths, well-formed recipients, lock digest &
fingerprint match, a valid signature per ciphertext, `.env` is gitignored, ciphertext
decrypts to valid dotenv, and the rotation ledger is readable. `--structural-only` skips
only the decryption step and says so explicitly.

### `check-local` — developer synchronization

```bash
envguardian check-local
envguardian check-local --allow-missing   # tolerate an absent local plaintext
```

Compares your **working** `.env` against the committed ciphertext, semantically (by
key/value), and reports which key names are added/removed/changed.

> **Why two commands?** CI cannot prove that an *uncommitted* local `.env` is current.
> `check` verifies what's in the repository; `check-local` verifies your working copy.
> They are deliberately separate jobs.

---

## 7. Git integration

### Hooks

```bash
envguardian install-hooks
envguardian install-hooks --uninstall
```

Installs three hooks (in managed, clearly-delimited blocks so they coexist with yours):

- **`pre-commit`** — validates the *staged snapshot* via git-index blobs: blocks
  accidentally staged plaintext, and verifies staged recipients/lock/ciphertext/signature
  agree. Any git subprocess error is treated as a failure.
- **`post-merge` / `post-checkout`** — after a pull/checkout, if managed inputs changed it
  **alerts** you (reporting only key and recipient *names*, plus signature status) and
  requires `envguardian decrypt --accept-changes`. It never auto-writes plaintext from an
  unreviewed branch.

### Secret-safe diff

```bash
# One-time: register the git diff driver (.gitattributes + git config)
envguardian diff --install

# Ad-hoc: show which keys changed between working .env and ciphertext
envguardian diff
```

Once installed, `git diff` on `.env.age` shows `+ KEY`, `- KEY`, `~ KEY` (added / removed /
changed) — **key names only, never values or any value derivative.**

### Semantic merge

```bash
# One-time: register the local merge drivers (.gitattributes + git config)
envguardian merge --install

# After a merge that touched ciphertext, finish it transactionally
envguardian merge --continue
```

When two branches diverge on `.env.age`, EnvGuardian performs a **3-way semantic merge of
the dotenv keys** in memory. A successful low-level merge **pauses on purpose** — this lets
`merge --continue` re-sign every resolved ciphertext and write one complete, consistent
lock only after all per-file decisions succeed. If the same key changed on both sides, it
**conflicts by key name** (no values shown); resolve it, then run `merge --continue`.

> Merge/diff drivers are registered **locally**, from your own binary path — EnvGuardian
> never executes a command string supplied by the repository.

---

## 8. Command reference

| Command | Purpose | Flags (beyond globals) |
|---|---|---|
| `envguardian init` | Scaffold config, seed recipients with your key, update `.gitignore`. | `--name`, `--file` (default `.env`) |
| `envguardian encrypt` | Encrypt every plaintext → ciphertext (idempotent). | `--force`, `--fix` |
| `envguardian decrypt` | Decrypt every ciphertext → plaintext (mode `0600`). | `--accept-changes` |
| `envguardian add-recipient` | Add a recipient and re-encrypt to the new set. | `--github`, `--key`, `--ssh`, `--name` |
| `envguardian revoke NAME` | Revoke a recipient; record exposed key names for rotation. | — |
| `envguardian list-recipients` | List who can decrypt. | `--json` |
| `envguardian rotation status` | List pending rotation key names. | `--json` |
| `envguardian rotation done KEY` | Mark one rotated key name complete. | `--json` |
| `envguardian check` | Verify committed repository integrity (CI). | `--structural-only`, `--json` |
| `envguardian check-local` | Verify local plaintext matches ciphertext. | `--allow-missing` |
| `envguardian install-hooks` | Install git hooks (auto-decrypt alert + block plaintext commits). | `--uninstall` |
| `envguardian diff` | Show changed key names; `--install` registers the git diff driver. | `--install` |
| `envguardian merge` | Install (`--install`) or finish (`--continue`) the ciphertext merge driver. | `--install`, `--continue` |
| `envguardian version` | Print version, commit, and build date. | — |

*Notable flags:* `encrypt --force` re-encrypts even when existing ciphertext can't be
verified (a loud "lost key" escape hatch — use sparingly). `encrypt --fix` appends any
un-ignored plaintext files to `.gitignore` instead of erroring.

---

## 9. Exit codes

For scripting and CI:

| Code | Meaning |
|:---:|---|
| `0` | Success / everything synchronized. |
| `1` | Out of sync / divergent local state / merge conflict (or a generic failure). |
| `2` | Identity resolution or decryption failure. |
| `3` | Malformed config, TOML, or dotenv syntax; unsafe path; misused `--json`. |
| `4` | Ciphertext signature verification failure. |

Identity/decryption failures (2) and signature failures (4) take precedence over generic
ones, so a non-zero exit tells you *what kind* of thing went wrong.

---

## 10. Troubleshooting

| Symptom | Likely cause & fix |
|---|---|
| `--json is not supported by "…"` (exit 3) | `--json` only works on `check`, `list-recipients`, `rotation status`, `rotation done`. |
| `decrypt` / `check` fails with exit **2** | No usable identity, or you're not a recipient. Pass `--identity <path>`, or ask to be added. |
| Post-merge/checkout says managed inputs changed | Review the change, then `envguardian decrypt --accept-changes`. |
| `encrypt` refuses: plaintext not gitignored | Add the file to `.gitignore`, or run `envguardian encrypt --fix`. |
| Exit **4** on decrypt/check | The `.age.sig` is missing or wasn't signed by a *current* recipient. Re-seal with `encrypt`, or investigate provenance. |
| `refusing to revoke the last recipient` | Add a replacement recipient before revoking. |
| `--github` fails: user has N keys | GitHub import currently needs exactly one `ssh-ed25519` key; use `--key`/`--ssh` instead. |
| Merge "intentionally paused" (exit 1) | Expected. Run `envguardian merge --continue` to finalize, sign, and stage. |

---

## 11. What EnvGuardian is *not*

By design, to stay finishable and trustworthy:

- ❌ A runtime secrets manager (that's Vault).
- ❌ Production secret injection (that's your cloud provider).
- ❌ Any server or hosted component.
- ❌ Storage for large or binary secrets.
- ❌ Compliance or audit tooling.

---

*Authoritative status lives in [`docs/PLAN.md`](PLAN.md); security details in
[`SECURITY.md`](../SECURITY.md) and [`docs/threat-model.md`](threat-model.md).*
