# EnvGuardian — User Guide (v0.2)

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
> EnvGuardian is **pre-release**. `v0.2.0` and `v0.2.1` are release candidates, not yet supported;
> `v0.1.0` was a development tag with known critical findings — **do not install hooks or
> binaries from `v0.1.0`.**
>
> - **Do not use it for real production secrets yet.** Use throwaway/dev values until the
>   release is finalized and every install path is publicly verified.
> - **Windows file permissions.** Plaintext is written with mode `0600` on Unix and with a
>   protected owner-only DACL (current user only, nothing inherited) on Windows. The write
>   fails rather than falling back to inherited permissions. Administrators, SYSTEM, and
>   backup tools can still read it, and a `.env` written by an older version keeps its old
>   ACL until EnvGuardian rewrites it. Editing `.env` with a tool that replaces the file
>   (for example an editor's "safe write") also resets its ACL; re-run `envguardian decrypt`
>   or use `icacls` to restore owner-only access.
> - This guide describes the **implemented** behavior of the `v0.2` line. If the README and this
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
| `.envguardian/auto-decrypt-state.toml` | 🚫 **Gitignored (local)** | Records the last commit you accepted; the hooks and plain `decrypt` install nothing else. Local trust state. |

`init` adds `.env` and `auto-decrypt-state.toml` to `.gitignore` for you, and adds
`*.age -text` and `*.age.sig -text` to `.gitattributes` so Git never converts the line
endings of ciphertext or signatures (both are verified byte-for-byte). Commit
`.gitattributes`. Repositories initialized with v0.2.0 or v0.2.1 should add those two lines
by hand; without them, Windows teammates with `core.autocrlf=true` get a lock digest and
signature mismatch after cloning.

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

# 5. Record that commit as your accepted state
envguardian decrypt --accept-changes
```

`init` seeds `recipients.toml` with the public key derived from your identity (default
`~/.ssh/id_ed25519`, or `--identity <path>`), so you are a recipient from the start. Inside
a Git repository, `decrypt` installs only a commit you have accepted, which is why step 5
exists.

### B. Teammate workflow (clone / pull)

The first decryption in a fresh clone is an explicit trust decision: no accepted commit is
recorded yet, so plain `decrypt` refuses. Review the recipients and config you are about to
trust, then accept:

```bash
# Who can decrypt? (also read .envguardian/config.toml)
envguardian list-recipients
# Record HEAD as accepted and decrypt every ciphertext → local plaintext (mode 0600)
envguardian decrypt --accept-changes
# Optional: re-decrypt automatically on checkout/pull when nothing managed changed
envguardian install-hooks
```

After that, plain `envguardian decrypt` restores the accepted snapshot, for example after
you delete `.env`. If upstream changed `config.toml`, `recipients.toml`, any ciphertext, or
any signature, neither the hooks nor plain `decrypt` will rewrite your local `.env`; both
list the changed key and recipient names and exit 1. After **reviewing** the incoming
change, accept it explicitly:

```bash
envguardian decrypt --accept-changes
```

See [`decrypt` and the accepted commit](#decrypt-and-the-accepted-commit) for every case.

### C. Changing a secret

```bash
# 1. Edit your local .env
# 2. Re-encrypt (idempotent — no-op if nothing changed)
envguardian encrypt
# 3. Commit the encrypted artifacts
git add .env.age .env.age.sig .envguardian/lock.toml
git commit -m "feat(config): add API_RATE_LIMIT"
# 4. Record your own commit as accepted
envguardian decrypt --accept-changes
```

Your own commit changes the ciphertext relative to your accepted commit, so until step 4 the
hooks and plain `decrypt` treat it like any other change. Between steps 2 and 3, plain
`decrypt` exits 0 without touching `.env`, because the uncommitted ciphertext decrypts to
exactly what `.env` already holds.

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

### Reviewing recipient changes

`recipients.toml` decides who can read every secret, and EnvGuardian cannot tell an
authorized change to it from an unauthorized one. **Human review of this file is the
security boundary**; `.github/CODEOWNERS` routes it to code owners, which only enforces
anything if your host requires code-owner approval before merge.

Do not treat a green CI `check` as evidence about a recipient change:

- **What `check` proves:** the snapshot is internally consistent — safe config and paths,
  well-formed recipients, a lock that matches the ciphertext bytes, a signature that
  verifies against a key listed in *that snapshot's* `recipients.toml`, and (with an
  identity) ciphertext that decrypts to valid dotenv.
- **What it does not prove:** that the recipient change was authorized, that the signer
  was a recipient before the change, who authored the ciphertext, or that the values are
  benign.

Someone who is not a recipient can add their own key to `recipients.toml` (or swap the key
under an existing name), write their own values, and run `encrypt --force`. The new
signature verifies against the recipients in their branch, so `check` passes. **A green
`check` on a pull request that changes `recipients.toml` proves nothing about who authored
the new ciphertext.**

When reviewing:

- **Reject a pull request that changes `recipients.toml` and ciphertext (`*.age`,
  `*.age.sig`, `lock.toml`) together** unless both changes are confirmed out of band — with
  the person who is supposed to have made them, over a channel other than the pull request,
  comparing any added key with one they give you directly. A legitimate `add-recipient`
  produces exactly this shape, so it needs the same confirmation.
- The signer name in `check` output or a hook alert comes from the changed file; it is not
  that confirmation.
- If such a change merges anyway, your hooks and plain `decrypt` still refuse to install it
  until you run `decrypt --accept-changes` — so do not run that without the confirmation
  above.

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

On its own, `check` verifies a snapshot against that snapshot's `recipients.toml`, so it
cannot detect a pull request that adds its author as a recipient and re-seals the
ciphertext. On pull requests, also pass the target branch's commit with `--base`:

```bash
envguardian check --structural-only --base "$BASE_SHA"
```

With `--base`, every ciphertext that changed since the base must carry a signature from a
recipient who was already trusted at the base, and any recipient change is reported by
name as a warning. A self-added recipient, or a recipient whose key was swapped on the
branch, fails with exit `4`. If the base cannot be resolved or read, or has no
EnvGuardian configuration yet (the first adoption pull request), the check fails rather
than skipping the comparison. In GitHub Actions:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0   # the base commit must be present
- run: envguardian check --structural-only --base "${{ github.event.pull_request.base.sha }}"
```

`--base` proves who sealed a change, not that a legitimate recipient's change is
benign, and a recipient can still add a teammate with `add-recipient`. Keep code-owner
review of `recipients.toml`; see [Reviewing recipient changes](#reviewing-recipient-changes).

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

### `decrypt` and the accepted commit

Inside a Git repository, `decrypt` never installs content you have not accepted. Your
accepted commit lives in the gitignored `.envguardian/auto-decrypt-state.toml`; only
`decrypt --accept-changes` and a hook run that found nothing changed update it. Plain
`decrypt` uses the same comparison as the post-checkout/post-merge hook and never updates
it.

| Situation | `decrypt` | `decrypt --accept-changes` |
|---|---|---|
| `HEAD`'s config, recipients, ciphertext, and signatures are byte-identical to the accepted commit | Verifies signatures and writes plaintext from `HEAD`'s committed files. | Same, then records `HEAD`. |
| Any of them differs (after a pull, checkout, merge, or your own commit) | Writes nothing; lists changed key and recipient names; exit `1`. | Verifies and writes `HEAD`'s plaintext, then records `HEAD`. |
| No accepted commit is recorded (fresh clone), or it is no longer in the repository | Writes nothing; exit `1`. | As above. |
| Uncommitted change to a ciphertext or signature (for example after `encrypt`) | Exit `0` without touching that plaintext only if the uncommitted ciphertext verifies against `HEAD`'s recipients and decrypts to exactly the file's current bytes; otherwise writes nothing, exit `1`. | Reads only `HEAD` and overwrites plaintext with it. Commit your changes first. |
| Uncommitted change to `config.toml` or `recipients.toml` | Writes nothing; exit `1`. | Reads only `HEAD`; uncommitted files are ignored. |
| Not a Git repository | Decrypts the files on disk after verifying their signatures. | Fails: it needs a committed snapshot. |
| A `.git` entry exists (or `GIT_DIR` is set) but Git cannot open the repository | Writes nothing; exit `1`. | Fails. |

`decrypt` writes plaintext only from committed blobs at `HEAD`. It reads an uncommitted
ciphertext only to compare it with your current plaintext, so an uncommitted file — for
example one copied in with `git checkout other-branch -- .env.age` — can never supply
plaintext. Refusals report key and recipient names only, never values.

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
  unreviewed branch, and plain `envguardian decrypt` applies the same check, so it is not a
  way around the alert. Git ignores a post-merge hook's exit status, so a blocked pull still
  completes; read the alert.

Hooks record the absolute path of the binary that installed them. If that binary later
moves (an upgrade, a reinstall elsewhere), the hooks fall back to `envguardian` on your
`PATH` and print a hint to rerun `envguardian install-hooks`. If no binary can be found,
`pre-commit` blocks the commit rather than skipping its checks.

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
>
> `install-hooks`, `diff --install`, and `merge --install` refuse to run from
> `go run`, whose temporary binary is deleted when the command exits. Install the binary
> first (`go install`, Homebrew, or a release archive). If you move or upgrade the binary,
> rerun `diff --install` and `merge --install` to update the recorded path.

---

## 8. Command reference

| Command | Purpose | Flags (beyond globals) |
|---|---|---|
| `envguardian init` | Scaffold config, seed recipients with your key, update `.gitignore` and `.gitattributes`. | `--name`, `--file` (default `.env`) |
| `envguardian encrypt` | Encrypt every plaintext → ciphertext (idempotent). | `--force`, `--fix` |
| `envguardian decrypt` | Decrypt every ciphertext → plaintext (mode `0600`). In a Git repository, only the accepted commit; `--accept-changes` reviews-and-accepts `HEAD`. | `--accept-changes` |
| `envguardian add-recipient` | Add a recipient and re-encrypt to the new set. | `--github`, `--key`, `--ssh`, `--name` |
| `envguardian revoke NAME` | Revoke a recipient; record exposed key names for rotation. | — |
| `envguardian list-recipients` | List who can decrypt. | `--json` |
| `envguardian rotation status` | List pending rotation key names. | `--json` |
| `envguardian rotation done KEY` | Mark one rotated key name complete. | `--json` |
| `envguardian check` | Verify committed repository integrity (CI). | `--structural-only`, `--base REF`, `--json` |
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
| `decryption blocked for commit …` (exit 1) | `HEAD`'s managed files differ from your accepted commit, or none is recorded (fresh clone). Review the listed key and recipient names and the commits that changed them (`git log -p -- .envguardian/`), then `envguardian decrypt --accept-changes`. |
| `decryption blocked: managed files differ from commit …` (exit 1) | Uncommitted changes to managed files. If you made them, commit and run `decrypt --accept-changes`; otherwise review them and restore with `git restore --source=HEAD --staged --worktree -- <path>`. |
| `… indicates a Git repository, but Git could not open it` (exit 1) | A `.git` entry or `GIT_DIR` exists but Git failed (broken `gitdir:`, `safe.directory`, Git not on `PATH`). `decrypt` fails closed; fix Git and retry. |
| `encrypt` refuses: plaintext not gitignored | Add the file to `.gitignore`, or run `envguardian encrypt --fix`. |
| Exit **4** on decrypt/check | The `.age.sig` is missing or wasn't signed by a *current* recipient. Re-seal with `encrypt`, or investigate provenance. |
| `refusing to revoke the last recipient` | Add a replacement recipient before revoking. |
| `--github` fails: user has N keys | GitHub import currently needs exactly one `ssh-ed25519` key; use `--key`/`--ssh` instead. |
| Merge "intentionally paused" (exit 1) | Expected. Run `envguardian merge --continue` to finalize, sign, and stage. |
| `another envguardian command is running in this repository` (exit 1) | Commands that write files take an exclusive lock (`.git/envguardian.lock`) so they cannot interleave, for example an IDE checkout firing the post-checkout hook while you run `encrypt`. Wait for the other command and retry. The operating system releases the lock when a process exits, so a crash never leaves a stale lock; the empty lock file can stay. |

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
