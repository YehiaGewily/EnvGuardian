# Security Policy

## Supported versions

EnvGuardian currently has **no supported release**. The `v0.1.0` tag is an
unreleased development snapshot and must not be used for real secrets.

| Version | Supported |
|---|---|
| `v0.2.1` release candidate | No — pending release verification |
| `v0.2.0` release candidate | No — pending release verification |
| `main` | No — development only |
| `v0.1.0` | No — known unsafe development tag |

## Known advisory: repository path traversal

**Affected:** `v0.1.0`.

Repository-controlled plaintext paths are not fully confined to the repository
and do not exclude `.git/`. A malicious repository can therefore configure an
automatic decrypt operation to overwrite a file outside the worktree or inside
Git's control directory when a recipient runs an installed post-merge or
post-checkout hook.

The unreleased `v0.2.0` candidate resolves every managed path at config
load, evaluates existing-parent symlinks, rechecks containment, and rejects
`.git/`. It also validates decrypted dotenv bytes before any plaintext write.

Until a fixed version is released:

- do not use EnvGuardian with real credentials,
- do not install hooks from `v0.1.0`,
- do not run commands from the `v0.1.0` binary in an untrusted repository.

This advisory is intentionally public because there is no supported release to
protect and users need an unambiguous warning.

## Known advisory: plain `decrypt` skipped the accepted-commit check

**Affected:** `v0.2.0` and `v0.2.1` release candidates. Fixed on `main`, not yet
released.

The post-checkout and post-merge hooks refuse to write plaintext when a
commit's config, recipients, ciphertext, or signature differs from the locally
accepted commit, and tell the user that `decrypt --accept-changes` is the
confirmation step. Plain `envguardian decrypt` did not apply that check: it
verified the working-tree signature against the working-tree recipients file
and decrypted. A branch author who is not a recipient could add their own key
to `recipients.toml`, run `encrypt --force`, and produce a signature that
verifies against that branch's recipients. After the hook refused the branch,
running plain `decrypt` overwrote the local `.env` with the branch author's
values without any confirmation.

On `main`, plain `decrypt` inside a Git repository applies the hook's
comparison and refuses before any plaintext write, decrypts only committed
`HEAD` blobs, and refuses in a clone with no accepted commit. Until a fixed
version is released, with `v0.2.0` or `v0.2.1` use only
`decrypt --accept-changes`, and only after reviewing the commit.

## Security boundary

### Windows plaintext permissions

Owner-only writes (mode `0600`: decrypted plaintext, local auto-decrypt state,
and temporary signing files) are created on Windows with a protected DACL that
has a single allow entry for the current process user and no inherited entries.
The DACL is applied when the temporary file is created, before any content is
written, and is read back from the open handle; if it cannot be resolved,
applied, or confirmed (for example on a FAT/exFAT volume that does not store
ACLs), the write fails and leaves no temporary file. Same-volume rename keeps
that DACL, including when replacing an existing file.

Limits: Administrators, SYSTEM, and backup software can still read the files,
as root can on Unix. Accounts that can modify the containing directory can
still delete or replace files in it. Plaintext written by earlier versions
keeps its inherited ACL until EnvGuardian rewrites it; run
`envguardian decrypt` to rewrite it, or fix it with `icacls`. The same applies
after any other tool replaces the file: editors that save by writing a new file
and renaming it over `.env`, copying a file over it, or restoring it from a
backup all produce a file with the directory's inherited ACL.

age encrypts to recipients, but it does not authenticate the sender. Successful
decryption proves neither who created a ciphertext nor that it came from a
trusted commit. EnvGuardian separately verifies a detached
OpenSSH signature over the ciphertext and mapping against current SSH
recipients. The v0.1.x migration warning is retired in v0.2: missing signatures
fail closed. See [docs/threat-model.md](docs/threat-model.md).

Removing a recipient only prevents access to future ciphertext. It cannot
remove access to historical ciphertext in git; affected credentials must be
rotated at their source.

### CI `check` cannot detect a self-added recipient

`check` verifies a snapshot against that same snapshot's `recipients.toml`. A
pull request whose author is not a recipient can add their own key to
`recipients.toml`, run `encrypt --force`, and produce a signature that verifies
against the recipients in their branch, so `check` passes. `check` proves the
snapshot is internally consistent and, with an identity, decryptable; it does
not prove who authored the ciphertext or that the recipient change was
authorized, and a green `check` on a pull request that changes
`recipients.toml` proves nothing about who authored the new ciphertext. The
security boundary is code-owner review of `.envguardian/recipients.toml`.
Reviewers should reject pull requests that change recipients and ciphertext
together unless both changes are confirmed out of band.

`check --base REF` (unreleased, on `main`) requires every ciphertext changed
since `REF` to be signed by a recipient already trusted at `REF`. Run it in CI
with the pull request's base commit to fail this pattern automatically. See
[docs/threat-model.md](docs/threat-model.md).

### Accepted-commit trust state

Inside a Git repository, neither the hooks nor plain `decrypt` write plaintext
unless `HEAD`'s config, recipients, ciphertext, and detached signatures are
byte-identical to the commit last accepted in the local, gitignored
`.envguardian/auto-decrypt-state.toml`. A fresh clone has no accepted commit,
so its first decryption must be `decrypt --accept-changes`. Plaintext is
written only from committed `HEAD` blobs, never from uncommitted working-tree
ciphertext. Outside a Git repository, `decrypt` reads the files on disk; if a
`.git` entry or `GIT_DIR` points at a repository Git cannot open, it fails
closed. Accepting a commit is a human review decision; see
[docs/threat-model.md](docs/threat-model.md).

## Reporting a vulnerability

**Do not report security vulnerabilities through public GitHub issues.**

Email **yehyaheya@gmail.com** with:

- a description of the issue and impact,
- reproduction steps or a proof of concept,
- affected versions and platforms.

You can expect acknowledgement within 72 hours and a status update within seven
days. Disclosure timing and credit will be coordinated with the reporter. To
use encrypted email, request the public key in an initial message.

## Scope

In scope:

- recovery of plaintext by someone with only repository read access,
- a plaintext-derived artifact that enables offline guessing,
- escaping the repository or writing inside `.git/`,
- bypassing plaintext guards or repository-integrity checks,
- identity-resolution or decryption flaws that expose key material,
- treating unauthenticated ciphertext as trusted provenance.

Outside the tool's security boundary:

- access by a current recipient,
- historical access by a former recipient,
- compromise of a developer machine holding an identity and plaintext.
