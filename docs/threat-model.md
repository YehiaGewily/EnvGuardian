# Threat model

EnvGuardian is a key-management and git-integration layer over age. It does not
implement cryptography and it is not a runtime secrets manager.

This document describes the unreleased `v0.2.0` candidate boundary. There is
currently no supported release.

## Assets and trust anchors

The protected asset is the plaintext dotenv content. A developer's age or SSH
identity is local and trusted. Repository contents, pull-request authors,
branches, working-tree files, and ciphertext authors are untrusted until the
developer reviews and accepts the relevant commit.

The repository host's protected-branch settings, signed-commit enforcement,
review policy, and CI are required operational controls. EnvGuardian's detached
SSH signature—not age decryption—turns a ciphertext artifact into an
authenticated statement by a current recipient.

## What age establishes

age establishes confidentiality for the configured recipients. Someone with
only repository read access should not learn plaintext without a matching
identity.

Successful age decryption does **not** establish who created the ciphertext. A
fork contributor can read `recipients.toml`, encrypt a malicious dotenv payload
to every listed public key, and produce ciphertext that decrypts successfully
for the whole team.

## Managed-path boundary

All configured plaintext and ciphertext paths are resolved once when config is
loaded. Resolution:

- rejects empty paths and Unix or Windows absolute forms,
- treats both slash styles as separators on every platform,
- rejects lexical traversal outside the repository,
- evaluates symlinks at the deepest existing parent and rechecks containment,
- rejects `.git/` and aliases between managed sources and destinations,
- rejects duplicate plaintext or ciphertext destinations.

Decrypted bytes must parse completely as dotenv before a mode-`0600` atomic
plaintext write. There is no bypass flag.

On Windows, mode-`0600` writes are created with a protected DACL whose only
entry allows the current process user, applied at creation and confirmed before
any content is written; otherwise the write fails. This does not protect
plaintext from Administrators, SYSTEM, or backup software (the equivalent of
root on Unix), and files written by older versions keep their inherited ACL
until rewritten.

## Automatic-decryption boundary

Automatic post-checkout and post-merge behavior stores the resolved commit of
the last explicit acceptance or successful auto-decrypt in the local,
gitignored `.envguardian/auto-decrypt-state.toml` file.

For a new commit, the hook first compares the committed config bytes with that
accepted commit. It does not parse an incoming changed config. If config is
unchanged, the accepted mapping is used to compare committed recipients and
ciphertext blobs. The hook decrypts committed blobs, not an uncommitted
working-tree substitute.

If config, recipients, ciphertext, or detached signature changed, the hook writes no plaintext. It
reports configuration changes, recipient names, and dotenv key names only; it
never prints values or value-derived metadata. It also reports whether the
incoming commit is unsigned, signed by a recognized SSH recipient, signed by a
non-recipient, or cannot be verified locally. The developer must review the
commit and run:

```bash
envguardian decrypt --accept-changes
```

That command validates and decrypts the exact `HEAD` snapshot, writes plaintext,
and updates local trust state only after successful writes.

### Manual decryption inside a repository

Plain `envguardian decrypt` inside a Git work tree passes through the same
comparison as the hook (one shared function), so it is not a way around a
blocked hook. In `v0.2.0` and `v0.2.1` it read and decrypted the working tree
without consulting trust state, which let a branch that added its author to
`recipients.toml` and re-sealed the ciphertext overwrite local plaintext that
the hook had just refused to write. Now:

- If config, recipients, any ciphertext, or any detached signature at `HEAD`
  differs from the accepted commit, it writes nothing and reports key and
  recipient names with exit code 1.
- With no recorded accepted commit (a fresh clone), it refuses. The first trust
  decision is always the explicit `decrypt --accept-changes`.
- It writes plaintext only from committed `HEAD` blobs. If a managed file in
  the working tree differs from `HEAD`, it refuses, with one exception: an
  uncommitted ciphertext or signature whose signature verifies against `HEAD`'s
  recipients and whose plaintext is byte-identical to the current local file is
  left untouched. That exception writes nothing, so it cannot install
  uncommitted content; it only keeps a developer's own `encrypt` followed by
  `decrypt` from failing. Uncommitted config or recipients changes always
  refuse.
- It never updates trust state.
- Outside a Git repository it decrypts the files on disk, because there is no
  branch to receive. If a `.git` entry or `GIT_DIR` indicates a repository that
  Git cannot open, it fails closed instead of treating the directory as
  outside a repository.

Commit-signature diagnostics remain supporting context, not ciphertext
authentication. The detached `.sig` artifact is verified independently against
the current recipients file before any automatic plaintext write.

## Ciphertext authenticity

Detached signatures bind ciphertext provenance to a current SSH recipient using OpenSSH
detached signatures. The signed, domain-separated payload covers the exact
ciphertext SHA-256, public recipient fingerprint, repository-relative config
path, plaintext mapping, and ciphertext mapping. This prevents copying a valid
signature to different ciphertext bytes, a different recipient set, or another
mapping.

`check`, manual decryption, pre-commit, post-checkout/post-merge decryption, and
`decrypt --accept-changes` verify present signatures against current SSH
recipient keys. A bad, re-pointed, or former-recipient signature fails with the
dedicated authenticity exit code before plaintext is written.

The v0.1.x migration permitted an explicit warning for missing signatures. v0.2
fails closed when a detached signature is missing.
The explicit acceptance transition remains required when managed commit inputs
change; a valid artifact signature identifies a current recipient as sealer but
does not prove that a branch was reviewed or approved.

## What `check` proves, and what it does not

`check` verifies one snapshot against itself. It reads config, recipients,
lock, ciphertext, and detached signatures from the same checkout, and proves
that:

- config and managed paths are safe and recipients are well formed;
- the lock matches each ciphertext's exact bytes and that snapshot's recipient
  fingerprint;
- each signature verifies, over that ciphertext and mapping, against an SSH key
  listed in that snapshot's `recipients.toml`;
- with an identity, each ciphertext decrypts to valid dotenv.

It does not prove that the recipients file is one the team approved, that the
signing key belonged to a recipient before the change, who authored the
change, or that the values are benign. "Current recipient" means a key listed
in the file being checked, which the change under test may itself have edited.

A contributor who is not a recipient can add their own key to
`recipients.toml` on a branch (or replace an existing recipient's key under the
same name), write their own values, run `envguardian encrypt --force`, and get
a signature that verifies against that branch's recipients. `check` passes on
that branch. A green `check` on a pull request that changes `recipients.toml`
therefore proves nothing about who authored the new ciphertext. Neither
`check` nor successful decryption authenticates the sender.

The boundary is human review of `.envguardian/recipients.toml`, which
`.github/CODEOWNERS` assigns to code owners. It holds only where the host
requires code-owner approval before merge, so enable that in your branch
protection. Reviewers should reject a pull
request that changes recipients and ciphertext (`*.age`, `*.age.sig`, or the
lock) together unless both the recipient change and the content change are
confirmed out of band: with the person who is supposed to have made them, over
a channel other than the pull request, comparing any added key with one they
supply directly. The signer name that `check` or a hook reports comes from the
changed file, so it is not that confirmation. `add-recipient` legitimately
produces this shape and needs the same confirmation. If such a commit lands
anyway, the accepted-commit gate still stops the hooks and plain `decrypt`
from installing it on a developer's machine until that developer runs
`decrypt --accept-changes`.

`check --base REF` closes the self-added-recipient gap for continuous
integration. It reads `REF`'s recipients from Git and requires every
ciphertext that differs from `REF` to carry a signature that verifies against
a key `REF` already listed, so neither a self-added recipient nor a key swapped
under an existing name can seal a change. It reports recipient changes by name
and fails when `REF` cannot be resolved or read. It trusts `REF` itself, so the
base must be the protected target branch, and it does not judge whether a
legitimate recipient's change, including adding a teammate, was authorized;
that remains code-owner review.

## Does not protect against

- A current recipient reading the plaintext.
- A former recipient decrypting historical ciphertext they were authorized to
  read. Credentials must be rotated at their upstream source.
- A compromised developer machine or stolen identity.
- A developer explicitly accepting a malicious commit without reviewing it.
- A malicious or compromised upstream service receiving credentials after the
  application runs.
- Production secret injection, runtime access control, or audit requirements.
