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

Commit-signature diagnostics remain supporting context, not ciphertext
authentication. The detached `.sig` artifact is verified independently against
the current recipients file before any automatic plaintext write.

## Ciphertext authenticity

Stage D binds ciphertext provenance to a current SSH recipient using OpenSSH
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

## Does not protect against

- A current recipient reading the plaintext.
- A former recipient decrypting historical ciphertext they were authorized to
  read. Credentials must be rotated at their upstream source.
- A compromised developer machine or stolen identity.
- A developer explicitly accepting a malicious commit without reviewing it.
- A malicious or compromised upstream service receiving credentials after the
  application runs.
- Production secret injection, runtime access control, or audit requirements.
