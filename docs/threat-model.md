# Threat model

EnvGuardian is a key-management and git-integration layer over age. It does not
implement cryptography and it is not a runtime secrets manager.

This document describes the unreleased `v0.1.1` development boundary. There is
currently no supported release.

## Assets and trust anchors

The protected asset is the plaintext dotenv content. A developer's age or SSH
identity is local and trusted. Repository contents, pull-request authors,
branches, working-tree files, and ciphertext authors are untrusted until the
developer reviews and accepts the relevant commit.

The repository host's protected-branch settings, signed-commit enforcement,
review policy, and CI are required operational controls. They do not turn age
ciphertext into an authenticated statement.

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

## Automatic-decryption boundary before Stage D

Automatic post-checkout and post-merge behavior stores the resolved commit of
the last explicit acceptance or successful auto-decrypt in the local,
gitignored `.envguardian/auto-decrypt-state.toml` file.

For a new commit, the hook first compares the committed config bytes with that
accepted commit. It does not parse an incoming changed config. If config is
unchanged, the accepted mapping is used to compare committed recipients and
ciphertext blobs. The hook decrypts committed blobs, not an uncommitted
working-tree substitute.

If config, recipients, or ciphertext changed, the hook writes no plaintext. It
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

Commit-signature diagnostics are supporting context, not ciphertext
authentication. An accepted commit can still contain ciphertext produced by a
different party.

## Stage D

Stage D will bind ciphertext provenance to an authorized signer and verify that
binding before repository checks or automatic decryption. Once that mechanism
lands, the tool can authenticate the ciphertext artifact itself instead of
relying on an explicit local acceptance transition.

Until then, `--accept-changes` is a human review boundary. It is deliberately
required even when malicious ciphertext decrypts and parses successfully.

## Does not protect against

- A current recipient reading the plaintext.
- A former recipient decrypting historical ciphertext they were authorized to
  read. Credentials must be rotated at their upstream source.
- A compromised developer machine or stolen identity.
- A developer explicitly accepting a malicious commit without reviewing it.
- A malicious or compromised upstream service receiving credentials after the
  application runs.
- Production secret injection, runtime access control, or audit requirements.
