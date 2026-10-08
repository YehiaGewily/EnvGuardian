# Security Policy

## Supported versions

EnvGuardian currently has **no supported release**. The `v0.1.0` tag is an
unreleased development snapshot and must not be used for real secrets.

| Version | Supported |
|---|---|
| `v0.2.1` release candidate | No — pending Stage G verification |
| `v0.2.0` release candidate | No — pending Stage G verification |
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
protect and users need an unambiguous warning. The tracked remediation is in
[docs/PLAN.md](docs/PLAN.md).

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
trusted commit. Development code after Stage D separately verifies a detached
OpenSSH signature over the ciphertext and mapping against current SSH
recipients. The v0.1.x migration warning is retired in v0.2: missing signatures
fail closed. See [docs/threat-model.md](docs/threat-model.md).

Removing a recipient only prevents access to future ciphertext. It cannot
remove access to historical ciphertext in git; affected credentials must be
rotated at their source.

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
