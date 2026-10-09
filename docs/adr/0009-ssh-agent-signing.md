# ADR 0009: Sign through ssh-agent with a public signing key

- Status: Accepted
- Date: 2026-10-09

## Context

ADR 0008 signs every ciphertext with `ssh-keygen -Y sign`, using the SSH
private-key file that was also resolved as the decryption identity. Many
developers keep SSH keys only in an agent: 1Password, Secretive, a hardware
token, or `ssh-agent` with a key that never touches disk unencrypted. Those
users could decrypt with a separate age identity but could not seal, because
sealing required a private-key file.

age cannot decrypt through an agent: SSH recipients need the private key to
derive the X25519 file key. Decryption and signing therefore need separate
keys for these users.

## Decision

Add a signing-key selection, `--signing-key PATH` or
`$ENVGUARDIAN_SIGNING_KEY`, naming an SSH **public** key file. When it is set,
EnvGuardian passes that file to `ssh-keygen -Y sign -f`, which signs with the
matching private key held by the running agent. Without it, sealing signs with
the SSH private-key file resolved as the identity, as before; `ssh-keygen`
also uses the agent for that key when the agent holds it.

The signing public key must be listed for a current recipient. A recipient can
list both an age key (for decryption) and an SSH key (for signing) with
`keys = [...]`. Verification is unchanged: a signature is accepted only when it
verifies for an SSH key of a current recipient.

All signature cryptography stays in OpenSSH. EnvGuardian only parses the public
key line to check recipient membership and never sees private key material on
this path.

## Consequences

Agent-held keys, including hardware-backed keys, can seal. An agent that is not
running, does not hold the key, or refuses the request makes `ssh-keygen` fail,
and sealing fails before any file is written. An invalid or non-recipient
`--signing-key` fails immediately, even when no signature needs replacing,
because the user selected it explicitly.

## Alternatives

Talking to the agent protocol directly through `golang.org/x/crypto/ssh/agent`
would put signature formatting (the SSHSIG envelope) in EnvGuardian and violate
the no-primitives rule. Requiring hardware users to export a private key file
defeats the hardware. Both are rejected.
