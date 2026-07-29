# ADR 0005: Treat every repository-controlled path as untrusted

- Status: Accepted
- Date: 2026-07-29

## Context

Config and Git branches are attacker-controlled inputs. A decrypted dotenv
written to a traversed path or `.git/hooks` becomes file overwrite or code
execution.

## Decision

Resolve managed paths once at config load. Reject empty, absolute,
drive-relative, traversal, symlink-escaping, `.git`, duplicate, and colliding
destinations. Recheck containment after resolving existing-parent symlinks.
Validate decrypted bytes as dotenv before any plaintext write.

## Consequences

Commands consume resolved paths rather than reinterpreting raw config. There is
no path-safety opt-out.
