# EnvGuardian merge-driver decision table

Status: accepted for the v0.2 merge driver.

The driver decrypts base, ours, and theirs independently, parses them as dotenv,
and performs the table below per key. Values remain in memory. User-visible
conflicts contain key names only. Reordering and comments do not affect semantic
classification; when semantic content is equal, the driver keeps ours so its
formatting and comments remain stable.

| Base | Ours | Theirs | Classification | Result |
|---|---|---|---|---|
| absent | same value | same value | add/add, equal | keep ours |
| absent | value A | value B | add/add, divergent | conflict by key name |
| absent | absent | value | one-sided add | take theirs |
| absent | value | absent | one-sided add | keep ours |
| value | same as base | changed | one-sided modify | take theirs |
| value | changed | same as base | one-sided modify | keep ours |
| value | same change | same change | modify/modify, equal | keep ours |
| value | change A | change B | modify/modify, divergent | conflict by key name |
| value | absent | same as base | one-sided delete | delete |
| value | same as base | absent | one-sided delete | delete |
| value | absent | changed | delete/modify | conflict by key name |
| value | changed | absent | modify/delete | conflict by key name |
| value | absent | absent | delete/delete | delete |

The complete merge succeeds only when every key has a non-conflicting result.
On success, the resolved dotenv bytes are re-encrypted through the transactional
seal planner, signed through the ciphertext-authentication path, and committed
with the lock file last. On conflict, no managed file is written.

Git registration is local configuration created from the running EnvGuardian
binary. The repository may select the driver by name in `.gitattributes`, but it
never supplies an executable command string.
