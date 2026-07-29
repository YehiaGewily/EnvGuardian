# `.env` behavior and godotenv differential conformance

There is no `.env` standard. Four commonly used implementations disagree on
quoting, interpolation, comments, and whitespace in ways that silently change
secret values. This document records those disagreements with concrete
inputs/outputs and states the behaviour EnvGuardian adopts for each, with the
reasoning.

> **Conformance boundary.** EnvGuardian makes an automated compatibility claim
> only against pinned **godotenv v1.5.1**. CI runs that differential suite
> explicitly with the `differential` build tag. The python-dotenv, Node dotenv,
> and Docker columns below are non-authoritative background notes from manual
> investigation—not tested compatibility claims and not release evidence.

**Legend for output cells:** `↵` = a real newline inside the value ·
`␣` = a significant space · `(empty)` = set to `""` · `(unset)` = not defined ·
`(error)` = parse/load fails · `(host env)` = value pulled from the process
environment. Surrounding quotes shown in an output cell are **literal
characters that ended up in the value**.

---

## 0. The one-paragraph summary

Only **godotenv** and **python-dotenv** behave like a POSIX-ish shell:
double quotes expand escapes and `${VAR}`, single quotes are literal.
**Node's `dotenv`** does *no* `${VAR}` interpolation on its own (that's the
separate `dotenv-expand` package), expands only `\n`/`\r` in double quotes, and
cuts inline comments at the **first** `#` even without a leading space —
truncating values like `http://h/#frag`. **Docker `--env-file`** is not a
dotenv parser at all: no quote handling, no escapes, no interpolation, no
multiline, no inline comments; quotes and `${VAR}` are literal, and a **bare
name with no `=`** imports the value from the host environment.

EnvGuardian follows the godotenv/python-dotenv POSIX-ish semantics for the
value grammar, but is **stricter** on ambiguity (duplicate keys, bare keys, and
undefined interpolation are errors, not silent coercions) because it guards a
*committed* secrets file where a silently-wrong value is worse than a loud
failure. It is also the only one of the five that is a **round-tripping**
parser — it preserves comments, blank lines, key order, quote style, and line
endings — which the idempotency rule in
[CONTRIBUTING.md](../CONTRIBUTING.md) requires.

---

## 1. Feature support matrix

| Capability | godotenv | python-dotenv | Node dotenv | Docker `--env-file` | **EnvGuardian** |
|---|:--:|:--:|:--:|:--:|:--:|
| Strips `export ` prefix | ✅ | ✅ | ✅ *(v16+)* | ❌ | ✅ (preserved on write) |
| Double-quote escape expansion | full | full | `\n`/`\r` only | ❌ | full |
| Single quotes literal | ✅ | ✅ | ✅ | n/a (quotes literal) | ✅ |
| `${VAR}` interpolation | ✅ | ✅ | ❌ *(needs dotenv-expand)* | ❌ | ✅ |
| Interpolation inside single quotes | ❌ | ❌ | ❌ | ❌ | ❌ |
| Multiline quoted values | ✅ | ✅ | ✅ *(v15+)* | ❌ | ✅ |
| Inline comments | needs space | needs space | any `#` | ❌ | needs space |
| Trims whitespace around `=` | ✅ | ✅ | ✅ | ❌ | ✅ |
| Empty value `K=` | ✅ | ✅ | ✅ | ✅ | ✅ |
| Bare key `K` (no `=`) | (error) | (unset) | ignored | (host env) | **(error)** |
| Duplicate key | last wins | last wins | last wins | last wins | **(error)** |
| CRLF tolerated | ✅ | ✅ | ✅ | ✅ | ✅ (EOL preserved) |
| Leading BOM handled | ❌* | varies* | ❌* | ❌* | ✅ (removed from key semantics; preserved on write) |
| Round-trips comments/order/format | ❌ | ❌ | ❌ | ❌ | ✅ |

The rest of the document gives the example input behind each row.

---

## 2. Case-by-case disagreements

### A. Double-quoted escape sequences

Input:

```
A="line1\nline2\ttab"
```

| godotenv | python-dotenv | Node dotenv | Docker | **EnvGuardian** |
|---|---|---|---|---|
| `line1↵line2ttab` † | `line1↵line2␣␣tab` | `line1↵line2\ttab` | `"line1\nline2\ttab"` | `line1↵line2␣␣tab` |

† **Empirically verified against godotenv v1.5.1** by the differential test
(`differential_test.go`). godotenv expands **only** `\n` and `\r`; every other
escape simply **loses its backslash** (`\t`→`t`, `\z`→`z`), and `\\` collapses
to nothing. So on this input godotenv yields `line2ttab`, not a tab. Node
likewise expands only `\n`/`\r` but *keeps* the backslash on the rest, so it
yields `\ttab`. Docker expands nothing and keeps the quotes.

> **EnvGuardian:** in double quotes, expand the full set `\n \r \t \\ \" \$`.
> **Why:** it's what people expect when they paste a JSON blob or a `\n`-joined
> key, and it's the only behaviour under which `\t` survives round-tripping.
> This is a **deliberate divergence from godotenv** (which drops the backslash)
> and from Node (which leaves it): the differential test allows exactly this
> escape divergence and nothing else. Note that the four references *disagree
> with each other* here — there is no "compatible" choice, so we pick the
> principled one.

### B. Single-quoted values are literal

Input:

```
B='line1\nline2 ${HOST} #x'
```

| godotenv | python-dotenv | Node dotenv | Docker | **EnvGuardian** |
|---|---|---|---|---|
| `line1\nline2 ${HOST} #x` | `line1\nline2 ${HOST} #x` | `line1\nline2 ${HOST} #x` | `'line1\nline2 ${HOST} #x'` | `line1\nline2 ${HOST} #x` |

Single quotes suppress escapes, interpolation, and inline-comment handling in
all four real parsers; Docker just keeps the quote characters.

> **EnvGuardian:** single quotes are fully raw — no escapes, no `${VAR}`, no
> comment stripping. **Why:** this is the escape hatch for values that legit­
> imately contain `$`, `#`, `\`, or backslash-n literally (e.g. a regex or a
> pre-escaped token).

### C. `${VAR}` interpolation

Given an earlier line `HOST=db.local`:

```
C1=postgres://${HOST}:5432       # unquoted
C2="postgres://${HOST}:5432"     # double-quoted
C3='postgres://${HOST}:5432'     # single-quoted
```

| Input | godotenv | python-dotenv | Node dotenv | Docker | **EnvGuardian** |
|---|---|---|---|---|---|
| `C1` | `…db.local:5432` | `…db.local:5432` | `…${HOST}:5432` | `…${HOST}:5432` | `…db.local:5432` |
| `C2` | `…db.local:5432` | `…db.local:5432` | `…${HOST}:5432` | `…${HOST}:5432` | `…db.local:5432` |
| `C3` | `…${HOST}:5432` | `…${HOST}:5432` | `…${HOST}:5432` | `…${HOST}:5432` | `…${HOST}:5432` |

Node's core `dotenv` performs **no** interpolation — you must add
`dotenv-expand`. Docker never interpolates.

> **EnvGuardian:** interpolate `${VAR}` and `$VAR` in unquoted and double-quoted
> values, referencing keys already defined **earlier in the same file**;
> suppress it in single quotes; allow `\$` for a literal `$`. An **undefined**
> reference is an **error**, not an empty string. **Why:** interpolation is
> part of EnvGuardian's documented grammar and expected by developers, but silently
> expanding `${TYPO}` to `""` in a secrets file is exactly the kind of quiet
> breakage this tool exists to prevent — so we fail loudly and name the key.

### D. Multiline quoted values (the PEM-key case)

Input:

```
KEY="-----BEGIN-----
abc
-----END-----"
```

| godotenv | python-dotenv | Node dotenv | Docker | **EnvGuardian** |
|---|---|---|---|---|
| `-----BEGIN-----↵abc↵-----END-----` | same ✅ | same ✅ *(v15+)* | **(error)** — consumes only line 1 as `"-----BEGIN-----`, then tries to parse `abc` / `-----END-----"` as their own entries | `-----BEGIN-----↵abc↵-----END-----` |

Docker has no concept of a value spanning lines, so a PEM key or multiline
certificate is unrepresentable.

> **EnvGuardian:** support multiline values inside either quote style.
> **Why:** PEM private keys and certs are a primary reason a `.env` needs
> encrypting in the first place; not supporting them would gut the use case.

### E. `export ` prefix

Input:

```
export TOKEN=abc
```

| godotenv | python-dotenv | Node dotenv | Docker | **EnvGuardian** |
|---|---|---|---|---|
| `TOKEN` → `abc` | `TOKEN` → `abc` | `TOKEN` → `abc` *(v16+; older: line ignored)* | key becomes `export TOKEN` → invalid / dropped | `TOKEN` → `abc` |

> **EnvGuardian:** accept and strip a leading `export ` on read, and **preserve
> it on write** if the original line had it. **Why:** these files are often
> `source`-d by shell scripts, so the prefix is meaningful to the user;
> re-emitting the line without it would create a spurious diff and violate the
> idempotency rule.

### F. Inline comments — with and without a leading space

Inputs:

```
F1=secret # prod key
F2=sec#ret
```

| Input | godotenv | python-dotenv | Node dotenv | Docker | **EnvGuardian** |
|---|---|---|---|---|---|
| `F1` | `secret` | `secret` | `secret` | `secret # prod key` | `secret` |
| `F2` | `sec#ret` | `sec#ret` | `sec` ⚠️ | `sec#ret` | `sec#ret` |

Two opposite hazards. **Node** treats *any* `#` as a comment start, so it
**truncates** `F2` to `sec` — deadly for URLs with fragments
(`http://h/#frag`), colour hex values, or passwords containing `#`. **Docker**
does the reverse: it has no inline comments, so the `# prod key` on `F1` becomes
part of the secret.

> **EnvGuardian:** outside quotes, a `#` begins a comment **only** when preceded
> by whitespace; inside quotes it is literal. Comment text is preserved on
> write. **Why:** requiring the space keeps `#`-bearing values intact (the
> common failure) while still supporting `KEY=val # note`. To force a literal
> trailing `# ...`, quote the value.

### G. Whitespace around `=`

Input:

```
K = v
```

| godotenv | python-dotenv | Node dotenv | Docker | **EnvGuardian** |
|---|---|---|---|---|
| `K` → `v` | `K` → `v` | `K` → `v` | key `K␣`, value `␣v` → name-with-space (rejected/garbage) | `K` → `v` |

> **EnvGuardian:** trim whitespace around `=` and trim *unquoted* leading/
> trailing value whitespace; quote the value to keep surrounding spaces.
> **Why:** matches three of four parsers and matches human intent; Docker's
> literal treatment is a footgun.

### H. Empty value vs. bare key

Inputs:

```
E=
BARE
```

| Input | godotenv | python-dotenv | Node dotenv | Docker | **EnvGuardian** |
|---|---|---|---|---|---|
| `E=` | `(empty)` | `(empty)` | `(empty)` | `(empty)` | `(empty)` |
| `BARE` | `(error)` | `BARE` → `(unset)` | ignored | `BARE` → `(host env)` | **(error)** |

`E=` is unambiguous everywhere. The bare key is chaos: Docker silently imports
the host's `$BARE`, python-dotenv records it as `None`, Node drops it.

> **EnvGuardian:** `K=` is a valid empty string. A bare key with no `=` is an
> **error** (`line N: missing '='`). **Why:** Docker's host-env import is
> surprising and non-reproducible — the same committed file would decrypt to
> different values on different machines, defeating the entire point. Reject it.

### I. Duplicate keys

Input:

```
D=1
D=2
```

| godotenv | python-dotenv | Node dotenv | Docker | **EnvGuardian** |
|---|---|---|---|---|
| `2` (last wins) | `2` (last wins) | `2` (last wins in `parse`; `config()` won't override an existing `process.env`) | `2` (last wins) | **(error)** `duplicate key D (lines 1, 2)` |

> **EnvGuardian:** duplicate keys are an **error** naming both line numbers.
> **Why:** in a reviewed, committed secrets file a duplicate is a merge mistake
> or a copy-paste bug; "last wins" would let a stale value silently shadow the
> intended one. Fail loudly — this is cheap insurance against a whole class of
> bad merges. A merge driver is planned for `v0.2.0`; it is not implemented.

### J. CRLF line endings

Input (bytes): `X=1\r\n`

| godotenv | python-dotenv | Node dotenv | Docker | **EnvGuardian** |
|---|---|---|---|---|
| `1` | `1` | `1` (normalises `\r\n?`) | `1` (Go `ScanLines` drops trailing `\r`) | `1` |

The **parse** side agrees. The EnvGuardian-specific concern is the **write**
side.

> **EnvGuardian:** normalise to `\n` internally for parsing, but detect and
> **preserve the file's dominant line-ending style on write**. **Why:** the
> idempotency rule. If a Windows contributor's `.env` is CRLF, re-emitting it as
> LF would rewrite every line and produce a full-file diff on every encrypt —
> exactly the churn the tool must avoid.

### K. Leading UTF-8 BOM

Input (bytes): `EF BB BF` then `X=1`

| godotenv | python-dotenv | Node dotenv | Docker | **EnvGuardian** |
|---|---|---|---|---|
| `﻿X` → `1` (first key corrupted)* | varies by read encoding* | `﻿X` → `1`* | first name carries BOM (invalid)* | `X` → `1` (BOM stripped) |

A BOM in a `.env` is almost always an accidental artifact of a Windows editor
saving as "UTF-8 with BOM". Most parsers fold it into the first key name, so
`X` silently becomes undefined.

> **EnvGuardian:** remove a single leading UTF-8 BOM from the first key's parse
> semantics, record that it was present, and preserve it when writing the file.
> An unmodified parse/write round trip is byte-identical. **Why:** the first key
> must not be corrupted, while the source-preserving writer must not create an
> unrelated formatting diff.

### L. Invalid UTF-8 bytes in a value

Input (bytes): `BAD=` then `FF FE FD`

| godotenv | Node dotenv | Docker | **EnvGuardian** |
|---|---|---|---|
| `BAD` → `���` (each bad byte → U+FFFD) † | passes bytes through | passes bytes through | `BAD` → `\xFF\xFE\xFD` (bytes preserved) |

† Empirically verified against godotenv v1.5.1: it decodes the file as UTF-8 and
replaces invalid bytes with the Unicode replacement character, silently
mutating the value.

> **EnvGuardian:** preserve the raw bytes of a value exactly; never sanitize.
> **Why:** a secret is bytes, not text. Rewriting `0xFF` to `U+FFFD` would
> corrupt a binary-ish token *and* break the idempotency rule (the decrypted
> plaintext would differ from what was encrypted). This is a **deliberate
> divergence from godotenv**, allowed explicitly by the differential test.

---

## 3. Consolidated EnvGuardian rules

1. **Grammar:** POSIX-ish. `export` optional; `KEY=VALUE`; `#` comment requires
   preceding whitespace outside quotes.
2. **Double quotes:** expand `\n \r \t \\ \" \$`; allow multiline; interpolate
   `${VAR}`/`$VAR`.
3. **Single quotes:** fully literal; allow multiline; no interpolation, no
   escapes, no comment stripping.
4. **Unquoted:** trim surrounding whitespace; interpolate; inline comment on
   ` #`.
5. **Interpolation:** references keys defined **earlier in the same file**;
   `\$` escapes a literal `$`; an **undefined** reference is an error.
6. **Strict rejections (loud, with line numbers):** duplicate key; bare key
   without `=`; undefined interpolation; unterminated quote.
7. **Tolerated:** CRLF and a leading BOM. Their syntax is normalized for parsing
   while the source representation is preserved on write.
8. **Round-trip fidelity (unique to EnvGuardian):** the writer preserves
   comments, blank lines, key order, original quote style, `export` prefixes,
   the leading BOM, and the file's dominant line ending. Unmodified nodes are
   re-emitted byte-for-byte; changed and added entries are rendered as needed.

### Why stricter than every reference tool

The four references are **lossy map builders** tuned for "load config at app
startup, coerce whatever you find." EnvGuardian guards a **committed,
reviewed, encrypted** file where a silently-wrong value survives code review and
ships. In that setting, ambiguity should stop the pipeline, not be guessed at —
hence errors for duplicates, bare keys, and undefined interpolation. And because
the ciphertext must not churn, the parser must be a faithful round-tripper,
which none of the four references attempt.

> Run `go test -tags differential -run TestDifferentialGodotenv
> ./internal/dotenv` to execute the pinned godotenv comparison locally. The CI
> workflow runs the same command as a required, explicit job. EnvGuardian makes
> no automated conformance claim for Python, Node, or Docker.
