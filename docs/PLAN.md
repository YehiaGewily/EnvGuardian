# EnvGuardian — Remediation & Completion Plan v2

This plan supersedes the historical milestone plan. Keep this file tracked in
git so repository documentation can link to an authoritative, reviewable
status document.

**Goal:** EnvGuardian becomes a tool that can safely hold a real team's secrets,
not a demo.

## Ground decisions

1. `v0.1.0` is an unreleased development tag. Do not delete it or move it.
   Fixes ship as `v0.1.1`.
2. Automatic decryption must never write outside the repository and never
   inside `.git/`.
3. Recipient changes must never bypass decrypt-and-compare when ciphertext
   already exists. **The recipient fingerprint decides whether we write. It
   never decides what we write.**
4. Lock state is per ciphertext and bound to that ciphertext's exact bytes.
5. Ciphertext digests are safe to commit because ciphertext is already public.
   Plaintext hashes, lengths, prefixes, and every other plaintext derivative
   are never committed, logged, or printed.
6. CI cannot prove an uncommitted local `.env` is current. `check` verifies
   repository integrity; `check-local` verifies developer synchronization. They
   are separate commands and separate jobs.
7. **age gives confidentiality, not sender authentication.** Until Stage D,
   any party who can open a pull request can produce ciphertext that decrypts
   for every recipient. This shapes Stages A and D.
8. Documentation honesty is a release gate. A false README claim is treated as
   a bug of the same severity as the code it misdescribes.
9. `v0.1.1` supports one file pair. Multi-file support returns in `v0.2.0` on
   top of the transactional planner; this is sequencing, not abandonment.

## Stage map

| Stage | Phases | Outcome | Rough effort |
|---|---:|---|---:|
| A — Stop the bleeding | 0–2 | Untrusted input cannot write outside the repo or execute | ~1 week |
| B — Correctness core | 3–5 | Seal, lock, and recipient updates are transactional and verifiable | ~1.5 weeks |
| C — Verification | 6–8 | Checks and hooks fail closed on the real commit snapshot | ~1 week |
| D — Authenticity | 9 | Ciphertext provenance is verifiable | ~1 week |
| E — Hygiene | 10–12 | Secret-safe output, atomic writes, coherent CLI, and tests | ~1 week |
| F — Features | 13 | Revocation/rotation, merge driver, and ADRs | ~1.5 weeks |
| G — Ship | 14 | `v0.1.1` is installable | ~2 days |

Ship `v0.1.1` after Stage E. Stage F targets `v0.2.0`.

## Stage A — Stop the bleeding

### Phase 0 — Repository protection and documentation honesty

Both halves are same-day work and precede code hardening.

#### GitHub configuration

- [ ] Protect `main` with an active branch ruleset.
- [ ] Require pull requests and at least one approval; dismiss stale approvals.
- [ ] Require every job in the CI workflow as a status check.
- [ ] Block force pushes and branch deletion.
- [ ] Require signed commits. This is load-bearing for Phase 2.
- [x] Add `.github/CODEOWNERS` for `.envguardian/**`, `*.age`,
  `.gitattributes`, `.github/workflows/**`, `internal/crypt/**`,
  `internal/keys/**`, and `internal/cli/hooks.go`.

The unchecked items are remote GitHub settings and are not satisfied by files
in this repository. Complete and verify them before declaring Phase 0 done.

#### Documentation truth pass

- [x] Warn that the project is pre-release and must not hold real secrets.
- [x] Remove unavailable Homebrew and prebuilt-binary installation claims.
- [x] Warn against installing hooks from `v0.1.0`.
- [x] Replace links to untracked plans and tool-specific instruction files;
  make `CONTRIBUTING.md` the permanent engineering policy.
- [x] State that only the build-tagged godotenv differential test exists and it
  is excluded from normal CI.
- [x] Document the writer's actual BOM-preservation behavior.
- [x] Make `internal/rotation` and `internal/gitint` package docs describe only
  implemented code.
- [x] Remove the unimplemented `rotation done` suggestion from `check`.
- [x] Record the legacy milestone status accurately; M3 is unimplemented.
- [x] Add a path-traversal advisory and disclosure address to `SECURITY.md`.
- [x] Add a non-publishing `workflow_dispatch` verification path to the release
  workflow.

#### Legacy milestone status

| Legacy milestone | Actual status |
|---|---|
| M0 | Build/test/lint workflow and GoReleaser configuration exist. `v0.1.0` is only a development tag; no supported release or Homebrew tap exists. |
| M1 | Parser, key loading, identity resolution, age wrapper, and commands exist as a prototype. Security and transaction remediation remains open. |
| M2 | Hook, check, ignore, and diff prototypes exist. They are not yet safe or complete enough for real secrets. |
| M3 | Unimplemented. There is no revoke command, rotation completion command, merge driver, or ADR set. |

**Done when:** the remote `main` branch cannot be pushed directly and every
statement in the repository describes the current implementation honestly.

### Phase 1 — Contain every managed path

- [x] Add `config.ResolveManagedPath` and apply it while loading config.
- [x] Reject empty and cross-platform absolute paths, textual traversal, and
  paths inside `.git/`.
- [x] Evaluate symlinks on the deepest existing parent after joining and
  recheck repository containment.
- [x] Reject plaintext/ciphertext collisions and duplicate destinations,
  including aliases through symlinks or existing hard links.
- [x] Enforce the `v0.1.1` single-file-pair boundary until the transactional
  multi-file planner lands in `v0.2.0`.
- [x] Validate `init --file` before any repository mutation.
- [x] Route configured encrypt, decrypt, working diff, check, hook, and
  recipient operations through the resolved paths.
- [x] Parse decrypted bytes as dotenv before an atomic mode-`0600` write.
- [x] Cover traversal, Unix/Windows absolute forms, `.git/`, symlink escape,
  collisions, duplicates, invalid decrypted dotenv, and a valid nested path.

**Done:** repository-controlled managed mappings cannot select a read or write
outside the repository or inside `.git/`.

### Phase 2 — Fix the automatic-decryption trust boundary

- [x] Store the last accepted/successful auto-decrypt commit in the local,
  gitignored `.envguardian/auto-decrypt-state.toml` file.
- [x] Compare committed `config.toml`, `recipients.toml`, and every configured
  ciphertext with that commit before automatic decryption.
- [x] Refuse managed changes, report only key and recipient names, report commit
  signature/recipient status, and require `decrypt --accept-changes`.
- [x] Compare config bytes before parsing the incoming config; hook destinations
  come only from an already accepted config or an explicit acceptance.
- [x] Decrypt exact ciphertext blobs from the resolved commit rather than a
  potentially modified working tree.
- [x] Test changed config, changed ciphertext, unchanged silent success, and
  explicit acceptance/state update.
- [x] Document the temporary boundary and the remaining Stage D authenticity
  requirement in `docs/threat-model.md`.

**Done:** checking out a commit with changed managed inputs cannot modify local
plaintext without explicit acceptance.

Later stage checklists will be added under user direction.
