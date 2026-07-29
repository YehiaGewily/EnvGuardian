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
7. **age gives confidentiality, not sender authentication.** Any party who can
   open a pull request can produce ciphertext that decrypts for every
   recipient. Stage D therefore adds separate detached SSH signatures; age
   decryption itself never becomes proof of authorship.
8. Documentation honesty is a release gate. A false README claim is treated as
   a bug of the same severity as the code it misdescribes.
9. `v0.1.1` supported one file pair. Stage F restores multi-file support for
   `v0.2.0` on the proven transactional planner.

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
  `*.age.sig`, `.gitattributes`, `.github/workflows/**`,
  `internal/crypt/**`, `internal/authenticity/**`, `internal/keys/**`, and
  `internal/cli/hooks.go`.

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
- [x] Record the then-current legacy milestone status; Stage F's completed M3
  entry below now supersedes that Phase 0 snapshot.
- [x] Add a path-traversal advisory and disclosure address to `SECURITY.md`.
- [x] Add a non-publishing `workflow_dispatch` verification path to the release
  workflow.

#### Legacy milestone status

| Legacy milestone | Actual status |
|---|---|
| M0 | Build/test/lint workflow and GoReleaser configuration exist. `v0.1.0` is only a development tag; no supported release or Homebrew tap exists. |
| M1 | Parser, key loading, identity resolution, age wrapper, and commands exist as a prototype. Security and transaction remediation remains open. |
| M2 | Hook, check, ignore, and diff prototypes exist. They are not yet safe or complete enough for real secrets. |
| M3 | Implemented for v0.2: transactional revocation, a key-name-only rotation ledger, a paused/finalized semantic merge driver, multi-file support, and ADRs 0001–0008. |

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
- [x] Enforce the `v0.1.1` single-file-pair boundary during remediation; Stage
  F removes it only after multi-file planner tests pass.
- [x] Validate `init --file` before any repository mutation.
- [x] Route configured encrypt, decrypt, working diff, check, hook, and
  recipient operations through the resolved paths.
- [x] Resolve config, recipients, lock, and local hook-state metadata through
  the same boundary so a symlinked `.envguardian` directory cannot redirect a
  transaction outside the repository.
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
- [x] Document the temporary acceptance boundary in `docs/threat-model.md`,
  which now also records how Stage D detached signatures authenticate artifacts
  without authenticating age decryption itself.

**Done:** checking out a commit with changed managed inputs cannot modify local
plaintext without explicit acceptance.

## Stage B — Correctness core

### Phase 3 — Single file pair, lock state, and seal planner

- [x] Initially accept one pair while keeping slice-shaped planning/commit APIs;
  Stage F restores multiple mappings with one lock entry per ciphertext.
- [x] Replace the global prototype lock with strict lock format v2: one entry
  per configured ciphertext, recipient fingerprint, and exact ciphertext
  SHA-256 digest.
- [x] Read and validate plaintext and decrypt existing ciphertext before any
  write; compare semantic dotenv key/value content.
- [x] Make recipient/lock changes decide whether to write, while decrypted
  existing content decides what is written. Reject divergent local plaintext
  during a recipient/lock change.
- [x] Require a usable identity for existing ciphertext unless the user selects
  the loud `--force` lost-key escape hatch; allow identity-free creation only
  for brand-new ciphertext.
- [x] Generate all replacements before committing, write the lock last, retain
  originals for rollback on ordinary errors, and make interrupted writes
  detectable through ciphertext digests.
- [x] Strictly reject missing, extra, duplicate, malformed, digest-mismatched,
  fingerprint-mismatched, and unsupported-version lock entries.
- [x] Test add/replace/remove recipient membership, same-count key replacement,
  planning without writes, rollback, interrupted commit detection, lock skew,
  and stale-branch divergence.

**Done:** sealing is planned before mutation; recipient changes cannot silently
replace committed secret content with a stale local dotenv.

### Phase 4 — Transactional recipient operations

- [x] Make `add-recipient` use the seal planner and delay every success message
  and recipients-file write until planning succeeds.
- [x] Enforce the plaintext `.gitignore` guard.
- [x] If local plaintext is absent, decrypt existing ciphertext in memory; if
  it is undecryptable, fail without modifying recipients, ciphertext, or lock.
- [x] Commit ciphertext and recipients before writing lock last, rolling all
  attempted files back on ordinary errors.
- [x] Reject explicitly supplied invalid identities.
- [x] Give GitHub fetching a timeout, reject oversized bodies, and validate
  every returned Ed25519 key.
- [x] Add additive `keys = [...]` parsing, flatten all legacy/new keys for age,
  duplicate detection and fingerprints, while retaining legacy `key =` reads.
- [x] Fail loudly when GitHub returns multiple Ed25519 keys until v0.2 enables
  multi-key recipient onboarding.

**Done:** a failed recipient addition leaves all committed managed state
unchanged under ordinary process errors.

### Phase 5 — Config and CLI correctness

- [x] Validate config version during every load and reject unknown TOML fields.
- [x] Preserve `os.ErrNotExist` through wrapping so hooks can distinguish an
  uninitialized repository.
- [x] Enforce exit codes: 0 success, 1 out of sync/conflict, 2 identity or
  decryption failure, 3 malformed config or dotenv, and 4 ciphertext signature
  failure.
- [x] Delete the unused `--no-color` flag and implement secret-safe
  `--verbose` progress.
- [x] Support `--json` for `check`, `list-recipients`, `rotation status`, and
  `rotation done`; reject it on other commands.
- [x] Discover the repository root when commands run from subdirectories, while
  preserving explicit `--config` behavior.
- [x] Add meaningful config-package coverage for versions, unknown fields,
  missing-file error identity, path rules, collisions, and single-pair scope.

**Done:** malformed input and identity failures have stable CLI semantics, and
commands operate on the intended repository root.

## Stage C — Verification that fails closed

### Phase 6 — Split `check` and `check-local`

- [x] Make `check` verify supported config and safe paths, valid recipients,
  ciphertext existence, lock digest/fingerprint, decryptability, dotenv
  validity, plaintext gitignore state, and readable rotation state.
- [x] Require an identity and successful decryption by default; provide the
  explicit `--structural-only` mode for fork PRs without secrets.
- [x] Fail on malformed or unreadable rotation ledgers. Only a genuinely
  absent ledger means no pending rotations.
- [x] Add `check-local` to compare working plaintext semantically with
  ciphertext and fail on a missing plaintext unless `--allow-missing` is set.
- [x] Document that CI cannot compare ciphertext with an uncommitted local
  plaintext file.

**Done:** repository verification never succeeds because an implicit identity
or content check was skipped; local synchronization has its own command.

### Phase 7 — Rebuild pre-commit around the index

- [x] Read staged config, recipients, lock, ciphertext, and detached signature
  with exact Git-index blob commands and parse changed paths as NUL-delimited
  output.
- [x] Treat every Git subprocess error as a verification failure.
- [x] Reject configured plaintext present in the index, including force-added
  files and plaintext staged while removing EnvGuardian configuration.
- [x] Verify staged recipients against staged lock, and staged lock digests
  against staged ciphertext bytes.
- [x] When managed state changes, require an identity, compare local plaintext
  with staged ciphertext, and reject working/staged ciphertext divergence.
- [x] For commits touching no managed file, perform structural verification
  without requiring an identity.
- [x] Handle configuration removal and refuse existing hook files with no
  valid shebang.

**Done:** pre-commit validates the snapshot being committed rather than a
potentially different working tree.

### Phase 8 — Real external diff driver

- [x] Add hidden `diff-driver PATH OLD OLD_HEX OLD_MODE NEW NEW_HEX NEW_MODE`.
- [x] Decrypt and parse both sides independently, then emit only `+ KEY`,
  `- KEY`, and `~ KEY`.
- [x] Fail clearly if either side cannot be read, decrypted, or parsed.
- [x] Register a repository-local `diff.envguardian.command`; remove the
  obsolete one-sided `textconv` setting and shell-quote the executable path.
- [x] Test value-only changes, additions/removals, comment/reorder policy,
  non-recipient failure, sentinel non-disclosure, and special-character shell
  quoting.

**Done:** Git diffs surface value-only changes by key name without revealing
values or other plaintext derivatives.

## Stage D — Authenticity

### Phase 9 — Sign the ciphertext

- [x] Record the mechanism first in
  [ADR 0008](adr/0008-ciphertext-authentication.md): OpenSSH
  signatures reuse recipient SSH keys and delegate cryptography to
  `ssh-keygen -Y sign/verify`.
- [x] Generate `.env.age.sig` alongside ciphertext and include it in the
  rollback-capable seal/recipient transaction before lock is written last.
- [x] Sign a versioned, domain-separated public payload binding the exact
  ciphertext SHA-256, recipient fingerprint, config path, plaintext mapping,
  and ciphertext mapping.
- [x] Make `check`, manual decrypt, pre-commit, and exact-commit automatic
  decryption verify present signatures against current SSH recipients before
  any plaintext write.
- [x] Add `authenticity.SignatureError` and dedicated exit code 4.
- [x] Warn on missing signatures during v0.1.x migration; document that v0.2
  changes this to a failure.
- [x] Test non-recipient and revoked signers, different ciphertext and mapping
  bindings, missing-signature migration, exact hook snapshots, idempotency,
  transaction preservation, and secret-safe failures.

**Done:** successful age decryption is no longer the only evidence attached to
a ciphertext; a present detached signature proves it was sealed by a current
SSH recipient for this exact repository mapping.

## Stage E — Hygiene

### Phase 10 — Secret-safe diagnostics

- [x] Remove malformed dotenv fragments and invalid leading bytes from parser
  errors; report the line, column, and error category only.
- [x] Render identity and age decryption failures through stable safe
  categories instead of upstream parser text.
- [x] Stop echoing repository-controlled Git subprocess output in errors.
- [x] Add sentinel tests across dotenv, identity, crypt, diff, hooks, check,
  automatic decryption, signatures, and complete CLI output streams.
- [x] Keep key names available for useful comparisons while never emitting
  values or value derivatives.

**Done:** malformed plaintext, private-key input, and upstream parser text do
not reach user-visible output.

### Phase 11 — Atomic writes everywhere

- [x] Route `.gitignore`, `.gitattributes`, hook installation, and all other
  production writes through `internal/atomic`.
- [x] Apply final file permissions before syncing content and metadata, clean
  temporary files on failures, and fsync the parent after rename.
- [x] Preserve the permission mode of existing hook files.
- [x] Document prominently that `0600` does not install a restrictive Windows
  ACL and that the Windows build is not yet suitable for real secrets.
- [x] Add a repository test that rejects direct production `os.WriteFile`.

**Done:** every production write uses the single atomic-write boundary, with
the remaining Windows ACL limitation stated instead of hidden.

### Phase 12 — Tests and coverage gates

- [x] Keep `crypt` at 85.5%, `config` at 86.0%, `keys` at 85.6%, and `dotenv`
  at 90.8%; Stage F's added behavior tests keep honest whole-repository
  statement coverage at 81.2%.
- [x] Add a checked-in coverage gate enforcing package floors and 80% overall,
  and upload the aggregate profile from CI.
- [x] Run the pinned godotenv v1.5.1 differential suite as an explicit CI job
  instead of leaving it outside CI.
- [x] Pin every GitHub Action reference to a verified commit SHA.
- [x] Add `go mod tidy -diff` and pinned GoReleaser configuration validation.
- [x] Keep path-containment and staged-Git integration tests in the existing
  Unix, macOS, and Windows matrix.
- [x] Narrow automated conformance claims to godotenv; Python, Node, and Docker
  remain clearly labeled non-authoritative manual background notes.

**Done:** local validation passes the same package and aggregate coverage
floors now encoded in CI, and verification dependencies are immutable.

## Stage F — Features (v0.2.0)

### Phase 13 — M3

#### Revocation and rotation

- [x] Implement a strict versioned rotation ledger containing key names only.
- [x] Add transactional `revoke NAME`, refuse the last-recipient removal, and
  derive pending names from authenticated, decrypted current ciphertext.
- [x] Add `rotation status` and `rotation done KEY`, including key-name-only
  JSON and atomic ledger writes.
- [x] Fail on unreadable or malformed ledgers and state plainly that Git
  history remains decryptable until credentials are rotated at their source.
- [x] Test successful revocation, last-recipient refusal, malformed state,
  value non-disclosure, and no mutation on stale-plaintext divergence.

#### Merge driver

- [x] Record the base/ours/theirs policy in
  [the merge decision table](merge-driver-decision-table.md) before code.
- [x] Merge semantic key/value state in memory, retain ours formatting for
  comment-only/reorder equality, and report conflicts by key name only.
- [x] Register executable commands only in local Git config; repository
  `.gitattributes` selects driver names and disables ciphertext line conversion.
- [x] Pause successful low-level merges, then make `merge --continue` resolve
  every configured ciphertext and commit ciphertexts, signatures, and the
  complete lock through one planner transaction before staging them.
- [x] Test real diverging branches for a successful independent-key merge and
  a same-key conflict whose streams contain no sentinel values.

#### ADRs and multi-file support

- [x] Add ADRs 0001–0008 covering age, SSH identities, revocation versus
  rotation, ciphertext idempotency, managed paths, lock/transactions,
  repository versus local checks, and ciphertext authentication.
- [x] Restore multiple file mappings on the plural planner; verify shared-lock
  lookup and unchanged multi-file idempotency.
- [x] Make missing signatures fail closed for v0.2 rather than using the
  v0.1.x migration warning.

**Done:** M3 operates on the same containment, authentication, and transaction
boundaries as sealing; successful merges cannot leave a falsely current lock.
