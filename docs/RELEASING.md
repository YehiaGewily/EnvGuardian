# Releasing

EnvGuardian currently has no supported release. `v0.1.0` is an unreleased
development tag; do not delete it or move it. `v0.1.1` was not cut before the
v0.2 feature set landed on `main`, so the first supported release candidate is
`v0.2.0`. Publishing that version keeps the tag honest about multi-file,
rotation, revocation, merge-driver, and strict-signature behavior.

The [release workflow](../.github/workflows/release.yml) has two paths:

- a manual `workflow_dispatch` runs a GoReleaser snapshot and publishes
  nothing;
- pushing a future `v*` tag runs the publishing path.

The publishing path must not be used until the Stage G release gate is complete.
Prebuilt binaries and Homebrew remain unavailable until a supported GitHub
release and tap are actually published and verified.

## Controlled verification

From GitHub, open **Actions → release → Run workflow**. A manual run executes
`goreleaser release --snapshot --clean`; snapshot artifacts remain attached to
the workflow run and no GitHub release or package is published.

For a local dry run:

```bash
goreleaser check
goreleaser release --snapshot --clean
```

## Homebrew tap prerequisite

Before the final tag, create the public `YehiaGewily/homebrew-tap` repository
with a `main` branch. Create a fine-grained personal access token restricted to
that repository with only **Contents: read and write** (Metadata read is
automatic), then store it in the EnvGuardian repository as the Actions secret
`HOMEBREW_TAP_TOKEN`. Never put the token in a file, command history, workflow
log, or GoReleaser configuration.

GoReleaser publishes `Casks/envguardian.rb` to the tap. The normal
`GITHUB_TOKEN` publishes GitHub release assets; it cannot write to another
repository.

## `v0.2.0` release procedure

Do not run these commands until the release gate in the plan is complete.

1. Confirm `main` is protected and green, every required check ran on the exact
   commit, and `CHANGELOG.md` contains final `v0.2.0` notes.
2. Confirm the release workflow and GoReleaser publishing configuration against
   a manual snapshot run. Inspect six archives and `checksums.txt`.
3. Create and push a signed annotated tag:

   ```bash
   git tag -s v0.2.0 -m "v0.2.0"
   git push origin v0.2.0
   ```

4. Download every release asset, verify `checksums.txt`, and run the binary on
   Linux, macOS, and Windows. Confirm both architectures were published for
   each OS.
5. Verify source installation from a clean module/cache environment:

   ```bash
   go install github.com/YehiaGewily/envguardian/cmd/envguardian@v0.2.0
   envguardian version
   ```

6. Verify Homebrew from a clean environment:

   ```bash
   brew tap YehiaGewily/tap
   brew install --cask envguardian
   envguardian version
   ```

7. Only after all paths succeed, update README and SECURITY to mark v0.2.0
   supported and replace the pre-release warning with verified installation
   instructions. The Windows DACL limitation must remain prominent until native
   ACL enforcement exists.

## Coverage badge

The README does not claim a coverage percentage. Add a coverage badge only
after CI uploads a coverage report and the badge reflects the current commit.
