# Releasing

EnvGuardian currently has no supported release. `v0.1.0` is an unreleased
development tag; do not delete it or move it. The first hardening release will
be `v0.1.1` after Stages A through E in [PLAN.md](PLAN.md) are complete.

The [release workflow](../.github/workflows/release.yml) has two paths:

- a manual `workflow_dispatch` runs a GoReleaser snapshot and publishes
  nothing;
- pushing a future `v*` tag runs the publishing path.

The publishing path must not be used until the Stage G release gate is complete.
Homebrew publishing is intentionally absent because no tap exists. Prebuilt
binaries are not available until a supported GitHub release is actually
published.

## Controlled verification

From GitHub, open **Actions → release → Run workflow**. A manual run executes
`goreleaser release --snapshot --clean`; snapshot artifacts remain attached to
the workflow run and no GitHub release or package is published.

For a local dry run:

```bash
goreleaser check
goreleaser release --snapshot --clean
```

## Future `v0.1.1` release procedure

Do not run these commands until the release gate in the plan is complete.

1. Confirm `main` is protected and green, every required check ran on the exact
   commit, and `CHANGELOG.md` contains final `v0.1.1` notes.
2. Confirm the release workflow and GoReleaser publishing configuration against
   a manual snapshot run.
3. Create and push a signed annotated tag:

   ```bash
   git tag -s v0.1.1 -m "v0.1.1"
   git push origin v0.1.1
   ```

4. Verify checksums and downloaded binaries before documenting installation.

## Future Homebrew work

Stage G may add a Homebrew tap after the tap repository, credentials, publishing
configuration, and an end-to-end release test exist. Do not add installation
instructions before the package is publicly retrievable and verified.

## Coverage badge

The README does not claim a coverage percentage. Add a coverage badge only
after CI uploads a coverage report and the badge reflects the current commit.
