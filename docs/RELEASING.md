# Releasing

Releases are cut by pushing a semver tag. The
[`release` workflow](../.github/workflows/release.yml) runs
[GoReleaser](https://goreleaser.com), which builds binaries for
linux/darwin/windows × amd64/arm64, publishes a GitHub Release with checksums,
and updates the Homebrew tap.

## One-time setup: the Homebrew tap

1. **Create the tap repo.** On GitHub, create a public repository named
   **`homebrew-tap`** under your account (`YehiaGewily/homebrew-tap`). Homebrew
   requires the `homebrew-` prefix; users install with
   `brew install YehiaGewily/tap/envguardian`.

2. **Create a token.** The default `GITHUB_TOKEN` can only write to the current
   repo, so GoReleaser needs a Personal Access Token to push the cask to the tap
   repo:
   - Fine-grained PAT with **Contents: Read and write** on `homebrew-tap`, or a
     classic PAT with the `repo` scope.

3. **Add it as a secret.** In this repo's
   *Settings → Secrets and variables → Actions*, add a secret named
   **`HOMEBREW_TAP_TOKEN`** with that PAT.

> Not ready for Homebrew yet? Comment out the `homebrew_casks:` block in
> [`.goreleaser.yaml`](../.goreleaser.yaml) and the release will still publish
> binaries — just no `brew` formula.

## Coverage badge (optional)

The coverage badge uses [Codecov](https://codecov.io). Connect the repo at
codecov.io; CI already uploads `coverage.out` on the Ubuntu + Go 1.25 leg. No
token is needed for public repos.

## Cutting a release

1. Make sure `main` is green and `CHANGELOG.md` has the release notes moved from
   `## [Unreleased]` into a new `## [x.y.z]` section.
2. Tag and push:

   ```bash
   git tag -a v0.1.0 -m "v0.1.0"
   git push origin v0.1.0
   ```

3. The `release` workflow runs automatically. Watch it under the repo's
   **Actions** tab; the GitHub Release and updated tap appear when it finishes.

## Dry run

Verify the config and build without publishing anything:

```bash
goreleaser check
goreleaser release --snapshot --clean   # artifacts land in ./dist
```
