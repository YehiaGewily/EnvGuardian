#!/bin/sh
# Generates shell completion scripts for release archives and the Homebrew
# cask. GoReleaser runs this before building; the output is not tracked.
set -eu
rm -rf completions
mkdir completions
go run ./cmd/envguardian completion bash > completions/envguardian.bash
go run ./cmd/envguardian completion zsh > completions/_envguardian
go run ./cmd/envguardian completion fish > completions/envguardian.fish
go run ./cmd/envguardian completion powershell > completions/envguardian.ps1
