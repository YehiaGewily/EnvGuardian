package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/YehiaGewily/envguardian/internal/proclock"
)

// processLockName is the lock file inside a repository's Git directory.
const processLockName = "envguardian.lock"

// exclusive runs fn while holding the repository's EnvGuardian process lock,
// so two invocations never interleave planner transactions or plaintext
// writes. The lock never waits; contention is reported, not queued.
func exclusive(flags *globalFlags, fn func() error) error {
	p, err := secureRootPaths(flags)
	if err != nil {
		return err
	}
	path, err := processLockPath(p.Root)
	if err != nil {
		return err
	}
	lock, err := proclock.Acquire(path)
	if errors.Is(err, proclock.ErrLocked) {
		return withExit(exitOutOfSync, fmt.Errorf("another envguardian command is running in this repository (lock %s); wait for it to finish, then retry", display(path)))
	}
	if err != nil {
		return fmt.Errorf("take the repository lock: %w", err)
	}
	defer func() { _ = lock.Release() }()
	return fn()
}

// processLockPath places the lock in the work tree's Git directory. Outside
// Git it uses the user cache directory, keyed by the repository root, so no
// file is added to the project. A Git failure where a repository is indicated
// fails closed rather than silently locking somewhere else.
func processLockPath(root string) (string, error) {
	out, gitErr := gitCommandBytes(root, "rev-parse", "--absolute-git-dir")
	if gitErr == nil {
		if dir := strings.TrimSpace(string(out)); dir != "" {
			return filepath.Join(dir, processLockName), nil
		}
		gitErr = errors.New("git returned an empty Git directory")
	}
	marker := "GIT_DIR"
	if os.Getenv("GIT_DIR") == "" {
		marker = findGitEntry(root)
	}
	if marker != "" {
		return "", withExit(exitOutOfSync, fmt.Errorf("%s indicates a Git repository, but Git could not open it (%w); fix the repository or Git installation and retry", marker, gitErr))
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("locate a user cache directory for the process lock: %w", err)
	}
	dir := filepath.Join(cache, "envguardian", "locks")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create process lock directory %s: %w", dir, err)
	}
	sum := sha256.Sum256([]byte(filepath.Clean(root)))
	return filepath.Join(dir, hex.EncodeToString(sum[:16])+".lock"), nil
}
