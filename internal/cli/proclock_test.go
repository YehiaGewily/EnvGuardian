package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/YehiaGewily/envguardian/internal/proclock"
)

func TestWritingCommandsRefuseWhileAnotherHoldsTheLock(t *testing.T) {
	repo, identity := setupCommittedHookRepo(t)
	path, err := processLockPath(repo)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(filepath.ToSlash(path), "/.git/") {
		t.Fatalf("lock path %s is not inside the Git directory", path)
	}
	held, err := proclock.Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".env"), []byte("A=sentinel-lock-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(repo, ".env.age"))
	if err != nil {
		t.Fatal(err)
	}

	for _, args := range [][]string{
		{"encrypt", "--identity", identity},
		{"decrypt", "--identity", identity},
		{"rotation", "done", "A"},
		{"install-hooks"},
	} {
		out, code := runCLICombinedInDir(t, repo, args...)
		if code != exitOutOfSync || !strings.Contains(out, "another envguardian command is running") {
			t.Fatalf("%v while locked: exit=%d\n%s", args, code, out)
		}
		if strings.Contains(out, "sentinel-lock-value") {
			t.Fatalf("%v leaked a plaintext value:\n%s", args, out)
		}
	}
	after, err := os.ReadFile(filepath.Join(repo, ".env.age"))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("ciphertext changed while another process held the lock")
	}
	if out, code := runCLICombinedInDir(t, repo, "check", "--identity", identity); code != exitOK {
		t.Fatalf("read-only check must not need the lock: exit=%d\n%s", code, out)
	}

	if err := held.Release(); err != nil {
		t.Fatal(err)
	}
	if out, code := runCLICombinedInDir(t, repo, "encrypt", "--identity", identity); code != exitOK {
		t.Fatalf("encrypt after release: exit=%d\n%s", code, out)
	}
}

func TestProcessLockPathOutsideGitUsesUserCache(t *testing.T) {
	cache := t.TempDir()
	switch runtime.GOOS {
	case "windows":
		t.Setenv("LocalAppData", cache)
	case "darwin", "ios":
		t.Setenv("HOME", cache)
	default:
		t.Setenv("XDG_CACHE_HOME", cache)
	}
	t.Setenv("GIT_DIR", "")
	t.Setenv("GIT_CEILING_DIRECTORIES", filepath.Dir(t.TempDir()))
	dir := t.TempDir()
	path, err := processLockPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	resolvedCache, _ := filepath.EvalSymlinks(cache)
	resolvedPath, _ := filepath.EvalSymlinks(filepath.Dir(path))
	if !strings.HasPrefix(resolvedPath, resolvedCache) {
		t.Fatalf("lock %s is not under the user cache %s", path, cache)
	}
	if again, _ := processLockPath(dir); again != path {
		t.Fatalf("lock path is not stable: %s then %s", path, again)
	}
	if other, _ := processLockPath(t.TempDir()); other == path {
		t.Fatal("two repositories share one lock path")
	}
}
