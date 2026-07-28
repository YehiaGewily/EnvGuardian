package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// buildBinary compiles envguardian into a temp dir and returns its path.
func buildBinary(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	repoRoot := filepath.Dir(filepath.Dir(pkgDir)) // internal/cli -> repo root
	name := "envguardian"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	bin := filepath.Join(t.TempDir(), name)
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/envguardian")
	cmd.Dir = repoRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

func gitInitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, args := range [][]string{
		{"init"},
		{"config", "user.email", "test@example.com"},
		{"config", "user.name", "test"},
		{"config", "commit.gpgsign", "false"},
	} {
		c := exec.Command("git", args...)
		c.Dir = dir
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	return dir
}

func run(t *testing.T, dir, name string, args ...string) (string, int) {
	t.Helper()
	c := exec.Command(name, args...)
	c.Dir = dir
	out, err := c.CombinedOutput()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("run %s %v: %v", name, args, err)
		}
	}
	return string(out), code
}

func TestInstallHooksBlocksPlaintextCommit(t *testing.T) {
	bin := buildBinary(t)
	repo := gitInitRepo(t)

	// Generate an identity and initialize the repo.
	idPath := filepath.Join(repo, "id.txt")
	writeAgeID(t, idPath)
	if out, code := run(t, repo, bin, "init", "--identity", idPath, "--name", "alice"); code != 0 {
		t.Fatalf("init: %d\n%s", code, out)
	}
	if out, code := run(t, repo, bin, "install-hooks"); code != 0 {
		t.Fatalf("install-hooks: %d\n%s", code, out)
	}

	// Hooks exist and carry our block.
	for _, h := range managedHooks {
		data, err := os.ReadFile(filepath.Join(repo, ".git", "hooks", h))
		if err != nil {
			t.Fatalf("hook %s missing: %v", h, err)
		}
		if !strings.Contains(string(data), hookBegin) {
			t.Errorf("hook %s missing managed block:\n%s", h, data)
		}
		if (h == "post-merge" || h == "post-checkout") && !strings.Contains(string(data), "hook-auto-decrypt") {
			t.Errorf("hook %s bypasses automatic-decryption trust gate:\n%s", h, data)
		}
	}

	// Stage the plaintext .env (force, since it's gitignored) and try to commit.
	if err := os.WriteFile(filepath.Join(repo, ".env"), []byte("SECRET=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, code := run(t, repo, "git", "add", "-f", ".env"); code != 0 {
		t.Fatalf("git add: %d\n%s", code, out)
	}
	out, code := run(t, repo, "git", "commit", "-m", "leak")
	if code == 0 {
		t.Fatalf("commit succeeded but should have been blocked:\n%s", out)
	}
	if !strings.Contains(out, "refusing to commit plaintext") {
		t.Errorf("block message missing:\n%s", out)
	}

	// The commit must not have happened.
	if count, _ := run(t, repo, "git", "rev-list", "--all", "--count"); strings.TrimSpace(count) != "0" {
		t.Errorf("commit count = %q, want 0 (a commit was created despite the block)", strings.TrimSpace(count))
	}
}

func TestInstallHooksIdempotentAndUninstall(t *testing.T) {
	bin := buildBinary(t)
	repo := gitInitRepo(t)

	// A pre-existing hook we must not clobber.
	hookPath := filepath.Join(repo, ".git", "hooks", "pre-commit")
	if err := os.WriteFile(hookPath, []byte("#!/bin/sh\necho existing\n"), 0o750); err != nil {
		t.Fatal(err)
	}

	idPath := filepath.Join(repo, "id.txt")
	writeAgeID(t, idPath)
	run(t, repo, bin, "init", "--identity", idPath, "--name", "alice")

	// Install twice; the block must appear exactly once and the original line survive.
	run(t, repo, bin, "install-hooks")
	run(t, repo, bin, "install-hooks")
	data, _ := os.ReadFile(hookPath)
	if n := strings.Count(string(data), hookBegin); n != 1 {
		t.Errorf("managed block appears %d times, want 1:\n%s", n, data)
	}
	if !strings.Contains(string(data), "echo existing") {
		t.Errorf("pre-existing hook content was lost:\n%s", data)
	}

	// Uninstall removes only our block.
	run(t, repo, bin, "install-hooks", "--uninstall")
	data, _ = os.ReadFile(hookPath)
	if strings.Contains(string(data), hookBegin) {
		t.Errorf("uninstall left the managed block:\n%s", data)
	}
	if !strings.Contains(string(data), "echo existing") {
		t.Errorf("uninstall removed non-managed content:\n%s", data)
	}
}
