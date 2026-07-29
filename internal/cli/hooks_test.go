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

func setupCommittedHookRepo(t *testing.T) (bin, repo, identity string) {
	t.Helper()
	bin = buildBinary(t)
	repo = gitInitRepo(t)
	identity = filepath.Join(repo, "id.txt")
	writeAgeID(t, identity)
	if out, code := run(t, repo, bin, "init", "--identity", identity, "--name", "alice"); code != exitOK {
		t.Fatalf("init: %d\n%s", code, out)
	}
	if err := os.WriteFile(filepath.Join(repo, ".env"), []byte("A=one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, code := run(t, repo, bin, "encrypt", "--identity", identity); code != exitOK {
		t.Fatalf("encrypt: %d\n%s", code, out)
	}
	if out, code := run(t, repo, "git", "add", ".gitignore", ".env.age", ".envguardian"); code != exitOK {
		t.Fatalf("git add baseline: %d\n%s", code, out)
	}
	if out, code := run(t, repo, "git", "commit", "-m", "baseline"); code != exitOK {
		t.Fatalf("commit baseline: %d\n%s", code, out)
	}
	return bin, repo, identity
}

func TestPreCommitComparesPlaintextWithStagedCiphertext(t *testing.T) {
	bin, repo, identity := setupCommittedHookRepo(t)
	if err := os.WriteFile(filepath.Join(repo, ".env"), []byte("A=two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run(t, repo, bin, "encrypt", "--identity", identity)
	run(t, repo, "git", "add", ".env.age", ".envguardian/lock.toml")
	if err := os.WriteFile(filepath.Join(repo, ".env"), []byte("A=sentinel-secret-three\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := run(t, repo, bin, "hook-pre-commit", "--identity", identity)
	if code != exitOutOfSync || !strings.Contains(out, "changed keys: [A]") {
		t.Fatalf("stale staged ciphertext exit=%d\n%s", code, out)
	}
	if strings.Contains(out, "sentinel-secret-three") {
		t.Fatalf("pre-commit leaked plaintext value:\n%s", out)
	}
}

func TestPreCommitRejectsStagedRecipientsWithOldLock(t *testing.T) {
	bin, repo, identity := setupCommittedHookRepo(t)
	secondIdentity := filepath.Join(repo, "second-id.txt")
	secondRecipient := writeAgeID(t, secondIdentity)
	recipientsPath := filepath.Join(repo, ".envguardian", "recipients.toml")
	data, err := os.ReadFile(recipientsPath)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, []byte("\n[[recipient]]\nname = \"bob\"\nkey = \""+secondRecipient+"\"\nsource = \"manual\"\nadded_at = \"2026-07-28\"\nadded_by = \"test\"\n")...)
	if err := os.WriteFile(recipientsPath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	run(t, repo, "git", "add", ".envguardian/recipients.toml")
	out, code := run(t, repo, bin, "hook-pre-commit", "--identity", identity)
	if code != exitOutOfSync || !strings.Contains(out, "lock fingerprint differs") {
		t.Fatalf("old lock with staged recipients exit=%d\n%s", code, out)
	}
}

func TestPreCommitDetectsPartialCiphertextStaging(t *testing.T) {
	bin, repo, identity := setupCommittedHookRepo(t)
	if err := os.WriteFile(filepath.Join(repo, ".env"), []byte("A=two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run(t, repo, bin, "encrypt", "--identity", identity)
	run(t, repo, "git", "add", ".env.age", ".envguardian/lock.toml")
	if err := os.WriteFile(filepath.Join(repo, ".env"), []byte("A=three\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run(t, repo, bin, "encrypt", "--identity", identity)
	out, code := run(t, repo, bin, "hook-pre-commit", "--identity", identity)
	if code != exitOutOfSync || !strings.Contains(out, "working and staged ciphertext differ") {
		t.Fatalf("partial staging exit=%d\n%s", code, out)
	}
}

func TestPreCommitManagedChangeRequiresIdentity(t *testing.T) {
	bin, repo, _ := setupCommittedHookRepo(t)
	configPath := filepath.Join(repo, ".envguardian", "config.toml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, append([]byte("# reviewed metadata change\n"), data...), 0o644); err != nil {
		t.Fatal(err)
	}
	run(t, repo, "git", "add", ".envguardian/config.toml")
	out, code := run(t, repo, bin, "hook-pre-commit", "--identity", filepath.Join(repo, "missing-id"))
	if code != exitIdentity {
		t.Fatalf("missing identity exit=%d, want %d\n%s", code, exitIdentity, out)
	}
}

func TestPreCommitUnmanagedChangeUsesStructuralVerification(t *testing.T) {
	bin, repo, _ := setupCommittedHookRepo(t)
	if err := os.WriteFile(filepath.Join(repo, "README.md"), []byte("unmanaged\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run(t, repo, "git", "add", "README.md")
	if out, code := run(t, repo, bin, "hook-pre-commit", "--identity", filepath.Join(repo, "missing-id")); code != exitOK {
		t.Fatalf("unmanaged commit required an identity: %d\n%s", code, out)
	}
}

func TestPreCommitRejectsPartialConfigStaging(t *testing.T) {
	bin, repo, identity := setupCommittedHookRepo(t)
	configPath := filepath.Join(repo, ".envguardian", "config.toml")
	bad := "version = 1\n\n[[file]]\nplaintext = \".env\"\nciphertext = \"missing.age\"\n"
	if err := os.WriteFile(configPath, []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	run(t, repo, "git", "add", ".envguardian/config.toml")
	out, code := run(t, repo, bin, "hook-pre-commit", "--identity", identity)
	if code == exitOK || !strings.Contains(out, "staged ciphertext missing.age is missing") {
		t.Fatalf("partial config staging exit=%d\n%s", code, out)
	}
}

func TestPreCommitHandlesConfigRemoval(t *testing.T) {
	bin, repo, _ := setupCommittedHookRepo(t)
	if out, code := run(t, repo, "git", "rm", ".envguardian/config.toml"); code != exitOK {
		t.Fatalf("git rm config: %d\n%s", code, out)
	}
	if out, code := run(t, repo, bin, "hook-pre-commit"); code != exitOK {
		t.Fatalf("config removal was not handled: %d\n%s", code, out)
	}
}

func TestInstallHookRefusesMalformedShebang(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pre-commit")
	if err := os.WriteFile(path, []byte("echo malformed\n"), 0o750); err != nil {
		t.Fatal(err)
	}
	err := installHook(path, "envguardian hook-pre-commit")
	if err == nil || !strings.Contains(err.Error(), "no supported shell shebang") {
		t.Fatalf("installHook malformed shebang error=%v", err)
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != "echo malformed\n" {
		t.Fatalf("malformed hook was modified: %q", data)
	}
}

func TestPreCommitRejectsPlaintextAlreadyPresentInIndex(t *testing.T) {
	bin, repo, identity := setupCommittedHookRepo(t)
	if out, code := run(t, repo, "git", "add", "-f", ".env"); code != exitOK {
		t.Fatalf("force add plaintext: %d\n%s", code, out)
	}
	if out, code := run(t, repo, "git", "commit", "--no-verify", "-m", "unsafe fixture"); code != exitOK {
		t.Fatalf("create unsafe fixture: %d\n%s", code, out)
	}
	if err := os.WriteFile(filepath.Join(repo, "README.md"), []byte("unmanaged\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run(t, repo, "git", "add", "README.md")
	out, code := run(t, repo, bin, "hook-pre-commit", "--identity", identity)
	if code != exitConfig || !strings.Contains(out, "refusing to commit plaintext") {
		t.Fatalf("tracked plaintext was not rejected: %d\n%s", code, out)
	}
}
