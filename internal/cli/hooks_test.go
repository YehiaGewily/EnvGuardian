package cli

import (
	"errors"
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
		// Git may otherwise start background maintenance after a commit. That
		// process can outlive the test briefly and race with t.TempDir cleanup.
		{"config", "gc.auto", "0"},
		{"config", "gc.autoDetach", "false"},
		{"config", "maintenance.auto", "false"},
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
	repo := gitInitRepo(t)

	// A pre-existing hook we must not clobber.
	hookPath := filepath.Join(repo, ".git", "hooks", "pre-commit")
	if err := os.WriteFile(hookPath, []byte("#!/bin/sh\necho existing\n"), 0o750); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(hookPath, 0o710); err != nil {
			t.Fatal(err)
		}
	}

	idPath := filepath.Join(repo, "id.txt")
	writeAgeID(t, idPath)
	runCLICombinedInDir(t, repo, "init", "--identity", idPath, "--name", "alice")

	// Install twice; the block must appear exactly once and the original line survive.
	runCLICombinedInDir(t, repo, "install-hooks")
	runCLICombinedInDir(t, repo, "install-hooks")
	data, _ := os.ReadFile(hookPath)
	if n := strings.Count(string(data), hookBegin); n != 1 {
		t.Errorf("managed block appears %d times, want 1:\n%s", n, data)
	}
	if !strings.Contains(string(data), "echo existing") {
		t.Errorf("pre-existing hook content was lost:\n%s", data)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(hookPath)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o710 {
			t.Errorf("hook permissions = %o, want preserved 710", got)
		}
	}

	// Uninstall removes only our block.
	runCLICombinedInDir(t, repo, "install-hooks", "--uninstall")
	data, _ = os.ReadFile(hookPath)
	if strings.Contains(string(data), hookBegin) {
		t.Errorf("uninstall left the managed block:\n%s", data)
	}
	if !strings.Contains(string(data), "echo existing") {
		t.Errorf("uninstall removed non-managed content:\n%s", data)
	}
}

func setupCommittedHookRepo(t *testing.T) (repo, identity string) {
	t.Helper()
	repo = gitInitRepo(t)
	identity = filepath.Join(repo, "id.txt")
	writeAgeID(t, identity)
	if out, code := runCLICombinedInDir(t, repo, "init", "--identity", identity, "--name", "alice"); code != exitOK {
		t.Fatalf("init: %d\n%s", code, out)
	}
	if err := os.WriteFile(filepath.Join(repo, ".env"), []byte("A=one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, code := runCLICombinedInDir(t, repo, "encrypt", "--identity", identity); code != exitOK {
		t.Fatalf("encrypt: %d\n%s", code, out)
	}
	if out, code := run(t, repo, "git", "add", ".gitignore", ".env.age", ".env.age.sig", ".envguardian"); code != exitOK {
		t.Fatalf("git add baseline: %d\n%s", code, out)
	}
	if out, code := run(t, repo, "git", "commit", "-m", "baseline"); code != exitOK {
		t.Fatalf("commit baseline: %d\n%s", code, out)
	}
	return repo, identity
}

func TestPreCommitComparesPlaintextWithStagedCiphertext(t *testing.T) {
	repo, identity := setupCommittedHookRepo(t)
	if err := os.WriteFile(filepath.Join(repo, ".env"), []byte("A=two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runCLICombinedInDir(t, repo, "encrypt", "--identity", identity)
	run(t, repo, "git", "add", ".env.age", ".env.age.sig", ".envguardian/lock.toml")
	if err := os.WriteFile(filepath.Join(repo, ".env"), []byte("A=sentinel-secret-three\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := runCLICombinedInDir(t, repo, "hook-pre-commit", "--identity", identity)
	if code != exitOutOfSync || !strings.Contains(out, "changed keys: [A]") {
		t.Fatalf("stale staged ciphertext exit=%d\n%s", code, out)
	}
	if strings.Contains(out, "sentinel-secret-three") {
		t.Fatalf("pre-commit leaked plaintext value:\n%s", out)
	}
}

func TestPreCommitRejectsStagedRecipientsWithOldLock(t *testing.T) {
	repo, identity := setupCommittedHookRepo(t)
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
	out, code := runCLICombinedInDir(t, repo, "hook-pre-commit", "--identity", identity)
	if code != exitOutOfSync || !strings.Contains(out, "lock fingerprint differs") {
		t.Fatalf("old lock with staged recipients exit=%d\n%s", code, out)
	}
}

func TestPreCommitDetectsPartialCiphertextStaging(t *testing.T) {
	repo, identity := setupCommittedHookRepo(t)
	if err := os.WriteFile(filepath.Join(repo, ".env"), []byte("A=two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runCLICombinedInDir(t, repo, "encrypt", "--identity", identity)
	run(t, repo, "git", "add", ".env.age", ".env.age.sig", ".envguardian/lock.toml")
	if err := os.WriteFile(filepath.Join(repo, ".env"), []byte("A=three\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runCLICombinedInDir(t, repo, "encrypt", "--identity", identity)
	out, code := runCLICombinedInDir(t, repo, "hook-pre-commit", "--identity", identity)
	if code != exitOutOfSync || !strings.Contains(out, "working and staged ciphertext differ") {
		t.Fatalf("partial staging exit=%d\n%s", code, out)
	}
}

func TestPreCommitManagedChangeRequiresIdentity(t *testing.T) {
	repo, _ := setupCommittedHookRepo(t)
	configPath := filepath.Join(repo, ".envguardian", "config.toml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, append([]byte("# reviewed metadata change\n"), data...), 0o644); err != nil {
		t.Fatal(err)
	}
	run(t, repo, "git", "add", ".envguardian/config.toml")
	out, code := runCLICombinedInDir(t, repo, "hook-pre-commit", "--identity", filepath.Join(repo, "missing-id"))
	if code != exitIdentity {
		t.Fatalf("missing identity exit=%d, want %d\n%s", code, exitIdentity, out)
	}
}

func TestPreCommitUnmanagedChangeUsesStructuralVerification(t *testing.T) {
	repo, _ := setupCommittedHookRepo(t)
	if err := os.WriteFile(filepath.Join(repo, "README.md"), []byte("unmanaged\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run(t, repo, "git", "add", "README.md")
	if out, code := runCLICombinedInDir(t, repo, "hook-pre-commit", "--identity", filepath.Join(repo, "missing-id")); code != exitOK {
		t.Fatalf("unmanaged commit required an identity: %d\n%s", code, out)
	}
}

func TestPreCommitRejectsPartialConfigStaging(t *testing.T) {
	repo, identity := setupCommittedHookRepo(t)
	configPath := filepath.Join(repo, ".envguardian", "config.toml")
	bad := "version = 1\n\n[[file]]\nplaintext = \".env\"\nciphertext = \"missing.age\"\n"
	if err := os.WriteFile(configPath, []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	run(t, repo, "git", "add", ".envguardian/config.toml")
	out, code := runCLICombinedInDir(t, repo, "hook-pre-commit", "--identity", identity)
	if code == exitOK || !strings.Contains(out, "staged ciphertext missing.age is missing") {
		t.Fatalf("partial config staging exit=%d\n%s", code, out)
	}
}

func TestPreCommitHandlesConfigRemoval(t *testing.T) {
	repo, _ := setupCommittedHookRepo(t)
	if out, code := run(t, repo, "git", "rm", ".envguardian/config.toml"); code != exitOK {
		t.Fatalf("git rm config: %d\n%s", code, out)
	}
	if out, code := runCLICombinedInDir(t, repo, "hook-pre-commit"); code != exitOK {
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
	repo, identity := setupCommittedHookRepo(t)
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
	out, code := runCLICombinedInDir(t, repo, "hook-pre-commit", "--identity", identity)
	if code != exitConfig || !strings.Contains(out, "refusing to commit plaintext") {
		t.Fatalf("tracked plaintext was not rejected: %d\n%s", code, out)
	}
}

func TestPreCommitRejectsBadSignature(t *testing.T) {
	repo, identity := setupCommittedHookRepo(t)
	if err := os.WriteFile(filepath.Join(repo, ".env.age.sig"), []byte("bad signature\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run(t, repo, "git", "add", ".env.age.sig")
	out, code := runCLICombinedInDir(t, repo, "hook-pre-commit", "--identity", identity)
	if code != exitSignature || !strings.Contains(out, "ciphertext signature error") {
		t.Fatalf("bad staged signature exit=%d\n%s", code, out)
	}
}

func TestPreCommitRejectsMissingSignature(t *testing.T) {
	repo, identity := setupCommittedHookRepo(t)
	if out, code := run(t, repo, "git", "rm", ".env.age.sig"); code != exitOK {
		t.Fatalf("git rm signature: %d\n%s", code, out)
	}
	out, code := runCLICombinedInDir(t, repo, "hook-pre-commit", "--identity", identity)
	if code != exitSignature || !strings.Contains(out, missingSignatureFailure) {
		t.Fatalf("missing signature exit=%d\n%s", code, out)
	}
}

func TestIsGoRunBinary(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/tmp/go-build3912/b001/exe/envguardian", true},
		{filepath.FromSlash("C:/Users/dev/AppData/Local/Temp/go-build1234/b001/exe/envguardian.exe"), true},
		{"/home/dev/go/bin/envguardian", false},
		{"/opt/homebrew/bin/envguardian", false},
		{"/tmp/go-build3912/b001/cli.test", false},
		{"/srv/tools/exe/envguardian", false},
	}
	for _, tt := range tests {
		if got := isGoRunBinary(tt.path); got != tt.want {
			t.Errorf("isGoRunBinary(%q)=%v, want %v", tt.path, got, tt.want)
		}
	}
}

// runHookBlock executes one managed hook block with /bin/sh semantics and the
// given PATH, returning combined output and the exit code.
func runHookBlock(t *testing.T, body, pathEnv string, args ...string) (string, int) {
	t.Helper()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh is required")
	}
	script := filepath.Join(t.TempDir(), "hook")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"+hookBegin+"\n"+body+"\n"+hookEnd+"\necho after-block\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(sh, append([]string{script}, args...)...) // #nosec G204 -- test-owned script
	cmd.Env = append(os.Environ(), "PATH="+pathEnv)
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("run hook: %v", err)
		}
		code = exitErr.ExitCode()
	}
	return string(out), code
}

// fakeEnvguardian writes a shell script that reports how it was invoked.
func fakeEnvguardian(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho \"ran $*\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestHookBodyKeepsShellMetacharactersLiteral(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file names with quotes and dollars")
	}
	dir := filepath.Join(t.TempDir(), "it's $HOME `id`")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	exe := fakeEnvguardian(t, dir, "envguardian")
	shDir := filepath.Dir(mustLookPath(t, "sh"))
	out, code := runHookBlock(t, hookBody("post-merge", exe, "/repo/it's $x.toml"), shDir)
	if code != 0 || !strings.Contains(out, "ran --config /repo/it's $x.toml hook-auto-decrypt") {
		t.Fatalf("exit=%d output:\n%s", code, out)
	}
	if !strings.Contains(out, "after-block") {
		t.Fatalf("managed block skipped later hook content:\n%s", out)
	}
}

func TestHookFallsBackToPathWhenRecordedBinaryMoved(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake binaries are POSIX shell scripts")
	}
	pathDir := t.TempDir()
	fakeEnvguardian(t, pathDir, "envguardian")
	shDir := filepath.Dir(mustLookPath(t, "sh"))
	missing := filepath.Join(t.TempDir(), "gone", "envguardian")

	out, code := runHookBlock(t, hookBody("pre-commit", missing, ""), pathDir+":"+shDir)
	if code != 0 || !strings.Contains(out, "ran hook-pre-commit") || !strings.Contains(out, "envguardian install-hooks") {
		t.Fatalf("fallback exit=%d output:\n%s", code, out)
	}

	out, code = runHookBlock(t, hookBody("pre-commit", missing, ""), shDir)
	if code == 0 || !strings.Contains(out, "not on PATH") || strings.Contains(out, "after-block") {
		t.Fatalf("pre-commit with no binary must fail closed: exit=%d output:\n%s", code, out)
	}

	out, code = runHookBlock(t, hookBody("post-checkout", missing, ""), shDir, "old", "new", "0")
	if code != 0 || strings.Contains(out, "missing") || !strings.Contains(out, "after-block") {
		t.Fatalf("file checkout must skip the block quietly and keep later content: exit=%d output:\n%s", code, out)
	}
}

func TestPreCommitHookFailsClosedWhenBinaryMoved(t *testing.T) {
	bin := buildBinary(t)
	repo := gitInitRepo(t)
	idPath := filepath.Join(repo, "id.txt")
	writeAgeID(t, idPath)
	if out, code := run(t, repo, bin, "init", "--identity", idPath, "--name", "alice"); code != 0 {
		t.Fatalf("init: %d\n%s", code, out)
	}
	if out, code := run(t, repo, bin, "install-hooks"); code != 0 {
		t.Fatalf("install-hooks: %d\n%s", code, out)
	}
	if err := os.Rename(bin, bin+".moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "README.md"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run(t, repo, "git", "add", "README.md")
	commit := exec.Command("git", "commit", "-m", "after move")
	commit.Dir = repo
	// Only Git and its shell: no envguardian is reachable through PATH.
	pathEnv := filepath.Dir(mustLookPath(t, "git")) + string(os.PathListSeparator) + filepath.Dir(mustLookPath(t, "sh"))
	commit.Env = append(os.Environ(), "PATH="+pathEnv)
	out, err := commit.CombinedOutput()
	if err == nil {
		t.Fatalf("commit succeeded with no envguardian binary available:\n%s", out)
	}
	if !strings.Contains(string(out), "recorded binary") {
		t.Fatalf("missing reinstall hint:\n%s", out)
	}
}

func mustLookPath(t *testing.T, name string) string {
	t.Helper()
	found, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s is required", name)
	}
	return found
}
