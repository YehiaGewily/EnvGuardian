package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runEnv(t *testing.T, dir string, env []string, name string, args ...string) (string, int) {
	t.Helper()
	c := exec.Command(name, args...)
	c.Dir = dir
	c.Env = env
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

// TestDiffDriverEndToEnd installs the textconv driver and runs a real `git
// diff`, proving it shows only key names — never values.
func TestDiffDriverEndToEnd(t *testing.T) {
	bin := buildBinary(t) // skips if git is absent
	repo := gitInitRepo(t)
	idPath := filepath.Join(repo, "id.txt")
	writeAgeID(t, idPath)
	env := append(os.Environ(), "ENVGUARDIAN_IDENTITY="+idPath)

	run(t, repo, bin, "init", "--identity", idPath, "--name", "alice")
	if err := os.WriteFile(filepath.Join(repo, ".env"), []byte("A=one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run(t, repo, bin, "encrypt", "--identity", idPath)
	if out, code := run(t, repo, bin, "diff", "--install"); code != 0 {
		t.Fatalf("diff --install: %d\n%s", code, out)
	}
	run(t, repo, "git", "add", ".env.age", ".gitattributes", ".envguardian")
	if out, code := runEnv(t, repo, env, "git", "commit", "-m", "v1"); code != 0 {
		t.Fatalf("commit v1: %d\n%s", code, out)
	}

	// Change the secrets: A's value changes, B is added.
	if err := os.WriteFile(filepath.Join(repo, ".env"), []byte("A=two\nB=three\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run(t, repo, bin, "encrypt", "--identity", idPath)

	out, _ := runEnv(t, repo, env, "git", "diff", "--", ".env.age")
	if !strings.Contains(out, "B") {
		t.Errorf("git diff did not surface the added key B:\n%s", out)
	}
	for _, secret := range []string{"one", "two", "three"} {
		if strings.Contains(out, secret) {
			t.Errorf("git diff LEAKED value %q:\n%s", secret, out)
		}
	}
}

func TestDiffWorkingKeysOnly(t *testing.T) {
	pinDate(t)
	dir := t.TempDir()
	t.Chdir(dir)
	// Encrypt A=1, B=keepme, then change the working copy: drop B, change A, add C.
	idPath := setupRepo(t, dir, "A=1\nB=keepme\n")
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("A=2\nC=new-secret-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, _, code := runCLI(t, "diff", "--identity", idPath)
	if code != exitOK {
		t.Fatalf("diff exit = %d\n%s", code, out)
	}
	for _, want := range []string{"+ C", "- B", "~ A"} {
		if !strings.Contains(out, want) {
			t.Errorf("diff output missing %q:\n%s", want, out)
		}
	}
	// The leak guard: no value, old or new, may appear anywhere in the output.
	for _, secret := range []string{"keepme", "new-secret-value", "=1", "=2"} {
		if strings.Contains(out, secret) {
			t.Errorf("diff LEAKED a value (%q):\n%s", secret, out)
		}
	}
}

func TestDiffTextconvKeysOnly(t *testing.T) {
	pinDate(t)
	dir := t.TempDir()
	t.Chdir(dir)
	idPath := setupRepo(t, dir, "ALPHA=one\nBETA=two-secret\n")

	// textconv mode: pass the ciphertext file directly.
	out, _, code := runCLI(t, "diff", "--identity", idPath, ".env.age")
	if code != exitOK {
		t.Fatalf("textconv exit = %d\n%s", code, out)
	}
	// Sorted key names, one per line, no values.
	if strings.TrimSpace(out) != "ALPHA\nBETA" {
		t.Errorf("textconv output = %q, want sorted key names", out)
	}
	for _, secret := range []string{"one", "two-secret"} {
		if strings.Contains(out, secret) {
			t.Errorf("textconv LEAKED a value (%q):\n%s", secret, out)
		}
	}
}

func TestDiffTextconvNotARecipientFails(t *testing.T) {
	pinDate(t)
	dir := t.TempDir()
	t.Chdir(dir)
	setupRepo(t, dir, "A=1\n")
	other := filepath.Join(dir, "other.txt")
	writeAgeID(t, other)

	// A non-recipient must not get key names; the command fails so git falls
	// back to a binary diff.
	_, _, code := runCLI(t, "diff", "--identity", other, ".env.age")
	if code == exitOK {
		t.Error("textconv succeeded for a non-recipient; must fail")
	}
}
