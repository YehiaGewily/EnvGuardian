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

// TestDiffDriverEndToEnd installs the two-sided external driver and runs a real
// git diff, proving value-only changes are visible without exposing values.
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
	run(t, repo, "git", "add", ".env.age", ".env.age.sig", ".gitattributes", ".envguardian")
	if out, code := runEnv(t, repo, env, "git", "commit", "-m", "v1"); code != 0 {
		t.Fatalf("commit v1: %d\n%s", code, out)
	}

	// Change the secrets: A's value changes, B is added.
	if err := os.WriteFile(filepath.Join(repo, ".env"), []byte("A=two\nB=three\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run(t, repo, bin, "encrypt", "--identity", idPath)

	out, _ := runEnv(t, repo, env, "git", "diff", "--", ".env.age")
	for _, want := range []string{"~ A", "+ B"} {
		if !strings.Contains(out, want) {
			t.Errorf("git diff did not surface %q:\n%s", want, out)
		}
	}
	for _, secret := range []string{"one", "two", "three"} {
		if strings.Contains(out, secret) {
			t.Errorf("git diff LEAKED value %q:\n%s", secret, out)
		}
	}
}

func TestInstallDiffDriverInProcess(t *testing.T) {
	repo := gitInitRepo(t)
	stdout, stderr, code := runCLIInDir(t, repo, "diff", "--install")
	if code != exitOK {
		t.Fatalf("diff --install exit=%d: %s", code, stderr)
	}
	if !strings.Contains(stdout, "configured local git diff.envguardian.command") {
		t.Fatal("diff installation omitted its success diagnostic")
	}
	attributes, err := os.ReadFile(filepath.Join(repo, ".gitattributes"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(attributes), "*.age diff=envguardian") {
		t.Fatal("diff installation did not write the repository attribute")
	}
	configured, code := run(t, repo, "git", "config", "--local", "--get", "diff.envguardian.command")
	if code != exitOK || !strings.Contains(configured, "diff-driver") {
		t.Fatal("diff installation did not register the local external driver")
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

func TestDiffDriverKeysOnly(t *testing.T) {
	pinDate(t)
	dir := t.TempDir()
	t.Chdir(dir)
	idPath := setupRepo(t, dir, "ALPHA=one\nBETA=two-secret\nDROP=gone\n")
	oldPath := filepath.Join(dir, "old.age")
	old, err := os.ReadFile(filepath.Join(dir, ".env.age"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oldPath, old, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("ALPHA=changed-secret\nBETA=two-secret\nADD=new-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, code := runCLI(t, "encrypt", "--identity", idPath); code != exitOK {
		t.Fatal("encrypt new side failed")
	}

	out, _, code := runCLI(t, "diff-driver", "--identity", idPath,
		".env.age", oldPath, "oldhex", "100644", filepath.Join(dir, ".env.age"), "newhex", "100644")
	if code != exitOK {
		t.Fatalf("diff-driver exit = %d\n%s", code, out)
	}
	for _, want := range []string{"+ ADD", "- DROP", "~ ALPHA"} {
		if !strings.Contains(out, want) {
			t.Errorf("diff-driver output missing %q: %s", want, out)
		}
	}
	for _, secret := range []string{"one", "two-secret", "changed-secret", "new-secret", "gone"} {
		if strings.Contains(out, secret) {
			t.Errorf("diff-driver LEAKED a value (%q):\n%s", secret, out)
		}
	}
}

func TestDiffDriverNotARecipientFails(t *testing.T) {
	pinDate(t)
	dir := t.TempDir()
	t.Chdir(dir)
	setupRepo(t, dir, "A=1\n")
	other := filepath.Join(dir, "other.txt")
	writeAgeID(t, other)

	_, _, code := runCLI(t, "diff-driver", "--identity", other,
		".env.age", ".env.age", "oldhex", "100644", ".env.age", "newhex", "100644")
	if code == exitOK {
		t.Error("diff-driver succeeded for a non-recipient; must fail")
	}
}

func TestDiffDriverIgnoresReorderingAndComments(t *testing.T) {
	pinDate(t)
	dir := t.TempDir()
	t.Chdir(dir)
	idPath := setupRepo(t, dir, "# old\nA=1\nB=2\n")
	oldPath := filepath.Join(dir, "old.age")
	old, err := os.ReadFile(filepath.Join(dir, ".env.age"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oldPath, old, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("# new comment\nB=2\nA=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Semantic equality means encrypt does not rewrite, so both sides remain
	// byte-identical and the external driver's policy is no output.
	out, _, code := runCLI(t, "diff-driver", "--identity", idPath,
		".env.age", oldPath, "oldhex", "100644", filepath.Join(dir, ".env.age"), "newhex", "100644")
	if code != exitOK || strings.TrimSpace(out) != "" {
		t.Fatalf("reorder/comment diff exit=%d output=%q", code, out)
	}
}

func TestShellQuoteProtectsSpecialCharacters(t *testing.T) {
	input := "C:/a path/$money/`tick`/'quote'/envguardian"
	got := shellQuote(input)
	if got != "'C:/a path/$money/`tick`/'\"'\"'quote'\"'\"'/envguardian'" {
		t.Fatalf("shellQuote() = %q", got)
	}
}
