package gitint

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func gitRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	for _, args := range [][]string{
		{"init"},
		{"config", "user.email", "test@example.com"},
		{"config", "user.name", "test"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	return dir
}

func gitAdd(t *testing.T, dir, path string) {
	t.Helper()
	cmd := exec.Command("git", "add", path)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git add %s: %v\n%s", path, err, out)
	}
}

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestIsIgnoredGitRepo(t *testing.T) {
	dir := gitRepo(t)
	write(t, dir, ".gitignore", ".env\n")
	write(t, dir, ".env", "A=1\n")
	write(t, dir, "visible.txt", "x")

	if ig, err := IsIgnored(dir, ".env"); err != nil || !ig {
		t.Errorf(".env: ignored=%v err=%v, want ignored", ig, err)
	}
	if ig, err := IsIgnored(dir, "visible.txt"); err != nil || ig {
		t.Errorf("visible.txt: ignored=%v err=%v, want not ignored", ig, err)
	}
}

// TestTrackedFileNotIgnored is the dangerous case: a plaintext already committed
// to git is NOT ignored even if a .gitignore rule would match it. The guard must
// catch this so it refuses to keep encrypting a leaked secret.
func TestTrackedFileNotIgnored(t *testing.T) {
	dir := gitRepo(t)
	write(t, dir, ".env", "A=1\n")
	gitAdd(t, dir, ".env") // now tracked
	write(t, dir, ".gitignore", ".env\n")

	if ig, err := IsIgnored(dir, ".env"); err != nil || ig {
		t.Errorf("tracked .env: ignored=%v err=%v, want NOT ignored", ig, err)
	}
}

func TestEnsureIgnoredFix(t *testing.T) {
	dir := gitRepo(t)

	// No .gitignore yet → refuse.
	err := EnsureIgnored(dir, []string{".env"}, false)
	var ni *NotIgnoredError
	if !errors.As(err, &ni) {
		t.Fatalf("want *NotIgnoredError, got %v", err)
	}
	if !strings.Contains(err.Error(), "not ignored") || !strings.Contains(err.Error(), "--fix") {
		t.Errorf("error missing guidance: %v", err)
	}

	// --fix appends and succeeds.
	if err := EnsureIgnored(dir, []string{".env"}, true); err != nil {
		t.Fatalf("fix: %v", err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, ".gitignore"))
	if !strings.Contains(string(data), ".env") {
		t.Errorf(".gitignore = %q", data)
	}
	if ig, _ := IsIgnored(dir, ".env"); !ig {
		t.Error(".env should be ignored after --fix")
	}
}

func TestFallbackParser(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".gitignore", "# a comment\n.env\n*.log\n!keep.log\n/build/\n")

	cases := []struct {
		path string
		want bool
	}{
		{".env", true},
		{"other.txt", false},
		{"app.log", true},
		{"keep.log", false}, // negated
		{"build", true},     // trailing-slash dir entry
	}
	for _, c := range cases {
		got, err := ignoredByGitignoreFile(dir, c.path)
		if err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("%s: ignored=%v, want %v", c.path, got, c.want)
		}
	}
}

func TestFallbackNoGitignore(t *testing.T) {
	dir := t.TempDir()
	got, err := ignoredByGitignoreFile(dir, ".env")
	if err != nil || got {
		t.Errorf("no .gitignore: ignored=%v err=%v, want false", got, err)
	}
}
